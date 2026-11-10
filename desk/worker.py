"""The worker: GitHub sync, outbox mirroring, label and state pushes, health, anchors, housekeeping.
Runs as its own container (`python -m desk.worker`). It reads GitHub and the node; it writes to
GitHub only what a person decided (a reply, a status), with one exception it makes itself: the stock
reply for a ticket left at accepted or patched with its reporter untold (`services.tell`). It never
signs anything on chain.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from datetime import datetime, timezone

from sqlalchemy import delete, select

from .auth import purge_reporter_auth, purge_seen_signatures
from .context import Context, build_context, set_context
from .db import session
from .log import VERIFY_EVERY_S, VERIFY_JOB, EventLog
from .models import Anchor, Challenge, HealthCheck, ScheduleRun, Session
from .services import github as gh
from .services import notify, sync, tell
from .services import tickets as tsvc

log = logging.getLogger("desk.worker")
NS = 1_000_000_000


async def mark_run(db, job: str, detail: dict | None = None) -> None:
    row = (await db.execute(select(ScheduleRun).where(ScheduleRun.job == job))).scalar_one_or_none()
    if row is None:
        db.add(ScheduleRun(job=job, last_run_ts=time.time_ns(), detail=detail or {}))
    else:
        row.last_run_ts = time.time_ns()
        row.detail = detail or {}


class Worker:
    JOBS = {
        "github_poll": 120,
        "tell": 60,
        "outbox": 20,
        "push": 60,
        "health": 300,
        VERIFY_JOB: VERIFY_EVERY_S,
        "housekeeping": 3600,
        "anchor": 3600,
        "daily": 3600,
    }

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.stop = asyncio.Event()
        self.gh = gh.GitHub(ctx.settings.github_token)
        self.last: dict[str, float] = {}

    # ---- jobs -----------------------------------------------------------------------------

    async def job_github_poll(self):
        if not self.gh.enabled:
            return
        async with session() as db:
            try:
                stats = await sync.poll(self.ctx, db, self.gh)
                total = sum(s["issues"] + s["comments"] + s["pulls"] for s in stats)
                if total:
                    log.info("github poll: %s", stats)
                await mark_run(db, "github_poll", {"ok": True, "stats": stats})
            except Exception as e:
                log.warning("github poll failed: %s", e)
                await mark_run(db, "github_poll", {"ok": False, "error": str(e)[:300]})
            await db.commit()

    async def job_tell(self):
        """The stock reply on tickets resting at accepted or patched that nobody has told. Mail goes
        after the commit, to what was committed."""
        async with session() as db:
            told = await tell.tell_resting(self.ctx, db)
            owed = notify.take_owed(db)
            await mark_run(db, "tell", {"told": len(told)})
            await db.commit()
        if told:
            log.info("told: %s", ", ".join(f"{x['ticket']} ({x['status']})" for x in told))
        await notify.mail_owed(self.ctx, owed)

    async def job_outbox(self):
        async with session() as db:
            sent = failed = 0
            for r in await sync.queued_replies(db):
                try:
                    ok = await sync.mirror_reply(self.ctx, db, self.gh, r)
                    sent += int(ok)
                    failed += int(not ok)
                except Exception as e:
                    log.warning("mirror reply %s: %s", r.id, e)
                    r.mirror, r.mirror_error = "failed", str(e)[:2000]
                    failed += 1
                await db.commit()
            if sent or failed:
                log.info("outbox: %d sent, %d failed", sent, failed)
            await mark_run(db, "outbox", {"sent": sent, "failed": failed})
            await db.commit()

    async def job_push(self):
        """Labels and open/closed state follow the desk; disclosed private tickets get their issue."""
        if not self.gh.enabled:
            return
        async with session() as db:
            n = 0
            for t in await sync.tickets_needing_push(db):
                try:
                    n += int(await sync.push_labels(self.ctx, db, self.gh, t))
                    n += int(await sync.push_state(self.ctx, db, self.gh, t))
                except gh.GitHubError as e:
                    log.warning("push %s: %s", t.id, e)
                await db.commit()
            rows = (
                (
                    await db.execute(
                        select(tsvc.Ticket).where(
                            tsvc.Ticket.status == "disclosed", tsvc.Ticket.source != "github"
                        )
                    )
                )
                .scalars()
                .all()
            )
            for t in rows:
                try:
                    url = await sync.open_disclosure(self.ctx, db, self.gh, t)
                    if url:
                        log.info("disclosed %s as %s", t.id, url)
                        n += 1
                except gh.GitHubError as e:
                    log.warning("disclose %s: %s", t.id, e)
                await db.commit()
            await mark_run(db, "push", {"changes": n})
            await db.commit()

    async def job_health(self):
        ctx = self.ctx
        detail: dict = {
            "network_id": "",
            "node_ok": False,
            "github_ok": None,
            "vault": ctx.vault.available,
            "signer": ctx.signer.has("log"),
        }
        try:
            node = await ctx.refresh_node()
            detail["network_id"], detail["node_ok"] = node.network_id, bool(node.network_id)
        except Exception as e:
            detail["node_error"] = str(e)[:200]
        if self.gh.enabled:
            try:
                me = await self.gh.me()
                detail["github_ok"], detail["github_login"] = True, me.get("login", "")
            except Exception as e:
                detail["github_ok"], detail["github_error"] = False, str(e)[:200]
        async with session() as db:
            head = await EventLog.head(db)
            detail["log_head"] = head.index
            ok = detail["node_ok"] and detail["signer"] and detail["github_ok"] is not False
            db.add(HealthCheck(ts=time.time_ns(), ok=ok, detail=detail))
            last = (
                await db.execute(select(HealthCheck).order_by(HealthCheck.ts.desc()).offset(1).limit(1))
            ).scalar_one_or_none()
            if not ok and (last is None or last.ok):
                await ctx.events.append(db, "health.degraded", "desk", detail)
            elif ok and last is not None and not last.ok:
                await ctx.events.append(db, "health.recovered", "desk", detail)
            await mark_run(db, "health", {"ok": ok})
            await db.commit()

    async def job_log_verify(self):
        """Replays the chain and leaves the verdict for `/v1/log/verify`, which only reads it (XE-0657):
        the one place a full replay runs for a reader, on the worker's clock and not on a request's."""
        ctx = self.ctx
        async with session() as db:
            key = ctx.signer.public_key("log") if ctx.signer.has("log") else ""
            verdict = await EventLog.replay_and_record(db, key)
            await db.commit()
        if not verdict["ok"]:
            log.error("log verify failed at count %s: %s", verdict["count"], verdict["first_error"])

    async def job_housekeeping(self):
        async with session() as db:
            now = datetime.now(timezone.utc)
            purged = await purge_seen_signatures(db)
            ch = await db.execute(delete(Challenge).where(Challenge.expires_at < now))
            se = await db.execute(delete(Session).where(Session.expires_at < now))
            rp = await purge_reporter_auth(db)
            old = time.time_ns() - 90 * 86400 * NS
            hc = await db.execute(delete(HealthCheck).where(HealthCheck.ts < old))
            await mark_run(
                db,
                "housekeeping",
                {
                    "signatures": purged,
                    "challenges": ch.rowcount,
                    "sessions": se.rowcount,
                    "reporter_auth": rp,
                    "health_rows": hc.rowcount,
                },
            )
            await db.commit()

    async def job_anchor(self):
        """Once per configured period, snapshot the log head as the next anchor for the DAO to write."""
        every = int((self.ctx.config.desk.get("anchor") or {}).get("every_days", 7)) * 86400
        async with session() as db:
            last = (await db.execute(select(Anchor).order_by(Anchor.n.desc()).limit(1))).scalar_one_or_none()
            if last is not None and (time.time() - last.created_at.timestamp()) < every:
                return
            head = await EventLog.head(db)
            if last is not None and last.event_index == head.index:
                return
            n = (last.n + 1) if last else 1
            db.add(Anchor(n=n, event_index=head.index, head_hash=head.hash))
            prefix = (self.ctx.config.desk.get("anchor") or {}).get("key_prefix", "desk.anchor")
            await self.ctx.events.append(
                db,
                "log.anchor",
                "desk",
                {
                    "n": n,
                    "event_index": head.index,
                    "head_hash": head.hash,
                    "key": f"{prefix}.{n}",
                    "prev_anchor": last.head_hash if last else "",
                },
            )
            await mark_run(db, "anchor", {"n": n})
            await db.commit()
            log.info("anchor %d at index %d", n, head.index)

    async def job_daily(self):
        """One note a day with the counts, so the log reads as a diary without opening the tables."""
        async with session() as db:
            today = datetime.now(timezone.utc).date().isoformat()
            row = (
                await db.execute(select(ScheduleRun).where(ScheduleRun.job == "daily"))
            ).scalar_one_or_none()
            if row and row.detail.get("date") == today:
                return
            from .authz import SYSTEM

            counts = await tsvc.counts(db, SYSTEM, "bounty")
            support = await tsvc.counts(db, SYSTEM, "support")
            outbox = await tsvc.outbox(db, self.ctx.config, SYSTEM)
            head = await EventLog.head(db)
            await self.ctx.events.append(
                db,
                "note.daily",
                "desk",
                {
                    "date": today,
                    "bounty": counts,
                    "support": support,
                    "outbox": len(outbox),
                    "log_head": {"index": head.index, "hash": head.hash},
                    "network_id": self.ctx.node.network_id,
                },
            )
            await mark_run(db, "daily", {"date": today})
            await db.commit()

    # ---- loop -----------------------------------------------------------------------------

    async def run(self):
        log.info("worker up; github %s", "on" if self.gh.enabled else "off (no token)")
        try:
            await self.job_health()
        except Exception as e:
            log.warning("first health check failed: %s", e)
        while not self.stop.is_set():
            now = time.time()
            for name, every in self.JOBS.items():
                if now - self.last.get(name, 0) < every:
                    continue
                self.last[name] = now
                try:
                    await getattr(self, f"job_{name}")()
                except Exception as e:
                    log.exception("job %s failed: %s", name, e)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        await self.gh.aclose()
        log.info("worker stopped")


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = build_context()
    set_context(ctx)
    await ctx.refresh_node()
    w = Worker(ctx)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, w.stop.set)
    try:
        await w.run()
    finally:
        await ctx.aclose()


if __name__ == "__main__":
    asyncio.run(main())
