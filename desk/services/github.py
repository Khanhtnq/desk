"""GitHub over httpx. REST and webhooks; no library.

Reads page through `Link` headers. Rate limits are respected by sleeping to the reset, bounded, and
`Retry-After` is honoured (the #76 lesson applied to ourselves). Writes are comments, labels, issue
state and, for disclosure, a new issue. Nothing here touches the database.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import time
from typing import Any, AsyncIterator
from urllib.parse import quote

import httpx

log = logging.getLogger("desk.github")
API = "https://api.github.com"
LINK_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"github returned {status}: {message}")
        self.status = status
        self.message = message


class GitHub:
    def __init__(self, token: str, base_url: str = API, timeout: float = 30.0):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "xe-desk",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)
        self.enabled = bool(token)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- plumbing -------------------------------------------------------------------------

    async def _request(
        self, method: str, path: str, *, params: dict | None = None, json: Any = None
    ) -> httpx.Response:
        for attempt in range(5):
            r = await self._client.request(method, path, params=params, json=json)
            if r.status_code in (403, 429) and (
                r.headers.get("x-ratelimit-remaining") == "0" or r.headers.get("retry-after")
            ):
                wait = self._backoff(r)
                log.warning("github rate limit; sleeping %ds", wait)
                await asyncio.sleep(wait)
                continue
            if r.status_code >= 500 and attempt < 4:
                await asyncio.sleep(2**attempt)
                continue
            if r.status_code >= 400:
                try:
                    j = r.json()
                    msg = j.get("message", r.text)
                    if j.get("errors"):  # 422s say what failed in here, not in the message
                        msg += " " + "; ".join(
                            f"{e.get('resource', '')}.{e.get('field', '')}: {e.get('code', '')}"
                            if isinstance(e, dict) else str(e)
                            for e in j["errors"]
                        )
                except Exception:
                    msg = r.text
                raise GitHubError(r.status_code, msg)
            return r
        raise GitHubError(429, "rate limited")

    @staticmethod
    def _backoff(r: httpx.Response) -> int:
        ra = r.headers.get("retry-after")
        if ra and ra.isdigit():
            return min(int(ra), 300)
        reset = r.headers.get("x-ratelimit-reset")
        if reset and reset.isdigit():
            return max(1, min(int(reset) - int(time.time()), 300))
        return 60

    async def get(self, path: str, **params: Any) -> Any:
        r = await self._request("GET", path, params={k: v for k, v in params.items() if v is not None})
        return r.json() if r.content else None

    async def paged(self, path: str, **params: Any) -> AsyncIterator[dict]:
        params = {k: v for k, v in params.items() if v is not None}
        params.setdefault("per_page", 100)
        url: str | None = path
        first = True
        while url:
            r = await self._request("GET", url, params=params if first else None)
            first = False
            for item in r.json() or []:
                yield item
            m = LINK_NEXT.search(r.headers.get("link", ""))
            url = m.group(1) if m else None

    # ---- reads ----------------------------------------------------------------------------

    async def issues(self, repo: str, since: str | None = None, state: str = "all") -> AsyncIterator[dict]:
        """Issues only; the endpoint also returns PRs, which carry a `pull_request` key."""
        async for it in self.paged(
            f"/repos/{repo}/issues", state=state, since=since, sort="updated", direction="asc"
        ):
            if "pull_request" not in it:
                yield it

    async def issue(self, repo: str, number: int) -> dict:
        return await self.get(f"/repos/{repo}/issues/{number}")

    async def comments(self, repo: str, number: int, since: str | None = None) -> AsyncIterator[dict]:
        async for c in self.paged(f"/repos/{repo}/issues/{number}/comments", since=since):
            yield c

    async def pulls(self, repo: str, state: str = "all") -> AsyncIterator[dict]:
        async for p in self.paged(f"/repos/{repo}/pulls", state=state, sort="updated", direction="asc"):
            yield p

    async def labels(self, repo: str) -> list[dict]:
        return [label async for label in self.paged(f"/repos/{repo}/labels")]

    async def me(self) -> dict:
        return await self.get("/user")

    # ---- writes ---------------------------------------------------------------------------

    async def ensure_labels(self, repo: str, wanted: list[dict]) -> None:
        """Create or correct the desk's labels. GitHub label names are case-insensitive, so `Accepted`
        already on the repo is the same label as `accepted`: it is renamed and recoloured, not duplicated."""
        have = {label["name"].lower(): label for label in await self.labels(repo)}
        for w in wanted:
            cur = have.get(w["name"].lower())
            body = {
                "name": w["name"],
                "color": w.get("color", "ededed").lstrip("#").lower(),
                "description": (w.get("description") or "")[:100],
            }
            if cur is None:
                try:
                    await self._request("POST", f"/repos/{repo}/labels", json=body)
                except GitHubError as e:
                    if e.status != 422 or "already_exists" not in e.message:
                        raise
                    cur = {"name": w["name"]}  # listed stale; fall through and correct it in place
            if cur is not None and (
                cur.get("name") != body["name"]
                or (cur.get("color") or "").lower() != body["color"]
                or (cur.get("description") or "") != body["description"]
            ):
                await self._request(
                    "PATCH",
                    f"/repos/{repo}/labels/{quote(cur['name'], safe='')}",
                    json={"new_name": w["name"], **body},
                )

    async def set_labels(self, repo: str, number: int, names: list[str]) -> list[str]:
        r = await self._request("PUT", f"/repos/{repo}/issues/{number}/labels", json={"labels": names})
        return [label["name"] for label in r.json()]

    async def comment(self, repo: str, number: int, body: str) -> dict:
        return (
            await self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})
        ).json()

    async def set_state(self, repo: str, number: int, state: str, state_reason: str | None = None) -> dict:
        body: dict = {"state": state}
        if state == "closed" and state_reason:
            body["state_reason"] = state_reason
        return (await self._request("PATCH", f"/repos/{repo}/issues/{number}", json=body)).json()

    async def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> dict:
        return (
            await self._request(
                "POST", f"/repos/{repo}/issues", json={"title": title, "body": body, "labels": labels}
            )
        ).json()


# ---- webhooks ---------------------------------------------------------------------------------------


def verify_webhook(secret: str, body: bytes, signature_header: str) -> bool:
    if not secret or not signature_header.startswith("sha256="):
        return False
    want = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature_header[7:])


# ---- text helpers -----------------------------------------------------------------------------------

# an issue number is at most twelve digits: longer runs are not references, and int() of a few thousand
# digits is refused by CPython (XE-1160)
ISSUE_REF = re.compile(r"(?<![\w/])#(\d{1,12})\b")
CLOSES = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*#(\d{1,12})\b", re.I)
TIER_HINT = re.compile(
    r"\b(?:severity|tier|suggested(?:\s+severity)?)\s*[:\-–]?\s*\**\s*(critical|severe|high|medium|minor|low)\b",
    re.I,
)


def issue_refs(text: str) -> list[int]:
    """Issue numbers a PR references, closing keywords first, then any bare #n, deduplicated in order."""
    seen: list[int] = []
    for m in list(CLOSES.finditer(text or "")) + list(ISSUE_REF.finditer(text or "")):
        n = int(m.group(1))
        if n not in seen:
            seen.append(n)
    return seen


def closing_refs(text: str) -> set[int]:
    """Only the issues a PR says it fixes (`fixes #n`, `closes #n`, `resolves #n`). A bare `#n` is a
    mention, which links but is never read as a fix."""
    return {int(m.group(1)) for m in CLOSES.finditer(text or "")}


PUBLIC_TAG = re.compile(
    r"(?<![\w/#])(?:(?P<owner>[\w.-]+)/)?(?P<repo>[A-Za-z][\w.-]*)#(?P<num>\d{1,12})\b"
)


def public_tags(text: str, aliases: dict[str, str]) -> list[tuple[str, int]]:
    """Public reports an internal ticket names: `xe#8` via the alias table, or `owner/repo#8` in full.
    Bare `#n` is the tracker's own numbering and is left alone. Deduplicated, in order of appearance."""
    out: list[tuple[str, int]] = []
    for m in PUBLIC_TAG.finditer(text or ""):
        if m.group("owner"):
            repo = f"{m.group('owner')}/{m.group('repo')}"
        else:
            repo = aliases.get(m.group("repo").lower(), "")
        if not repo:
            continue
        pair = (repo, int(m.group("num")))
        if pair not in out:
            out.append(pair)
    return out


DESK_TAG = re.compile(r"(?<![\w-])(?P<prefix>XE|XS)-(?P<num>\d{1,6})\b", re.I)


def desk_tags(text: str) -> list[str]:
    """Desk tickets an internal ticket names by id: `XE-0232`, in any case and with or without the zero
    padding. Reports filed on the desk have no GitHub number, so this is the only way to name them.
    Deduplicated, in order of appearance, normalised to the desk's form."""
    out: list[str] = []
    for m in DESK_TAG.finditer(text or ""):
        tid = f"{m.group('prefix').upper()}-{int(m.group('num')):04d}"
        if tid not in out:
            out.append(tid)
    return out


def claimed_tier(title: str, body: str) -> str | None:
    """The tier the reporter suggested, if the text says so in a way we recognise."""
    for text in (title or "", (body or "")[:4000]):
        m = TIER_HINT.search(text)
        if m:
            t = m.group(1).lower()
            return "minor" if t == "low" else t
    m = re.search(r"\[(critical|severe|high|medium|minor)\]", title or "", re.I)
    return m.group(1).lower() if m else None
