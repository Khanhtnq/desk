"""The programme in numbers, for `/stats`, `/v1/stats` and the page's social card.

One rule decides what is counted. The page says the same thing to every reader, signed in or not, and
it is made of three kinds of number:

- **How much was filed, and when.** Every bounty report counts here, sealed or public: the total, the
  reports per day, the hours they arrive. These carry no ticket's state and nobody's name, and the
  ticket ids already say how many reports there are. This is the one place the desk counts sealed
  reports for the public; the daily note (`worker.daily_counts`) and `/v1/tickets/counts` count per
  status, which is a sealed report's state, and stay public-only. A sealed report that is moved to
  the support door leaves the count for the day it was filed on; that much of it shows.
- **The length of the log**, which is the log head's index, as `/v1/log/head` serves it.
- **Everything else** (who has filed, where reports stand, what was fixed and at which tier, the
  areas, the awards) is counted over public reports exactly as an anonymous reader is shown them: a
  tier only once the assessment is published (`assessment_held`), an award only once the ticket is
  `awarded` (`award_published`, and the leaderboard's filter). A sealed report moves none of these
  numbers. Researchers are counted here and not above: a public report names its reporter, so a
  count that included sealed reports would say, the day a researcher first filed in public, whether
  they had filed in private before.

Nothing here names a ticket, and nobody is named but through the leaderboard, which is already public.
The numbers are collected once a minute at most (`snapshot`), whoever asks and however often.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..log import EventLog
from ..models import Event, Ticket
from . import tickets as tsvc

TTL = 60.0  # seconds a collected snapshot is served for
QUIET_DAYS = 14  # a silence this long, after a handful of early reports, is where the charts begin
MAX_BARS = 120  # daily bars up to this many days; weekly bars beyond
TOP = 8  # researchers listed under the awards
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
CLOSED_SHOWN = ("duplicate", "invalid", "withdrawn")  # the closing reasons with a slice of their own
UNTIERED, UNSORTED = "untiered", "unsorted"  # a fixed report with no tier, a report with no area


@dataclass(frozen=True)
class _Row:
    """The columns of a ticket this page reads, shaped as `assessment_held` and `award_published` read
    a ticket, so the page asks them and never keeps a rule of its own."""

    id: str
    kind: str
    visibility: str
    status: str
    closed_reason: str | None
    area: str | None
    assessed_tier: str | None
    reporter_id: int | None
    award_xe: int | None
    award_approved_at: datetime | None
    status_changed_at: datetime | None
    disclosed_at: datetime | None
    filed: datetime


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _from_ns(ts: int) -> datetime:
    return datetime.fromtimestamp(ts / 1_000_000_000, timezone.utc)


async def _first_public_move(db: AsyncSession, status: str) -> dict[str, datetime]:
    """When each ticket was first moved to `status` in a row of the public log. A move made while the
    report was sealed is not in the public log, and is not read here."""
    q = (
        select(Event.ref, func.min(Event.ts))
        .where(
            Event.kind == "ticket.status", Event.public.is_(True), Event.payload["to"].astext == status
        )
        .group_by(Event.ref)
    )
    return {ref: _from_ns(int(ts)) for ref, ts in (await db.execute(q)).all()}


def _start(per_day: Counter) -> date:
    """The day the charts begin: the first report, unless a long silence follows a handful of early
    ones (a fiftieth of all reports at most), in which case the day the reports resume. One report
    filed months before the programme does not flatten everything after it; a lull once the
    programme is running is part of the picture and stays. Totals count what came before."""
    days, total = sorted(per_day), sum(per_day.values())
    start, seen = days[0], 0
    for a, b in zip(days, days[1:]):
        seen += per_day[a]
        if (b - a).days > QUIET_DAYS and seen * 50 <= total:
            start = b
    return start


async def collect(db: AsyncSession, now: datetime | None = None) -> dict:
    """The numbers, read from the database now. JSON all the way down."""
    now = _utc(now) if now else datetime.now(timezone.utc)
    today = now.date()
    filed = func.coalesce(Ticket.source_created_at, Ticket.created_at)
    q = select(
        Ticket.id, Ticket.kind, Ticket.visibility, Ticket.status, Ticket.closed_reason, Ticket.area,
        Ticket.assessed_tier, Ticket.reporter_id, Ticket.award_xe, Ticket.award_approved_at,
        Ticket.status_changed_at, Ticket.disclosed_at, filed,
    ).where(Ticket.kind == "bounty")
    rows = [_Row(*r) for r in (await db.execute(q)).all()]
    patched_at = await _first_public_move(db, "patched")
    awarded_at = await _first_public_move(db, "awarded")
    board = await tsvc.leaderboard(db)
    head = await EventLog.head(db)

    def day(dt: datetime | None) -> date:
        return min(_utc(dt).date(), today) if dt else today

    # ---- every report: how many, and when ----------------------------------------------------------
    per_day: Counter[date] = Counter()
    heat = [[0] * 24 for _ in WEEKDAYS]
    for r in rows:
        when = _utc(r.filed)
        per_day[min(when.date(), today)] += 1
        heat[when.weekday()][when.hour] += 1

    # ---- public reports, as an anonymous reader is shown them ---------------------------------------
    public = [r for r in rows if r.visibility == "public"]
    first_seen: dict[int, date] = {}  # each researcher, by the day of their first public report
    for r in public:
        if r.reporter_id is not None:
            first_seen[r.reporter_id] = min(day(r.filed), first_seen.get(r.reporter_id, today))
    joined = Counter(first_seen.values())
    fixed = [r for r in public if r.status in tsvc.FIXED_STATUSES]
    closed = Counter(r.closed_reason or "other" for r in public if r.status == "closed")
    by_tier = Counter(r.assessed_tier or UNTIERED for r in fixed if not tsvc.assessment_held(r))
    by_area = Counter(r.area or UNSORTED for r in public)
    fixed_on: Counter[date] = Counter()
    for r in fixed:
        fixed_on[day(patched_at.get(r.id) or r.disclosed_at or r.status_changed_at)] += 1
    awarded_on: Counter[date] = Counter()
    for r in public:  # the leaderboard's filter, a row at a time
        if tsvc.award_published(r) and r.award_approved_at is not None and r.reporter_id is not None:
            awarded_on[day(awarded_at.get(r.id) or r.status_changed_at)] += int(r.award_xe or 0)

    start = _start(per_day) if per_day else today
    span = [start + timedelta(days=i) for i in range((today - start).days + 1)]

    def before(c: Counter) -> int:
        return sum(n for d, n in c.items() if d < start)

    busiest = max(span, key=lambda d: (per_day[d], d))
    return {
        "as_of": now.isoformat(timespec="seconds"),
        "since": start.isoformat(),
        "days": len(span),
        "reports": len(rows),
        "researchers": len(first_seen),
        "last_7_days": sum(per_day[d] for d in span[-7:]),
        "busiest": {"day": busiest.isoformat(), "reports": per_day[busiest]},
        "before": {
            "reports": before(per_day), "researchers": before(joined), "fixed": before(fixed_on),
            "awarded_xe": before(awarded_on),
        },
        "per_day": [
            {
                "day": d.isoformat(), "reports": per_day[d], "researchers": joined[d],
                "fixed": fixed_on[d], "awarded_xe": awarded_on[d],
            }
            for d in span
        ],
        "by_hour": heat,
        "public": {
            "reports": len(public),
            "open": sum(1 for r in public if r.status in tsvc.OPEN_STATUSES),
            "fixed": len(fixed),
            "closed": dict(sorted(closed.items())),
            "fixed_by_tier": dict(sorted(by_tier.items())),
            "by_area": dict(sorted(by_area.items())),
        },
        "awards": {
            "xe": sum(b["award_xe"] for b in board),
            "tickets": sum(b["tickets"] for b in board),
            "researchers": len(board),
            "top": [
                {"name": b["name"] or b["login"] or f"reporter {b['reporter_id']}", "login": b["login"],
                 "award_xe": b["award_xe"], "tickets": b["tickets"]}
                for b in board[:TOP]
            ],
        },
        "log_entries": head.index + 1,
    }


_cached: tuple[float, dict] | None = None
_collecting = asyncio.Lock()


async def snapshot(db: AsyncSession) -> dict:
    """`collect`, at most once a minute: the page is the same for every reader, so one reading serves
    them all, and a crowd arriving from a post costs the database one pass."""
    global _cached
    if _cached and time.monotonic() - _cached[0] < TTL:
        return _cached[1]
    async with _collecting:
        if _cached and time.monotonic() - _cached[0] < TTL:
            return _cached[1]
        data = await collect(db)
        _cached = (time.monotonic(), data)
        return data


# ---- words ------------------------------------------------------------------------------------------


def _d(iso: str) -> date:
    return date.fromisoformat(iso)


def _dm(d: date) -> str:
    return f"{d.day} {d.strftime('%b')}"


def _dmy(d: date) -> str:
    return f"{d.day} {d.strftime('%b %Y')}"


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _short(n: float) -> str:
    """An axis label: 800, 1.5k, 20k, 1.2M."""
    for unit, suffix in ((1_000_000, "M"), (1_000, "k")):
        if n >= unit:
            return f"{n / unit:.1f}".rstrip("0").rstrip(".") + suffix
    return f"{n:.1f}".rstrip("0").rstrip(".")


def figures(s: dict) -> list[tuple[str, str]]:
    """The four numbers the social card leads with, as (figure, label)."""
    return [
        (f"{s['reports']:,}", "reports"),
        (f"{s['researchers']:,}", "researchers"),
        (f"{s['public']['fixed']:,}", "fixes shipped"),
        (_short(s["awards"]["xe"] / 1_000_000), "XE awarded"),
    ]


def card_version(s: dict) -> str:
    """Changes when a figure on the social card does."""
    return hashlib.sha256(repr((figures(s), spark(s))).encode()).hexdigest()[:10]


def headline(s: dict) -> str:
    """One sentence of the numbers, for the page's description and for a post."""
    return (
        f"{_plural(s['reports'], 'report')} filed, "
        f"{_plural(s['public']['fixed'], 'fix', 'fixes')} shipped, "
        f"{tsvc.xe_amount(s['awards']['xe'])} XE awarded."
    )


# ---- drawing ----------------------------------------------------------------------------------------
# Geometry only: the template writes the SVG from these numbers and the stylesheet colours it, so a
# chart follows the theme and nothing is fetched to draw it.


def _step(top: float) -> int:
    """The gridline step of a chart whose tallest value is `top`: four steps of 1, 2 or 5 times a power
    of ten reach it. Never under 1, so an empty chart still has a scale."""
    for k in range(13):
        for b in (1, 2, 5):
            if b * 10**k * 4 >= top:
                return b * 10**k
    return int(top)


def _buckets(per_day: list[dict]) -> list[list[dict]]:
    size = 1 if len(per_day) <= MAX_BARS else 7
    return [per_day[i : i + size] for i in range(0, len(per_day), size)]


def _first(bucket: list[dict]) -> str:
    return _dm(_d(bucket[0]["day"]))


def _label(bucket: list[dict]) -> str:
    return _first(bucket) if len(bucket) == 1 else f"Week of {_first(bucket)}"


def _ticks(labels: list[str], xs: list[float], most: int = 8) -> list[dict]:
    every = max(1, -(-len(labels) // most))
    return [{"x": round(xs[i], 1), "label": labels[i]} for i in range(0, len(labels), every)]


def _running(vals: list[float], start: float = 0) -> list[float]:
    out, total = [], start
    for v in vals:
        total += v
        out.append(total)
    return out


def _path(pts: list[tuple[float, float]]) -> str:
    return "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in pts)


def spark(s: dict) -> list[int]:
    """Reports per day (per week on a long run), for the bars along the social card."""
    return [sum(d["reports"] for d in b) for b in _buckets(s["per_day"])]


def daily_chart(s: dict, *, w: int = 1080, h: int = 340) -> dict:
    """Reports per day as bars (left axis) under the running total as a line (right axis)."""
    buckets = _buckets(s["per_day"])
    vals = [sum(d["reports"] for d in b) for b in buckets]
    total = _running(vals, s["before"]["reports"])
    labels = [_label(b) for b in buckets]
    left, right, top, bottom = 44, 52, 14, 28
    pw, ph = w - left - right, h - top - bottom
    base = top + ph
    slot = pw / len(vals)
    bw = max(min(slot * 0.72, 44), 1)
    bar_step, line_step = _step(max(vals)), _step(total[-1])
    mid = [left + slot * (i + 0.5) for i in range(len(vals))]
    pts = [(x, base - ph * t / (line_step * 4)) for x, t in zip(mid, total)]
    if len(pts) == 1:
        pts = [(left, pts[0][1]), (left + pw, pts[0][1])]
    bars = []
    for i, v in enumerate(vals):
        bh = ph * v / (bar_step * 4)
        bars.append(
            {
                "x": round(mid[i] - bw / 2, 1), "y": round(base - bh, 1), "w": round(bw, 1),
                "h": round(bh, 1), "slot_x": round(left + slot * i, 1), "slot_w": round(slot, 1),
                "tip": f"{labels[i]}: {_plural(v, 'report')}, {int(total[i]):,} so far",
            }
        )
    return {
        "w": w, "h": h, "left": left, "right": w - right, "top": top, "base": base, "bars": bars,
        "line": _path(pts),
        "area": _path(pts) + f" L{pts[-1][0]:.1f} {base} L{pts[0][0]:.1f} {base} Z",
        "grid": [
            {"y": round(base - ph * k / 4, 1), "l": _short(bar_step * k), "r": _short(line_step * k)}
            for k in range(5)
        ],
        "ticks": _ticks([_first(b) for b in buckets], mid),
    }


def line_chart(
    s: dict, key: str, noun: tuple[str, str], *, scale: int = 1, w: int = 520, h: int = 220
) -> dict:
    """The running total of one daily series: `key` of each day, divided by `scale`."""
    buckets = _buckets(s["per_day"])
    total = _running([sum(d[key] for d in b) / scale for b in buckets], s["before"][key] / scale)
    labels = [_label(b) for b in buckets]
    left, right, top, bottom = 44, 24, 14, 28  # room on the right for half of the last day's label
    pw, ph = w - left - right, h - top - bottom
    base = top + ph
    step = _step(total[-1])
    n = len(total)
    gap = pw / (n - 1) if n > 1 else pw
    xs = [left + gap * i for i in range(n)] if n > 1 else [left + pw / 2]
    pts = [(x, base - ph * t / (step * 4)) for x, t in zip(xs, total)]
    end = pts[-1]
    if n == 1:
        pts = [(left, end[1]), (left + pw, end[1])]
        end = pts[-1]

    def said(t: float) -> str:
        whole = int(t) if float(t).is_integer() else round(t, 2)
        return f"{whole:,} {noun[0] if whole == 1 else noun[1]}"

    return {
        "w": w, "h": h, "left": left, "right": w - right, "top": top, "base": base,
        "line": _path(pts),
        "area": _path(pts) + f" L{pts[-1][0]:.1f} {base} L{pts[0][0]:.1f} {base} Z",
        "end": {"x": round(end[0], 1), "y": round(end[1], 1)},
        "cols": [  # a strip per point, clipped to the plot, for the pointer to land on
            {"x": round(max(x - gap / 2, left), 1),
             "w": round(min(x + gap / 2, left + pw) - max(x - gap / 2, left), 1), "cx": round(x, 1),
             "cy": round(base - ph * t / (step * 4), 1), "tip": f"{label}: {said(t)}"}
            for x, t, label in zip(xs, total, labels)
        ],
        "grid": [{"y": round(base - ph * k / 4, 1), "l": _short(step * k)} for k in range(5)],
        "ticks": _ticks([_first(b) for b in buckets], xs, 5),
    }


def heat_chart(s: dict, *, cell_w: int = 18, cell_h: int = 22, gap: int = 3) -> dict:
    """Weekday by hour (UTC): a cell per hour of the week, stronger the more reports arrived in it."""
    heat = s["by_hour"]
    most = max(max(row) for row in heat)
    left, top = 40, 4
    cells = []
    for r, row in enumerate(heat):
        for c, n in enumerate(row):
            cells.append(
                {
                    "x": left + c * (cell_w + gap), "y": top + r * (cell_h + gap),
                    "o": round(0.12 + 0.88 * (n / most) ** 0.6, 2) if n else 0,
                    "tip": f"{WEEKDAYS[r]} {c:02d}:00 UTC: {_plural(n, 'report')}",
                }
            )
    return {
        "w": left + 24 * (cell_w + gap), "h": top + 7 * (cell_h + gap) + 18, "cw": cell_w, "ch": cell_h,
        "cells": cells,
        "days": [
            {"y": top + r * (cell_h + gap) + cell_h // 2 + 4, "label": d} for r, d in enumerate(WEEKDAYS)
        ],
        "hours": [
            {"x": left + c * (cell_w + gap) + cell_w // 2, "label": f"{c:02d}"} for c in range(0, 24, 3)
        ],
        "hours_y": top + 7 * (cell_h + gap) + 12,
    }


def _hbars(rows: list[tuple[str, str, int]], said=None) -> list[dict]:
    """Horizontal bars: (key, label, n) with each bar's width as a share of the longest."""
    most = max((n for _, _, n in rows), default=0)
    return [
        {"key": k, "label": label, "n": n, "said": said(n) if said else f"{n:,}",
         "pct": round(100 * n / most, 1) if most else 0}
        for k, label, n in rows
    ]


def _busiest_hour(s: dict) -> str:
    n, r, c = max((n, r, c) for r, row in enumerate(s["by_hour"]) for c, n in enumerate(row))
    return f"{WEEKDAYS[r]} {c:02d}:00" if n else ""


def charts(s: dict, cfg) -> dict:
    """Everything `stats.html` draws, from a snapshot: the charts' geometry, the bar lists with their
    labels, and the sentence each chart is described by (the page's markdown twin carries that)."""
    pub, labels = s["public"], cfg.copy_public.get("labels") or {}
    since, busiest = _d(s["since"]), _d(s["busiest"]["day"])
    other = sum(n for k, n in pub["closed"].items() if k not in CLOSED_SHOWN)
    stand = [
        ("fixed", "Fixed", pub["fixed"]),
        ("open", labels.get("open", "Open"), pub["open"]),
        *[(k, f"Closed: {k}", pub["closed"].get(k, 0)) for k in CLOSED_SHOWN],
        ("other", "Closed: other", other),
    ]
    stand = [
        {"key": k, "label": label, "n": n, "pct": round(100 * n / pub["reports"], 2)}
        for k, label, n in stand
        if n
    ]
    tiers = [(k, cfg.tier_label(k), pub["fixed_by_tier"].get(k, 0)) for k in cfg.tier_order]
    tiers = [t for t in tiers if t[2]]
    if pub["fixed_by_tier"].get(UNTIERED):
        tiers.append((UNTIERED, "Not tiered", pub["fixed_by_tier"][UNTIERED]))
    areas = sorted(
        ((k, label, pub["by_area"].get(k, 0)) for k, label in cfg.areas.items()), key=lambda a: -a[2]
    )
    areas = [a for a in areas if a[2]]
    if pub["by_area"].get(UNSORTED):
        areas.append((UNSORTED, "Not sorted yet", pub["by_area"][UNSORTED]))
    top = [(str(i), t["name"], t["award_xe"]) for i, t in enumerate(s["awards"]["top"])]
    return {
        "since": _dmy(since),
        "busiest": _dm(busiest),
        "busiest_hour": _busiest_hour(s),
        "headline": headline(s),
        "daily": daily_chart(s),
        "researchers": line_chart(s, "researchers", ("researcher", "researchers")),
        "fixed": line_chart(s, "fixed", ("fix shipped", "fixes shipped")),
        "awarded": line_chart(s, "awarded_xe", ("XE awarded", "XE awarded"), scale=1_000_000),
        "heat": heat_chart(s),
        "stand": stand,
        "tiers": _hbars(tiers),
        "areas": _hbars(areas),
        "top": _hbars(top, tsvc.xe_amount),
        "weekly": len(s["per_day"]) > MAX_BARS,
    }
