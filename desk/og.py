"""Social cards: the 1200×630 image behind every public page's `og:image`.

Drawn on demand with Pillow, cached in memory by ETag, served from `/og/...`. A ticket card carries the
id, the title, the tier, the status and (once awarded) the award; a page card carries the page's name and
one line about it. Every card carries the XE mark, "Bounty programme" (or "Support") and the host, so a
link unfurled in Slack, Discord or X is unmistakably the desk even before anyone reads the title.

Private tickets and anything the anonymous visitor cannot see fall back to the site card: a crawler is
anonymous, and a title must never leak through an image that a chat client fetches without cookies.
"""

from __future__ import annotations

import hashlib
import io
import re
import threading
from collections import OrderedDict
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from PIL import Image, ImageDraw, ImageFont
from starlette.concurrency import run_in_threadpool

from . import brand
from .authz import ANON, can_see
from .context import get_context
from .db import session
from .services import tickets as tsvc
from .ui import site_for

router = APIRouter(prefix="/og", include_in_schema=False)

W, H = 1200, 630
PAD = 80
FONTS = Path(__file__).parent / "static" / "fonts"
TICKET_ID = re.compile(r"X[ES]-\d{4,}", re.IGNORECASE)
SLUG = re.compile(r"[a-z][a-z0-9-]{0,31}")

# Pages that have a card of their own. Anything else gets the site card ("index").
PAGES = ("index", "scope", "leaderboard", "log", "agent", "report", "ask", "live")

_fonts: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}
_lock = threading.Lock()
_cache: OrderedDict[str, bytes] = OrderedDict()
CACHE_MAX = 512


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    key = (name, size)
    f = _fonts.get(key)
    if f is None:
        f = _fonts[key] = ImageFont.truetype(str(FONTS / f"{name}.ttf"), size)
    return f


# ---- the mark ---------------------------------------------------------------------------------------

_NUM = re.compile(r"[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?")
_CMD = re.compile(r"[MLHVCZmlhvcz]")


def _flatten(path: str, steps: int = 14) -> list[list[tuple[float, float]]]:
    """Absolute M/L/H/V/C/Z only, which is what the mark uses. Cubics are flattened to `steps` segments."""
    polys: list[list[tuple[float, float]]] = []
    cur: list[tuple[float, float]] = []
    x = y = 0.0
    i = 0
    while i < len(path):
        m = _CMD.match(path, i)
        if not m:
            i += 1
            continue
        cmd = m.group()
        i = m.end()
        nums: list[float] = []
        while True:
            n = _NUM.match(path, i)
            if not n:
                sp = re.compile(r"[\s,]+").match(path, i)
                if sp:
                    i = sp.end()
                    continue
                break
            nums.append(float(n.group()))
            i = n.end()
        if cmd == "M":
            if cur:
                polys.append(cur)
            x, y = nums[0], nums[1]
            cur = [(x, y)]
            for j in range(2, len(nums), 2):
                x, y = nums[j], nums[j + 1]
                cur.append((x, y))
        elif cmd == "L":
            for j in range(0, len(nums), 2):
                x, y = nums[j], nums[j + 1]
                cur.append((x, y))
        elif cmd == "H":
            for v in nums:
                x = v
                cur.append((x, y))
        elif cmd == "V":
            for v in nums:
                y = v
                cur.append((x, y))
        elif cmd == "C":
            for j in range(0, len(nums), 6):
                x1, y1, x2, y2, x3, y3 = nums[j : j + 6]
                for s in range(1, steps + 1):
                    t = s / steps
                    u = 1 - t
                    px = u * u * u * x + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3
                    py = u * u * u * y + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3
                    cur.append((px, py))
                x, y = x3, y3
        elif cmd == "Z":
            if cur:
                polys.append(cur)
                x, y = cur[0]
            cur = []
    if cur:
        polys.append(cur)
    return polys


def _mark(height: int, colour: tuple[int, int, int]) -> Image.Image:
    """The mark rastered at `height` px, supersampled ×4 and downsampled for clean edges."""
    vw, vh = brand.MARK_VIEWBOX
    ss = 4
    scale = height * ss / vh
    w = int(round(vw * scale))
    img = Image.new("RGBA", (w, height * ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for poly in _flatten(brand.MARK_PATH):
        d.polygon([(px * scale, py * scale) for px, py in poly], fill=(*colour, 255))
    return img.resize((w // ss, height), Image.LANCZOS)


# ---- text -------------------------------------------------------------------------------------------


def _clean(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", s or "").strip()


def _wrap(text: str, font: ImageFont.FreeTypeFont, width: int, lines: int) -> list[str]:
    """Greedy wrap to at most `lines` lines; the last line is ellipsised if the text runs on."""
    words = _clean(text).split()
    out: list[str] = []
    cur = ""
    i = 0
    while i < len(words):
        trial = f"{cur} {words[i]}".strip()
        if not cur or font.getlength(trial) <= width:
            cur = trial
            i += 1
        else:
            out.append(cur)
            cur = ""
            if len(out) == lines:
                break
    if len(out) < lines:
        if cur:
            out.append(cur)
        return out
    # overflowed: run the rest onto the last line and ellipsise it to fit
    last = f"{out[-1]} {' '.join(words[i:])}".strip()
    while " " in last and font.getlength(last + "…") > width:
        last = last.rsplit(" ", 1)[0]  # drop whole words first
    while last and font.getlength(last + "…") > width:
        last = last[:-1].rstrip()  # then characters, for a single word wider than the card
    out[-1] = last + "…"
    return out


def _chip(
    d: ImageDraw.ImageDraw,
    x: int,
    y: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    *,
    fill: tuple[int, int, int] | None = None,
    outline: tuple[int, int, int] | None = None,
    colour: tuple[int, int, int] = brand.TEXT_HIGH,
) -> int:
    """A rounded pill; returns the x after it."""
    pad_x, h = 18, 44
    tw = int(font.getlength(text))
    box = (x, y, x + tw + pad_x * 2, y + h)
    d.rounded_rectangle(box, radius=h // 2, fill=fill, outline=outline, width=2 if outline else 0)
    d.text((x + pad_x, y + h // 2), text, font=font, fill=colour, anchor="lm")
    return box[2] + 12


def _tier_style(tier: str) -> dict:
    if tier == "critical":
        return {"fill": brand.NEGATIVE, "colour": brand.TEXT_HIGH}
    if tier == "severe":
        return {"fill": brand.BRAND_FILL, "colour": brand.TEXT_HIGH}
    if tier == "high":
        return {"outline": brand.BRAND, "colour": brand.BRAND}
    if tier == "medium":
        return {"outline": brand.STROKE_STRONG, "colour": brand.TEXT_HIGH}
    return {"outline": brand.STROKE_STRONG, "colour": brand.TEXT_LOW}


# ---- the card ---------------------------------------------------------------------------------------


def draw_card(
    *,
    programme: str,
    host: str,
    title: str,
    kicker: str = "",
    line: str = "",
    chips: list[tuple[str, dict]] | None = None,
) -> bytes:
    """One PNG. `kicker` sits above the title (a ticket id); `line` below it (a page description);
    `chips` are (text, style) pills under the title."""
    img = Image.new("RGB", (W, H), brand.BG)
    d = ImageDraw.Draw(img)

    # accent bar
    d.rectangle((0, 0, W, 6), fill=brand.BRAND)

    # lockup: mark + programme
    mark = _mark(44, brand.BRAND)
    img.paste(mark, (PAD, PAD), mark)
    pf = _font("Geist-Medium", 30)
    d.text((PAD + mark.width + 18, PAD + 22), programme, font=pf, fill=brand.TEXT_HIGH, anchor="lm")

    # body: a ticket starts high to make room for its chips; a page sits lower, nearer the middle
    y = 212 if kicker else 262
    if kicker:
        d.text((PAD, y), kicker, font=_font("GeistMono-Regular", 30), fill=brand.BRAND, anchor="la")
        y += 56
    tf = _font("Geist-Bold", 60 if len(title) <= 40 else 54)
    lines = _wrap(title, tf, W - PAD * 2, 2)
    for ln in lines:
        d.text((PAD, y), ln, font=tf, fill=brand.TEXT_HIGH, anchor="la")
        y += int(tf.size * 1.14)
    y += 26
    if chips:
        cf = _font("Geist-Medium", 24)
        x = PAD
        for text, style in chips:
            x = _chip(d, x, y, text, cf, **style)
        y += 44 + 18
    if line:
        lf = _font("Geist-Medium", 28)
        for ln in _wrap(line, lf, W - PAD * 2, 2):
            d.text((PAD, y), ln, font=lf, fill=brand.TEXT_MEDIUM, anchor="la")
            y += int(lf.size * 1.4)

    # footer: host, and a hairline above it
    d.line((PAD, H - PAD - 44, W - PAD, H - PAD - 44), fill=(37, 37, 37), width=1)
    d.text((PAD, H - PAD + 6), host, font=_font("GeistMono-Regular", 24), fill=brand.TEXT_LOW, anchor="ls")

    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


# ---- what goes on which card ------------------------------------------------------------------------


def _programme(site: str) -> str:
    return "Support" if site == "support" else "Bounty programme"


def page_spec(c, site: str, slug: str) -> dict:
    """Title and line for a page card, from the copy register so the lint sees them."""
    copy = c.config.copy_public
    sc = (copy.get("support") or {}) if site == "support" else copy
    cards = (sc.get("cards") or {}) if isinstance(sc, dict) else {}
    name = copy.get("support_name" if site == "support" else "bounty_name", copy.get("site_name", "XE"))
    if slug == "index" or slug not in PAGES:
        return {"title": name, "line": sc.get("footer_line", "")}
    card = cards.get(slug) or {}
    return {"title": card.get("title") or slug.replace("-", " ").capitalize(), "line": card.get("line", "")}


def _xe(micro: int) -> str:
    """Whole XE with any fraction kept, as the ticket page shows it (XE-1107)."""
    whole, frac = divmod(int(micro), 1_000_000)
    return f"{whole:,}" if frac == 0 else f"{whole:,}.{frac:06d}".rstrip("0")


def ticket_spec(c, t) -> dict:
    labels = c.config.copy_public.get("labels") or {}
    chips: list[tuple[str, dict]] = []
    if t.kind == "bounty" and t.assessed_tier and not tsvc.assessment_held(t):
        chips.append((c.config.tier_label(t.assessed_tier), _tier_style(t.assessed_tier)))
    status = labels.get(t.status, t.status)
    chips.append((status, {"outline": brand.STROKE_STRONG, "colour": brand.TEXT_MEDIUM}))
    if t.kind == "bounty" and t.award_xe is not None and t.status in ("awarded", "paid"):
        chips.append((f"{_xe(t.award_xe)} XE", {"outline": brand.BRAND, "colour": brand.BRAND}))
    return {"kicker": t.id, "title": t.title, "chips": chips}


def _etag(*parts: object) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode())
        h.update(b"\0")
    return h.hexdigest()[:20]


def _cached(etag: str, make) -> bytes:
    with _lock:
        png = _cache.get(etag)
        if png is not None:
            _cache.move_to_end(etag)
            return png
    png = make()
    with _lock:
        _cache[etag] = png
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)
    return png


def _respond(request: Request, etag: str, make) -> Response:
    quoted = f'"{etag}"'
    if request.headers.get("if-none-match") == quoted:
        return Response(status_code=304, headers={"ETag": quoted})
    png = _cached(etag, make)
    return Response(
        png,
        media_type="image/png",
        headers={
            "ETag": quoted,
            "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ---- routes -----------------------------------------------------------------------------------------


def _site_host(request: Request) -> tuple[str, str]:
    c = get_context()
    site = site_for(request)
    return site, c.settings.hosts[site]


@router.get("/page/{slug}.png")
async def page_card(request: Request, slug: str):
    if not SLUG.fullmatch(slug):
        raise HTTPException(404)
    c = get_context()
    site, host = _site_host(request)
    spec = page_spec(c, site, slug)
    key = slug if slug in PAGES else "index"  # every unknown slug is the one site card (XE-1274)
    etag = _etag("page", site, key, spec, c.config.hashes.get("copy/public.yaml", ""))

    def make():
        return draw_card(programme=_programme(site), host=host, **spec)

    return await run_in_threadpool(_respond, request, etag, make)


@router.get("/{tid}.png")
async def ticket_card(request: Request, tid: str):
    if not TICKET_ID.fullmatch(tid):
        raise HTTPException(404)
    c = get_context()
    site, host = _site_host(request)
    async with session() as db:
        t = await tsvc.get(db, tid.upper())
    if t is None or not can_see(ANON, t):
        # the site card, so a private link still unfurls as the desk without saying anything about the ticket
        spec = page_spec(c, site, "index")
        etag = _etag("page", site, "index", spec, c.config.hashes.get("copy/public.yaml", ""))
    else:
        spec = ticket_spec(c, t)
        # the key covers what the card shows and nothing it withholds (XE-0822)
        etag = _etag("ticket", site, spec, c.config.hashes.get("copy/public.yaml", ""))

    def make():
        return draw_card(programme=_programme(site), host=host, **spec)

    return await run_in_threadpool(_respond, request, etag, make)
