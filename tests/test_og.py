"""Social cards draw, at the right size, from the one copy of the mark, with copy that passes the lint."""

import io

from PIL import Image

from desk import brand, og
from desk.config import lint_public_copy


def test_mark_flattens_to_three_shapes():
    polys = og._flatten(brand.MARK_PATH)
    assert len(polys) == 3
    xs = [x for poly in polys for x, _ in poly]
    ys = [y for poly in polys for _, y in poly]
    assert 0 <= min(xs) and max(xs) <= brand.MARK_VIEWBOX[0] + 0.01
    assert 0 <= min(ys) and max(ys) <= brand.MARK_VIEWBOX[1] + 0.01


def test_card_is_1200_by_630_png():
    png = og.draw_card(
        programme="Bounty programme",
        host="bounty.xe.network",
        kicker="XE-0116",
        title="Representative can final-vote two hashes at one position when the commit-lock write fails",
        chips=[("Critical", og._tier_style("critical")), ("Patched", {"outline": brand.STROKE_STRONG})],
    )
    img = Image.open(io.BytesIO(png))
    assert img.format == "PNG" and img.size == (og.W, og.H)
    assert img.getpixel((600, 2)) == brand.BRAND  # accent bar


def test_stats_card_carries_the_figures_over_the_bars():
    figures = [("3,935", "reports"), ("412", "researchers"), ("218", "fixes shipped"), ("1.2M", "XE awarded")]
    card = dict(programme="Bounty programme", host="bounty.xe.network", title="The bounty in numbers")
    png = og.draw_stats_card(**card, figures=figures, bars=[0, 3, 12, 151, 40])
    img = Image.open(io.BytesIO(png))
    assert img.format == "PNG" and img.size == (og.W, og.H)
    assert img.getpixel((600, 2)) == brand.BRAND  # accent bar
    # five bars across the 1040px between the margins, each 208px apart: the fourth is the tallest and
    # stands full height on the hairline at 478; the first is a day with nothing, and nothing is drawn
    assert img.getpixel((800, 440)) == brand.BRAND and img.getpixel((800, 477)) == brand.BRAND
    assert img.getpixel((180, 440)) == brand.BG and img.getpixel((800, 390)) == brand.BG
    # a desk with nothing filed still has a card, and a figure too wide for its column is drawn smaller
    wide = [("1,234,567,890", "reports")] * 4
    for figs, bars in ((figures, []), (figures, [0, 0]), (wide, [1])):
        empty = Image.open(io.BytesIO(og.draw_stats_card(**card, figures=figs, bars=bars)))
        assert empty.size == (og.W, og.H)


def test_wrap_ellipsises_long_titles():
    f = og._font("Geist-Bold", 60)
    lines = og._wrap("word " * 80, f, 1040, 2)
    assert len(lines) == 2 and lines[-1].endswith("…")
    assert og._wrap("short", f, 1040, 2) == ["short"]


def test_page_specs_pass_copy_lint(config):
    texts = []
    for site in ("bounty", "support"):

        class C:
            pass

        c = C()
        c.config = config
        for slug in og.PAGES:
            spec = og.page_spec(c, site, slug)
            texts += [spec["title"], spec["line"]]
    assert lint_public_copy(config, texts) == []


def test_the_icon_is_the_mark_in_every_form_a_browser_asks_for():
    """A tab, a bookmark and a home screen show the XE mark, white on the desk's dark ground: as SVG, as
    `/favicon.ico` and as the touch icon, each drawn from the one copy of the mark and each named in the
    page's head, so no browser is left to pick something off the page."""
    from pathlib import Path

    svg = og.icon_svg()
    assert brand.MARK_PATH in svg and 'fill="#0a0a0a"' in svg and svg.startswith("<svg xmlns=")
    icon = og.draw_icon(64)
    assert icon.size == (64, 64)
    assert icon.getpixel((0, 0))[3] < 16  # the corner is rounded away
    assert icon.getpixel((32, 6)) == (*brand.BG, 255)  # the ground, above the mark
    assert min(icon.getpixel((44, 32))[:3]) > 235  # the mark's bar, right of centre
    ico = Image.open(io.BytesIO(og.icon_bytes("ico")))
    assert ico.format == "ICO" and {(16, 16), (32, 32), (48, 48)} <= set(ico.info["sizes"])
    touch = Image.open(io.BytesIO(og.icon_bytes("touch")))
    assert (touch.format, touch.size, touch.mode) == ("PNG", (180, 180), "RGB")
    assert max(touch.getpixel((0, 0))) < 16  # square and opaque to the corner: the phone rounds it
    root = Path(og.__file__).parent
    head = (root / "templates" / "base.html").read_text()
    paths = {r.path for r in og.icons.routes}
    for href in ("/favicon.ico", "/favicon.svg", "/apple-touch-icon.png"):
        assert f'href="{href}"' in head and href in paths
    main = (root / "main.py").read_text()
    assert main.index("include_router(og.icons)") < main.index("include_router(ui_router)")
