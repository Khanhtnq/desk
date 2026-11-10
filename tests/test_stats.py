"""`/stats`: the geometry the charts are drawn from, and the page itself rendered from a snapshot.

What is counted, and for whom, is asserted against Postgres in test_db.py
(`test_stats_count_what_an_anonymous_reader_can`); nothing here needs a database."""

from collections import Counter
from datetime import date, timedelta

from desk import authz
from desk.mirror import html_to_markdown
from desk.services import stats


def _snap(reports, *, before=0, **series):
    """A snapshot as `stats.collect` returns one: `reports` per day from 1 November 2026."""
    zero = [0] * len(reports)
    days = [date(2026, 11, 1) + timedelta(days=i) for i in range(len(reports))]
    per_day = [
        {
            "day": d.isoformat(), "reports": reports[i], "researchers": series.get("researchers", zero)[i],
            "fixed": series.get("fixed", zero)[i], "awarded_xe": series.get("awarded_xe", zero)[i],
        }
        for i, d in enumerate(days)
    ]
    heat = [[0] * 24 for _ in range(7)]
    heat[1][14], heat[0][0] = 37, 1
    busiest = max(per_day, key=lambda d: d["reports"])
    return {
        "as_of": "2026-11-10T14:03:22+00:00", "since": days[0].isoformat(), "days": len(days),
        "reports": before + sum(reports), "researchers": sum(series.get("researchers", zero)),
        "last_7_days": sum(reports[-7:]),
        "busiest": {"day": busiest["day"], "reports": busiest["reports"]},
        "before": {"reports": before, "researchers": 0, "fixed": 0, "awarded_xe": 0},
        "per_day": per_day, "by_hour": heat,
        "public": {
            "reports": 10, "open": 3, "fixed": 4, "closed": {"duplicate": 2, "stale": 1},
            "fixed_by_tier": {"minor": 3, "high": 1},
            "by_area": {"consensus": 2, "other": 7, "unsorted": 1},
        },
        "awards": {
            "xe": 7_500_000, "tickets": 2, "researchers": 1,
            "top": [{"name": "<b>ada</b>", "login": "ada", "award_xe": 7_500_000, "tickets": 2}],
        },
        "log_entries": 42,
    }


def test_scale_steps_are_round():
    assert [stats._step(n) for n in (0, 4, 5, 151, 3935)] == [1, 1, 2, 50, 1000]
    assert [stats._short(n) for n in (0, 50, 100, 1000, 1500, 20000, 1_200_000)] == [
        "0", "50", "100", "1k", "1.5k", "20k", "1.2M",
    ]


def test_charts_begin_where_the_reports_do():
    aug, nov = date(2026, 8, 22), date(2026, 11, 1)
    # one early report and then months of nothing: the charts begin when the reports do
    assert stats._start(Counter({aug: 1, nov: 60, nov + timedelta(days=1): 40})) == nov
    # a lull once the programme is running is part of the picture
    assert stats._start(Counter({aug: 30, nov: 60})) == aug
    assert stats._start(Counter({nov: 1})) == nov


def test_daily_chart_geometry():
    c = stats.daily_chart(_snap([1, 3, 0], before=5))
    assert (c["w"], c["h"], c["left"], c["right"], c["top"], c["base"]) == (1080, 340, 44, 1028, 14, 312)
    # the tallest day is 3, so the bars are scaled to 4: three quarters of the 298 between top and base
    assert [(b["y"], b["h"]) for b in c["bars"]] == [(237.5, 74.5), (88.5, 223.5), (312.0, 0.0)]
    assert c["bars"][0]["x"] == 186.0 and c["bars"][0]["w"] == 44
    assert [b["tip"] for b in c["bars"]] == [
        "1 Nov: 1 report, 6 so far", "2 Nov: 3 reports, 9 so far", "3 Nov: 0 reports, 9 so far",
    ]
    # the running total starts from what came before the chart does, on a scale of its own
    assert [g["l"] for g in c["grid"]] == ["0", "1", "2", "3", "4"]
    assert [g["r"] for g in c["grid"]] == ["0", "5", "10", "15", "20"]
    assert [g["y"] for g in c["grid"]] == [312.0, 237.5, 163.0, 88.5, 14.0]
    assert c["line"] == "M208.0 222.6 L536.0 177.9 L864.0 177.9"  # 6 and then 9, of 20
    assert c["area"] == c["line"] + " L864.0 312 L208.0 312 Z"
    assert [t["label"] for t in c["ticks"]] == ["1 Nov", "2 Nov", "3 Nov"]


def test_a_long_run_is_drawn_by_the_week_and_a_first_day_still_draws():
    long = stats.daily_chart(_snap([1] * 121))
    assert len(long["bars"]) == 18 and long["bars"][0]["tip"] == "Week of 1 Nov: 7 reports, 7 so far"
    assert long["bars"][-1]["tip"] == "Week of 28 Feb: 2 reports, 121 so far"
    assert len(long["ticks"]) <= 8
    one = _snap([4])
    assert stats.daily_chart(one)["line"] == "M44.0 14.0 L1028.0 14.0"  # 4 of 4, straight across the top
    lone = stats.line_chart(one, "researchers", ("researcher", "researchers"))
    assert len(lone["cols"]) == 1 and (lone["cols"][0]["x"], lone["cols"][0]["w"]) == (44, 452)
    assert stats.spark(one) == [4] and stats.spark(_snap([1] * 121))[:2] == [7, 7]


def test_line_chart_runs_a_total_in_whole_units():
    s = _snap([1, 1, 1], awarded_xe=[0, 5_000_000, 2_500_000], researchers=[1, 0, 2])
    c = stats.line_chart(s, "awarded_xe", ("XE awarded", "XE awarded"), scale=1_000_000)
    assert [col["tip"] for col in c["cols"]] == [
        "1 Nov: 0 XE awarded", "2 Nov: 5 XE awarded", "3 Nov: 7.5 XE awarded",
    ]
    assert [g["l"] for g in c["grid"]] == ["0", "2", "4", "6", "8"]
    assert c["line"].startswith("M44.0 192.0 L") and c["line"].count(" L") == 2 and c["area"].endswith(" Z")
    r = stats.line_chart(s, "researchers", ("researcher", "researchers"))
    assert [col["tip"] for col in r["cols"]] == [
        "1 Nov: 1 researcher", "2 Nov: 1 researcher", "3 Nov: 3 researchers",
    ]
    assert r["end"] == {"x": 496.0, "y": 58.5}  # 3 of 4, at the right edge of the plot


def test_heat_is_a_cell_per_hour_of_the_week():
    h = stats.heat_chart(_snap([1]))
    assert len(h["cells"]) == 7 * 24 and [d["label"] for d in h["days"]] == list(stats.WEEKDAYS)
    lit = {c["tip"]: c["o"] for c in h["cells"] if c["o"]}
    assert lit == {"Mon 00:00 UTC: 1 report": 0.22, "Tue 14:00 UTC: 37 reports": 1.0}
    assert stats._busiest_hour(_snap([1])) == "Tue 14:00"
    quiet = _snap([0])
    quiet["by_hour"] = [[0] * 24 for _ in range(7)]
    assert not any(c["o"] for c in stats.heat_chart(quiet)["cells"]) and stats._busiest_hour(quiet) == ""


def test_bar_lists_follow_the_vocabularies(config):
    ch = stats.charts(_snap([1, 3, 0]), config)
    stand = [(r["key"], r["n"]) for r in ch["stand"]]
    assert stand == [("fixed", 4), ("open", 3), ("duplicate", 2), ("other", 1)]
    assert sum(r["n"] for r in ch["stand"]) == 10 and ch["stand"][0]["pct"] == 40.0
    assert [(r["key"], r["label"], r["n"], r["pct"]) for r in ch["tiers"]] == [
        ("high", "High", 1, 33.3), ("minor", "Minor", 3, 100.0),
    ]
    assert [(r["key"], r["n"]) for r in ch["areas"]] == [("other", 7), ("consensus", 2), ("unsorted", 1)]
    assert [(r["label"], r["said"], r["pct"]) for r in ch["top"]] == [("<b>ada</b>", "7.5", 100.0)]
    assert ch["since"] == "1 Nov 2026" and ch["busiest"] == "2 Nov" and not ch["weekly"]
    assert ch["headline"] == "4 reports filed, 4 fixes shipped, 7.5 XE awarded."
    assert stats.figures(_snap([1, 3, 0]))[-1] == ("7.5", "XE awarded")
    assert stats.card_version(_snap([1, 3, 0])) != stats.card_version(_snap([1, 3, 1]))


def _page(config, s) -> str:
    """`stats.html` as `ui.render` would write it for an anonymous reader on the bounty door."""
    from desk import ui

    copy = config.copy_public
    og = {"title": "t", "description": "d", "url": "u", "site_name": "n",
          "image": "https://bounty.xe.network/og/page/stats.png?v=1"}
    ctx = {
        "og": og, "copy": copy, "cfg": config, "badge": "testnet", "network_id": "testnet-0005",
        "version": "0", "site": "bounty", "site_name": "XE Bounty", "site_copy": copy,
        "bounty_url": "https://bounty.xe.network", "support_url": "https://support.xe.network",
        "split": True, "me": None, "p": authz.ANON, "team": False, "csrf": "", "path": "/stats",
        "s": s, "ch": stats.charts(s, config),
    }
    return ui.templates.env.get_template("stats.html").render(ctx)


def test_the_page_renders_and_its_twin_says_the_numbers(config):
    html = _page(config, _snap([1, 3, 0], before=2, researchers=[1, 0, 2], fixed=[0, 4, 0]))
    # in the menu after Scope, and marked as where the reader is
    assert html.index('href="/scope"') < html.index('href="/stats"') < html.index('href="/leaderboard"')
    assert '<a href="/stats" aria-current="page">Stats</a>' in html
    # a strip to point at for every bar and every point of the three running totals, and the week of hours
    assert html.count('class="st-hit"') == 3 + 3 * 3 and html.count('class="st-cell') == 7 * 24
    assert html.count("<svg class=\"st-svg") == 5
    # a name is text wherever it is written
    assert "&lt;b&gt;ada&lt;/b&gt;" in html and "<b>ada</b>" not in html
    assert "/og/page/stats.png?v=1" in html and "/static/stats.js?v=" in html
    md = html_to_markdown(html, "https://bounty.xe.network/stats")
    assert "# The bounty in numbers" in md and "Reports filed since 1 Nov 2026" in md
    assert "The numbers by day" in md and "2026-11-02" in md and "<svg" not in md and "st-hit" not in md


def test_an_empty_desk_still_has_a_page(config):
    s = _snap([0])
    s["by_hour"] = [[0] * 24 for _ in range(7)]
    s["public"] = {"reports": 0, "open": 0, "fixed": 0, "closed": {}, "fixed_by_tier": {}, "by_area": {}}
    s["awards"] = {"xe": 0, "tickets": 0, "researchers": 0, "top": []}
    html = _page(config, s)
    assert "No public reports yet." in html and "No fixes yet." in html and "Nobody yet" in html
