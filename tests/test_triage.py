"""The triage parser against the real docs/BOUNTY_TRIAGE.md: the import has to reproduce the doc's own
counts (90 rows: 87 issues + E1–E3; 32 before, 27 later, 1 decide; 8 duplicates, 4 notices, 8 invalid,
5 support) and the five rulings."""

from collections import Counter

from desk.services.triage import parse_triage


def _rows(text):
    rows = parse_triage(text)
    return rows, {r.key: r for r in rows}


def test_row_count_and_keys(triage_text):
    rows, by = _rows(triage_text)
    assert len(rows) == 90
    assert len(by) == 90, "duplicate keys"
    assert {"E1", "E2", "E3"} <= set(by)
    assert all(r.repo == "xeprotocol/xe" for r in rows if not r.is_email)
    assert all(r.title for r in rows)


def test_gate_and_verdict_counts(triage_text):
    rows, _ = _rows(triage_text)
    gates = Counter(r.gate for r in rows)
    # 35 rows carry **Before** in the per-issue tables (the summary table's "32 + 1 decision" counts
    # fixes, not rows: #104 is a design ticket and #57 a release-process item); #21 is the one
    # **Decide**. The importer keeps what the row says; "via #n" cells are duplicates with no gate.
    assert gates["before"] == 35 and gates["later"] == 29 and gates["decide"] == 1
    assert sum(1 for r in rows if r.duplicate_of_key) == 8
    verdicts = Counter(r.verdict for r in rows)
    assert (
        verdicts["duplicate"] == 8
        and verdicts["notice"] == 4
        and verdicts["invalid"] == 8
        and verdicts["support"] == 5
    )
    assert verdicts["valid"] + verdicts["likely-valid"] + verdicts["design-gap"] == 65
    assert verdicts[None] == 0


def test_cto_rulings_are_the_assessed_tier(triage_text):
    _, by = _rows(triage_text)
    # #8 is a bundle: the row says "mixed → Severe", so no single claimed tier; the first reading (High)
    # is in the reconciliation table and lands in the note
    assert (by["8"].claimed_tier, by["8"].assessed_tier, by["8"].gate) == (None, "severe", "before")
    assert (by["4"].claimed_tier, by["4"].assessed_tier) == ("severe", "high")
    assert (by["96"].claimed_tier, by["96"].assessed_tier) == ("high", "medium")
    assert (by["E2"].assessed_tier, by["E2"].gate) == ("medium", "before")
    assert (by["20"].claimed_tier, by["20"].assessed_tier) == ("medium", "minor")
    for k in ("8", "4", "96", "E2", "20"):
        assert by[k].first_reading, k


def test_internal_column(triage_text):
    _, by = _rows(triage_text)
    assert (by["15"].internal_ref, by["15"].internal_state, by["15"].internal_fix_prs) == (
        "#1028",
        "fixed",
        ["#1029"],
    )
    assert (by["70"].internal_ref, by["70"].internal_state) == ("#1030", "partial")
    assert (by["58"].internal_ref, by["58"].internal_state) == ("#870", "exists")
    assert (by["81"].internal_ref, by["81"].internal_state) == ("#1047", "open")
    assert (by["42"].internal_ref, by["42"].internal_state, by["42"].internal_fix_prs) == (
        "#954",
        "fixed",
        ["#1024"],
    )
    assert (by["99"].internal_ref, by["99"].internal_state) == ("faucet#10", "fixed")
    assert by["3"].internal_ref == "" and by["3"].internal_state == "fixed"
    assert by["32"].internal_ref == ""
    assert by["E3"].internal_ref == "#1068"
    refs = [
        r.internal_ref
        for r in by.values()
        if r.internal_ref.startswith("#10") or r.internal_ref.startswith("#11")
    ]
    assert len(refs) == len(set(refs)), "an internal ticket maps to one row"


def test_status_mapping(triage_text):
    _, by = _rows(triage_text)
    assert by["15"].status() == ("patched", None)
    assert by["70"].status() == ("fixing", None)
    assert by["81"].status() == ("accepted", None)
    assert by["59"].status() == ("accepted", None)
    assert by["89"].status() == ("closed", "duplicate") and by["89"].duplicate_of_key == "15"
    assert by["E1"].status() == ("closed", "duplicate") and by["E1"].duplicate_of_key == "14"
    assert by["61"].duplicate_of_key == "E1"
    assert by["40"].status() == ("closed", "answered") and by["40"].verdict == "notice"
    assert by["74"].status() == ("closed", "invalid")
    assert by["34"].status() == ("closed", "withdrawn")
    # "support" is a verdict on the bounty, not a move to the support door
    assert by["99"].status() == ("closed", "answered") and by["99"].kind == "bounty"
    assert by["3"].status() == ("closed", "stale") and by["3"].kind == "bounty"
    assert (
        by["21"].status() == ("accepted", None)
        and by["21"].gate == "decide"
        and by["21"].verdict == "design-gap"
    )


def test_patches_and_effort(triage_text):
    _, by = _rows(triage_text)
    assert [(p.repo, p.ref) for p in by["15"].patches] == [("xeprotocol/xe", "27"), ("xeprotocol/xe", "111")]
    assert [(p.repo, p.ref, p.note) for p in by["21"].patches] == [("xeprotocol/xe", "25", "partial")]
    assert [(p.repo, p.ref, p.note) for p in by["101"].patches] == [("xeprotocol/dao", "1", "third party")]
    assert [(p.repo, p.ref) for p in by["102"].patches] == [("xeprotocol/sdk", "11")]
    assert [(p.repo, p.ref, p.note) for p in by["55"].patches] == [("xeprotocol/xe", "56", "wrong repo")]
    assert by["15"].effort == "<1h" and by["42"].effort == "3-5d" and by["59"].effort == "half-1d"
    assert by["21"].effort == "design"
    assert by["89"].effort is None
    assert by["104"].gate_note.startswith("design ticket")


def test_notes_and_areas(triage_text):
    _, by = _rows(triage_text)
    assert "Remote, unauthenticated" in by["15"].note
    assert by["15"].title.startswith("`POST /directory/register`")
    assert "*" not in by["15"].title
    assert by["69"].title.startswith("`/accounts/{address}/*`"), by["69"].title
    assert by["42"].area == "consensus" and by["59"].area == "p2p-sync" and by["70"].area == "node-api"
    assert (
        by["21"].area == "leasing-ledger"
        and by["49"].area == "dao-harness"
        and by["104"].area == "sdk-docs-web"
    )
    assert by["57"].area == "ops-testnet" and by["66"].area == "other"
    assert by["E3"].area == "node-api" and by["E1"].area == "consensus"


def test_closed_rows_have_no_assessed_tier(triage_text):
    rows, _ = _rows(triage_text)
    for r in rows:
        if r.verdict in ("duplicate", "notice", "invalid", "support"):
            assert r.assessed_tier is None, r.key
        elif r.key == "21":
            # "Critical → Design": a product decision, no tier until it is made
            assert r.assessed_tier is None and r.assessed_word == "Design"
        else:
            assert r.assessed_tier in ("critical", "severe", "high", "medium", "minor"), (
                r.key,
                r.assessed_word,
            )
