"""Pure checks: canonical digests and signed requests, the authorisation matrix, the status machine,
ids, the vault, TOTP against the RFC vector, config vocabularies, patch-token parsing, GitHub text
helpers, the webhook HMAC. No database, no network."""

import hashlib
import hmac
import time
from dataclasses import replace

import pytest
from fastapi import HTTPException

from desk import authz
from desk.auth import SignedRequest, signing_target, totp_code, totp_verify
from desk.canonical import DOMAIN_EVENT, DOMAIN_EVENT_V2, DOMAIN_LOGIN, DOMAIN_PAYOUT, canonical_json, digest
from desk.log import event_hash
from desk.models import (
    AGENT_SCOPES,
    AREAS,
    CLOSED_REASONS,
    EFFORTS,
    GATES,
    STATUSES,
    TIERS,
    TOPICS,
    VERDICTS,
    AgentToken,
    Ticket,
    User,
)
from desk.services import github as gh
from desk.services import thread
from desk.services.tickets import CLOSED_REASONS_FOR, TRANSITIONS, format_id
from desk.signer import Signer
from desk.vault import Vault, VaultError
from xe.keys import KeyPair, verify_hex_signature

# ---- canonical and signing ------------------------------------------------------------------------


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": [1, 2, {"z": None}]}) == b'{"a":[1,2,{"z":null}],"b":1}'


def test_domains_separate_signatures():
    kp = KeyPair.generate()
    payload = {"ticket": "XE-0001"}
    ts = time.time_ns()
    sig_login = kp.sign_hex(signing_target(DOMAIN_LOGIN, payload, ts))
    verify_hex_signature(kp.pub_key_hex, sig_login, signing_target(DOMAIN_LOGIN, payload, ts))
    with pytest.raises(Exception):
        verify_hex_signature(kp.pub_key_hex, sig_login, signing_target(DOMAIN_PAYOUT, payload, ts))


def test_signed_request_shape_matches_harness():
    req = SignedRequest(payload={"a": 1}, timestamp=1, pub_key="ab" * 32, signature="cd" * 64)
    assert set(req.model_dump()) == {"payload", "timestamp", "pub_key", "signature"}


def test_event_hash_is_domain_separated_and_deterministic():
    base = {"index": 0, "ts": 1, "kind": "k", "actor": "desk", "payload": {"x": 1}, "prev_hash": "0" * 64}
    # v2 (what is written now) covers the private flag and the ref
    h1 = event_hash(0, 1, "k", "desk", {"x": 1}, "0" * 64, public=False, ref="XE-0001")
    h2 = event_hash(0, 1, "k", "desk", {"x": 1}, "0" * 64, public=False, ref="XE-0001")
    assert h1 == h2 == digest(DOMAIN_EVENT_V2, {**base, "public": False, "ref": "XE-0001"}).hex()
    assert event_hash(0, 1, "k", "desk", {"x": 1}, "0" * 64, public=True, ref="XE-0001") != h1
    assert event_hash(1, 1, "k", "desk", {"x": 1}, "0" * 64, public=False, ref="XE-0001") != h1
    # v1 rows (before 4 Nov 2026) still hash as they were written
    assert event_hash(0, 1, "k", "desk", {"x": 1}, "0" * 64, v=1) == digest(DOMAIN_EVENT, base).hex()


# ---- authz ------------------------------------------------------------------------------------------


def _user(*roles):
    return authz.Principal(kind="user", user=User(id=1, email="a@b", roles=list(roles)), roles=set(roles))


def _token(*scopes):
    return authz.Principal(
        kind="token", token=AgentToken(id=7, model_id="m", scopes=list(scopes)), scopes=set(scopes)
    )


def test_matrix_covers_every_scope_and_role():
    scopes = {s for _, (_, ss) in authz.MATRIX.items() for s in ss}
    assert scopes == set(AGENT_SCOPES)
    roles = {r for _, (rs, _) in authz.MATRIX.items() for r in rs} - {"*"}
    assert roles <= set(authz.TEAM_ROLES)


def test_no_token_scope_speaks_or_decides():
    for perm in (
        "reply",
        "status",
        "award",
        "export:payouts",
        "read:payout_address",
        "adopt",
        "facts",
        "tier",
        "admin",
    ):
        for scope in AGENT_SCOPES:
            assert not authz.can(_token(scope), perm), (perm, scope)


def test_people_do_not_propose_and_only_tier_sets_tier():
    assert not authz.can(_user("reviewer", "admin"), "write:proposals")
    assert authz.can(_token("write:proposals"), "write:proposals")
    assert not authz.can_set_field(_user("reviewer"), "assessed_tier")
    assert authz.can_set_field(_user("tier"), "assessed_tier")
    assert authz.can_set_field(_user("reviewer"), "verdict")
    assert not authz.can_set_field(_token("write:notes"), "verdict")


def test_private_tickets_need_read_private():
    priv = Ticket(id="XE-0001", kind="bounty", visibility="private", source="email", title="t", status="new")
    pub = Ticket(id="XE-0002", kind="bounty", visibility="public", source="github", title="t", status="new")
    assert authz.can_see(authz.ANON, pub) and not authz.can_see(authz.ANON, priv)
    assert not authz.can_see(_token("read:public", "write:notes"), priv)
    assert authz.can_see(_token("read:private"), priv)
    assert authz.can_see(_user("reviewer"), priv)
    rep = authz.Principal(kind="reporter", reporter_id=5)
    priv.reporter_id = 5
    assert authz.can_see(rep, priv)
    assert not authz.can_see(replace(rep, reporter_id=6), priv)


def test_require_hides_private_as_404_and_anon_as_401():
    priv = Ticket(id="XE-0001", kind="bounty", visibility="private", source="email", title="t", status="new")
    with pytest.raises(HTTPException) as e:
        authz.require(authz.ANON, "write:notes", priv)
    assert e.value.status_code == 404
    with pytest.raises(HTTPException) as e:
        authz.require(authz.ANON, "write:notes")
    assert e.value.status_code == 401
    with pytest.raises(HTTPException) as e:
        authz.require(_token("read:public"), "reply")
    assert e.value.status_code == 403


def test_system_principal_can_everything_and_is_named_desk():
    assert authz.SYSTEM.actor == "desk"
    for perm in authz.MATRIX:
        assert authz.can(authz.SYSTEM, perm)


# ---- status machine ---------------------------------------------------------------------------------


def test_transitions_use_known_statuses_and_reach_paid():
    for kind, table in TRANSITIONS.items():
        for frm, tos in table.items():
            assert frm in STATUSES
            assert tos <= set(STATUSES)
    seen, frontier = set(), {"new"}
    while frontier:
        s = frontier.pop()
        seen.add(s)
        frontier |= TRANSITIONS["bounty"].get(s, set()) - seen
    assert {"paid", "closed", "disclosed", "patched"} <= seen
    assert TRANSITIONS["bounty"]["paid"] == set()
    assert "closed" in TRANSITIONS["bounty"]["patched"] or "closed" not in TRANSITIONS["bounty"]["patched"]
    assert set(CLOSED_REASONS_FOR["bounty"]) == set(CLOSED_REASONS)
    assert CLOSED_REASONS_FOR["support"] == {"answered", "stale", "duplicate"}


def test_support_flow_is_short():
    assert set(TRANSITIONS["support"]) == {"new", "triaging", "needs-info", "closed"}


def test_ticket_ids():
    assert format_id("bounty", 1) == "XE-0001"
    assert format_id("support", 31) == "XS-0031"
    assert format_id("bounty", 12345) == "XE-12345"


# ---- vault ------------------------------------------------------------------------------------------


def _signer():
    return Signer(
        {"log": KeyPair.generate(), "vault": KeyPair.generate()},
        {"log": {"event.sign"}, "vault": {"vault.seal", "vault.open"}},
    )


def test_vault_roundtrip_and_tamper():
    v = Vault(_signer())
    sealed = v.seal_text("a private report")
    assert sealed != b"a private report" and v.open_text(sealed) == "a private report"
    bad = bytearray(sealed)
    bad[-1] ^= 1
    with pytest.raises(VaultError):
        v.open(bytes(bad))
    assert not Vault(Signer.empty()).available
    with pytest.raises(VaultError):
        Vault(Signer.empty()).seal(b"x")


def test_log_key_cannot_open_the_vault():
    s = Signer({"log": KeyPair.generate()}, {"log": {"event.sign"}})
    assert not Vault(s).available


# ---- TOTP -------------------------------------------------------------------------------------------


def test_totp_rfc6238_vector():
    # RFC 6238 appendix B, SHA-1, secret "12345678901234567890", T=59 -> 94287082 (8 digits); 6 digits = 287082
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp_code(secret, at=59, digits=8) == "94287082"
    assert totp_code(secret, at=59) == "287082"
    assert totp_code(secret, at=1111111109, digits=8) == "07081804"


def test_totp_verify_window_and_garbage():
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    now = int(time.time())
    step = totp_verify(secret, totp_code(secret, at=now))
    assert step == now // 30
    assert totp_verify(secret, totp_code(secret, at=now - 30)) == now // 30 - 1
    assert totp_verify(secret, "abc") is None
    assert totp_verify(secret, totp_code(secret, at=now - 300)) is None
    # a code is accepted once: the step it matched is refused after it was recorded (XE-0820)
    assert totp_verify(secret, totp_code(secret, at=now), after_step=step) is None
    assert totp_verify(secret, totp_code(secret, at=now - 30), after_step=step) is None
    # Unicode digits are not a code, and do not raise (XE-1033)
    assert totp_verify(secret, "\u0661\u0662\u0663\u0664\u0665\u0666") is None


# ---- config -----------------------------------------------------------------------------------------


def test_config_vocabularies_match_code(config):
    assert set(config.tiers) == set(TIERS)
    assert config.tier_order[:3] == ["critical", "severe", "high"]
    assert config.ceiling_micro("severe") == 25_000 * 1_000_000
    assert config.ceiling_micro(None) == 0
    assert set(config.verdicts) == set(VERDICTS)
    assert set(config.topics) == set(TOPICS) and set(config.areas) == set(AREAS)
    assert config.area_vocab("support") == config.topics and config.area_vocab("bounty") == config.areas
    assert not (set(TOPICS) & set(AREAS) - {"other"})  # the two vocabularies do not overlap
    assert set(config.gates) == set(GATES)
    assert set(config.effort_bands) == set(EFFORTS)
    assert config.effort_hours("1-4h") == (2.5, 0.5)
    # awards land on steps of the ceiling, highest first, rounded down to the tier's grain
    assert list(config.award_steps) == ["top", "standard", "reduced", "minimal"]
    assert config.award_xe("high", "top") == 5000 and config.award_xe("high", "standard") == 3500
    assert config.award_xe("severe", "standard") == 8500  # 8,750 rounded down to the 500 grain
    assert config.award_xe("medium", "standard") == 850 and config.award_xe("minor", "minimal") == 50
    assert config.award_xe("minor", "standard", area="other") == 50  # desk findings take a quarter
    assert config.award_xe("none", "top") == 0 and config.award_xe("high", "no-such-step") == 0
    assert config.primary_repo == "xeprotocol/xe"
    assert {label["name"] for label in config.all_labels()} == config.tool_label_names
    assert config.label_for("closed", "duplicate") is not None
    assert config.label_for("patched", None)["name"]
    assert "patched" in config.reply_templates


def test_kill_list_catches_promises(config):
    from desk.config import lint_public_copy

    assert lint_public_copy(config) == []
    assert lint_public_copy(config, ["You will be paid 500 XE."])


# ---- patch tokens and github helpers ----------------------------------------------------------------


def test_patch_token_parsing():
    assert thread.parse_patch_token("#27", "xeprotocol/xe") == ("xeprotocol/xe", "27")
    assert thread.parse_patch_token("dao#1", "xeprotocol/xe") == ("xeprotocol/dao", "1")
    assert thread.parse_patch_token("sdk#11", "xeprotocol/xe") == ("xeprotocol/sdk", "11")
    assert thread.parse_patch_token("acme/thing#5", "xeprotocol/xe") == ("acme/thing", "5")
    assert thread.parse_patch_token("nonsense", "xeprotocol/xe") is None


def test_issue_refs_prefer_closing_keywords():
    assert gh.issue_refs("Fixes #15 and touches #89; see #15 again") == [15, 89]
    assert gh.closing_refs("Fixes #15 and touches #89; resolves: #16") == {15, 16}
    assert gh.closing_refs("see #15") == set()
    assert gh.issue_refs("no refs here, PR-123 is not one") == []
    assert gh.issue_refs("owner/repo#4 is cross-repo") == []


ALIASES = {"xe": "xeprotocol/xe", "dao": "xeprotocol/dao", "sdk": "xeprotocol/sdk"}


def test_public_tags_in_internal_tickets():
    # the convention in xeprotocol/core: "security: bounty bundle xe#8" → xeprotocol/xe issue 8
    assert gh.public_tags("security: bounty bundle xe#8", ALIASES) == [("xeprotocol/xe", 8)]
    assert gh.public_tags("sync nil-block panic xe#8, xe#68 and XE#4", ALIASES) == [
        ("xeprotocol/xe", 8),
        ("xeprotocol/xe", 68),
        ("xeprotocol/xe", 4),
    ]
    # bare #n is core's own numbering; unknown short names and URLs are not tags
    assert (
        gh.public_tags("follow-up to #1029 and foo#3; https://github.com/xeprotocol/xe/issues/8", ALIASES)
        == []
    )
    # the long form needs no alias
    assert gh.public_tags("see xeprotocol/dao#1", {}) == [("xeprotocol/dao", 1)]
    assert gh.public_tags("", ALIASES) == []


def test_desk_ids_in_internal_tickets():
    # a report filed on the desk has no GitHub number; the tracker names it by desk id
    assert gh.desk_tags("security: genesis_hash netcheck XE-0232") == ["XE-0232"]
    assert gh.desk_tags("covers xe-232, XE-0232 and XS-0007; see #1029") == ["XE-0232", "XS-0007"]
    # a desk id inside a longer word, or the repo short name, is not a tag
    assert gh.desk_tags("PRE-XE-0001 and xe#8 and XE-") == []
    assert gh.desk_tags("") == []


def test_claimed_tier_from_text():
    assert gh.claimed_tier("[High] crash", "") == "high"
    assert gh.claimed_tier("crash", "Severity: Severe\n...") == "severe"
    assert gh.claimed_tier("crash", "suggested severity - low") == "minor"
    assert gh.claimed_tier("crash", "nothing") is None


def test_webhook_hmac():
    body = b'{"x":1}'
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert gh.verify_webhook("s3cret", body, sig)
    assert not gh.verify_webhook("s3cret", body + b" ", sig)
    assert not gh.verify_webhook("", body, sig)
    assert not gh.verify_webhook("s3cret", body, "sha1=abc")


# ---- reporters (pure) ---------------------------------------------------------------------------------


def test_filing_privacy_rule():
    from desk.services import reporters as rsvc

    assert rsvc.must_be_private(rsvc.Filing(kind="bounty", private=True))
    assert rsvc.must_be_private(rsvc.Filing(kind="bounty", claimed_tier="critical", private=False))
    assert rsvc.must_be_private(rsvc.Filing(kind="bounty", claimed_tier="severe", private=False))
    assert not rsvc.must_be_private(rsvc.Filing(kind="bounty", claimed_tier="minor", private=False))
    assert not rsvc.must_be_private(rsvc.Filing(kind="support", claimed_tier="critical", private=True))


def test_email_cleaning_and_address_checks():
    from desk.services import reporters as rsvc

    assert rsvc.clean_email("  Alice@Example.ORG ") == "alice@example.org"
    with pytest.raises(HTTPException):
        rsvc.clean_email("nope")
    kp = KeyPair.generate()
    assert rsvc.check_address(kp.address.upper()) == kp.address
    assert rsvc.address_of(kp.pub_key_hex) == kp.address
    with pytest.raises(HTTPException):
        rsvc.check_address("abc")
    with pytest.raises(HTTPException):
        rsvc.address_of("zz")


def test_ticket_url_is_the_bare_id_on_its_front_door():
    from types import SimpleNamespace

    from desk.services.tickets import ticket_url
    from desk.ui import TICKET_ID

    ctx = SimpleNamespace(settings=SimpleNamespace(scheme="https", hosts={"bounty": "bounty.xe.network", "support": "support.xe.network"}))
    assert ticket_url(ctx, SimpleNamespace(kind="bounty", id="XE-0032")) == "https://bounty.xe.network/XE-0032"
    assert ticket_url(ctx, SimpleNamespace(kind="support", id="XS-0007")) == "https://support.xe.network/XS-0007"
    # the route only claims paths that look like an id; everything else stays a 404 and never shadows a page
    for ok in ("XE-0032", "xs-0001", "XE-12345"):
        assert TICKET_ID.fullmatch(ok)
    for bad in ("agent", "team", "XE-1", "XE-0032/x", "XQ-0001", "scope"):
        assert not TICKET_ID.fullmatch(bad)
