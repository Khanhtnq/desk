"""Standalone unit tests for proposal RBAC rejection guards and XE-1054 invariants."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy.sql.elements import BinaryExpression

from desk import authz
from desk.models import AgentToken, Proposal, Ticket, User
from desk.services import proposals
from desk.services.tickets import utcnow


class FakeEventLog:
    def __init__(self) -> None:
        self.appended: list[dict] = []

    async def append(self, db, kind, actor, payload, *, ref="", public=False) -> None:
        self.appended.append(
            {"kind": kind, "actor": actor, "payload": payload, "ref": ref, "public": public}
        )


class FakeContext:
    def __init__(self, config) -> None:
        self.config = config
        self.events = FakeEventLog()


class FakeResult:
    def __init__(self, items) -> None:
        self._items = list(items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalars(self):
        return self

    def all(self):
        return list(self._items)


class _Nested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, tb):
        pass


class FakeAsyncSession:
    def __init__(self, tickets=None, proposals_list=None) -> None:
        self.tickets: dict[str, Ticket] = {t.id: t for t in (tickets or [])}
        self.proposals: dict[int, Proposal] = {p.id: p for p in (proposals_list or [])}
        self.added: list = []
        self._next_pr_id = max(self.proposals.keys(), default=0) + 1

    def add(self, obj) -> None:
        if isinstance(obj, Proposal):
            if obj.id is None:
                obj.id = self._next_pr_id
                self._next_pr_id += 1
            self.proposals[obj.id] = obj
        elif isinstance(obj, Ticket):
            self.tickets[obj.id] = obj
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def refresh(self, obj, **kw) -> None:
        pass

    def begin_nested(self):
        return _Nested()

    async def execute(self, stmt):
        entity = getattr(stmt.column_descriptions[0]["entity"], "__name__", "")
        if entity == "Ticket":
            candidates = list(self.tickets.values())
        elif entity == "Proposal":
            candidates = list(self.proposals.values())
        else:
            candidates = []
        matched = [c for c in candidates if self._eval_node(stmt.whereclause, c)]
        return FakeResult(matched)

    def _eval_node(self, node, obj) -> bool:
        if node is None:
            return True
        if hasattr(node, "clauses"):
            results = [self._eval_node(c, obj) for c in node.clauses]
            op = getattr(node.operator, "__name__", "")
            return any(results) if "or" in op else all(results)
        if isinstance(node, BinaryExpression):
            col_name = getattr(node.left, "name", None)
            if not col_name:
                return True
            val = getattr(obj, col_name, None)
            target = getattr(node.right, "value", None)
            op = getattr(node.operator, "__name__", "")
            if op == "eq":
                return val == target
            if op == "ne":
                return val != target
            if op == "in_op":
                target_vals = target if isinstance(target, (list, tuple, set)) else [target]
                return val in target_vals
        return True


def _make_user(user_id: int, *roles: str) -> authz.Principal:
    return authz.Principal(
        kind="user",
        user=User(id=user_id, email=f"user{user_id}@example.org", roles=list(roles)),
        roles=set(roles),
    )


def _make_token(token_id: int = 1, *scopes: str) -> authz.Principal:
    return authz.Principal(
        kind="token",
        token=AgentToken(id=token_id, model_id="agent-model", scopes=list(scopes)),
        scopes=set(scopes),
    )


async def test_reviewer_rejection_of_assessed_tier_refused_and_preserved(config):
    """Plain reviewer cannot reject assessed_tier; tier role can reject."""
    ctx = FakeContext(config)
    t = Ticket(id="XE-0001", kind="bounty", visibility="public", status="new")
    pr = Proposal(id=1, ticket_id="XE-0001", field="assessed_tier", value={"value": "high"}, state="pending")
    db = FakeAsyncSession(tickets=[t], proposals_list=[pr])

    p_rev = _make_user(2, "reviewer")
    with pytest.raises(HTTPException) as exc:
        await proposals.decide(ctx, db, p_rev, pr, False)
    assert exc.value.status_code == 403
    assert exc.value.detail == "tier rulings need the tier role"
    assert pr.state == "pending"

    p_tier = _make_user(3, "reviewer", "tier")
    out = await proposals.decide(ctx, db, p_tier, pr, False)
    assert out["adopted"] is False
    assert pr.state == "rejected"
    assert pr.decided_by == 3


async def test_reviewer_rejection_of_award_xe_refused_and_fill_awards_adopts(config):
    """Plain reviewer (or reviewer+tier) cannot reject award_xe; fill_awards later adopts it."""
    ctx = FakeContext(config)
    t = Ticket(
        id="XE-0002",
        kind="bounty",
        visibility="public",
        status="triaging",
        assessed_tier="high",
        award_xe=None,
    )
    pr = Proposal(id=10, ticket_id="XE-0002", field="award_xe", value={"value": 5000}, state="pending")
    db = FakeAsyncSession(tickets=[t], proposals_list=[pr])

    p_rev = _make_user(4, "reviewer")
    with pytest.raises(HTTPException) as exc:
        await proposals.decide(ctx, db, p_rev, pr, False)
    assert exc.value.status_code == 403
    assert pr.state == "pending"

    p_tier = _make_user(5, "reviewer", "tier")
    with pytest.raises(HTTPException) as exc2:
        await proposals.decide(ctx, db, p_tier, pr, False)
    assert exc2.value.status_code == 403
    assert pr.state == "pending"

    p_treas = _make_user(6, "reviewer", "treasurer")
    res = await proposals.fill_awards(ctx, db, p_treas, ["XE-0002"], "standard")
    assert len(res["filled"]) == 1
    assert res["filled"][0]["from"] == "proposal #10"
    assert pr.state == "adopted"
    assert t.award_xe == 5000 * 1_000_000

    pr2 = Proposal(id=11, ticket_id="XE-0002", field="award_xe", value={"value": 3500}, state="pending")
    db.add(pr2)
    out = await proposals.decide(ctx, db, p_treas, pr2, False)
    assert out["adopted"] is False
    assert pr2.state == "rejected"


async def test_decide_many_skips_unauthorized_rejections_and_keeps_pending(config):
    """decide_many by plain reviewer skips tier/award rejections and rejects authorized items."""
    ctx = FakeContext(config)
    t = Ticket(
        id="XE-0003",
        kind="bounty",
        visibility="public",
        status="new",
        assessed_tier="high",
        award_xe=None,
    )
    pr_effort = Proposal(
        id=21, ticket_id="XE-0003", field="effort_eng", value={"value": "1-4h"}, state="pending"
    )
    pr_tier = Proposal(
        id=22, ticket_id="XE-0003", field="assessed_tier", value={"value": "severe"}, state="pending"
    )
    pr_award = Proposal(
        id=23, ticket_id="XE-0003", field="award_xe", value={"value": 1000}, state="pending"
    )
    db = FakeAsyncSession(tickets=[t], proposals_list=[pr_effort, pr_tier, pr_award])

    p_rev = _make_user(7, "reviewer")
    res = await proposals.decide_many(ctx, db, p_rev, adopt=[], reject=[21, 22, 23])

    assert len(res["decided"]) == 1
    assert res["decided"][0]["proposal"] == 21
    assert pr_effort.state == "rejected"

    assert len(res["skipped"]) == 2
    skipped_ids = {s["proposal"] for s in res["skipped"]}
    assert skipped_ids == {22, 23}
    assert pr_tier.state == "pending"
    assert pr_award.state == "pending"


async def test_visibility_and_reply_draft_adoption_permissions(config, monkeypatch):
    """decide enforces visibility and reply permission even when send_plain is False."""
    ctx = FakeContext(config)
    priv = Ticket(id="XE-0004", kind="bounty", visibility="private", status="new")
    pr_priv = Proposal(
        id=31, ticket_id="XE-0004", field="verdict", value={"value": "valid"}, state="pending"
    )
    db = FakeAsyncSession(tickets=[priv], proposals_list=[pr_priv])

    p_reporter = authz.Principal(kind="reporter", reporter_id=99)
    with pytest.raises(HTTPException) as exc1:
        await proposals.decide(ctx, db, p_reporter, pr_priv, False)
    assert exc1.value.status_code == 403

    p_other_user = _make_user(8, "reviewer")
    monkeypatch.setattr(proposals, "can_see", lambda p, t: False)
    with pytest.raises(HTTPException) as exc2:
        await proposals.decide(ctx, db, p_other_user, pr_priv, False)
    assert exc2.value.status_code == 404
    assert exc2.value.detail == "no such ticket"

    with pytest.raises(HTTPException) as exc3:
        await proposals.decide(ctx, db, p_other_user, pr_priv, True)
    assert exc3.value.status_code == 404

    monkeypatch.undo()
    pub = Ticket(id="XE-0005", kind="bounty", visibility="public", status="new")
    pr_draft = Proposal(
        id=32, ticket_id="XE-0005", field="reply_draft", value={"value": "Thanks!"}, state="pending"
    )
    db.tickets[pub.id] = pub
    db.proposals[pr_draft.id] = pr_draft

    monkeypatch.setitem(authz.MATRIX, "reply", (("reply_role",), ()))
    p_noreply = _make_user(9, "reviewer")
    with pytest.raises(HTTPException) as exc4:
        await proposals.decide(ctx, db, p_noreply, pr_draft, True, send_plain=False)
    assert exc4.value.status_code == 403
    assert exc4.value.detail == "user may not reply"


async def test_propose_xe_1054_invariants(config, monkeypatch):
    """propose() rejects unadoptable proposals on support, approved, and settled tickets."""
    ctx = FakeContext(config)
    db = FakeAsyncSession()
    p_tok = _make_token(10, "write:proposals")

    t_supp = Ticket(id="XS-0001", kind="support", visibility="public", status="new")
    with pytest.raises(HTTPException) as exc1:
        await proposals.propose(ctx, db, p_tok, t_supp, "award_xe", 50, "Reason over twenty characters")
    assert exc1.value.status_code == 400
    assert exc1.value.detail == "a support question carries no award"

    t_app = Ticket(
        id="XE-0006",
        kind="bounty",
        visibility="public",
        status="triaging",
        assessed_tier="high",
        award_xe=1000 * 1_000_000,
        award_approved_at=utcnow(),
    )
    with pytest.raises(HTTPException) as exc2:
        await proposals.propose(ctx, db, p_tok, t_app, "award_xe", 2000, "Reason over twenty characters")
    assert exc2.value.status_code == 409
    assert "the award is approved" in exc2.value.detail

    t_settled = Ticket(
        id="XE-0007",
        kind="bounty",
        visibility="public",
        status="awarded",
        assessed_tier="high",
        award_xe=1000 * 1_000_000,
    )
    with pytest.raises(HTTPException) as exc3:
        await proposals.propose(ctx, db, p_tok, t_settled, "award_xe", 2000, "Reason over twenty characters")
    assert exc3.value.status_code == 409
    assert exc3.value.detail == "the ticket is awarded; the award stands"

    pr_same = await proposals.propose(
        ctx, db, p_tok, t_settled, "award_xe", 1000, "Reason over twenty characters"
    )
    assert pr_same.value["value"] == 1000

    with pytest.raises(HTTPException) as exc_zero:
        await proposals.propose(
            ctx, db, p_tok, t_settled, "award_xe", 0, "Reason over twenty characters"
        )
    assert exc_zero.value.status_code == 409
    assert exc_zero.value.detail == "the ticket is awarded; the award stands"

    t_settled_zero = Ticket(
        id="XE-0007b",
        kind="bounty",
        visibility="public",
        status="awarded",
        assessed_tier="high",
        award_xe=0,
    )
    pr_zero_ok = await proposals.propose(
        ctx, db, p_tok, t_settled_zero, "award_xe", 0, "Reason over twenty characters"
    )
    assert pr_zero_ok.value["value"] == 0

    with pytest.raises(HTTPException) as exc4:
        await proposals.propose(
            ctx, db, p_tok, t_settled, "assessed_tier", "severe", "Reason over twenty characters"
        )
    assert exc4.value.status_code == 409
    assert exc4.value.detail == "the ticket is awarded; the tier behind the award stands"

    pr_tier_same = await proposals.propose(
        ctx, db, p_tok, t_settled, "assessed_tier", "high", "Reason over twenty characters"
    )
    assert pr_tier_same.value["value"] == "high"

    t_priv = Ticket(id="XE-0008", kind="bounty", visibility="private", status="new")
    monkeypatch.setattr(proposals, "PROPOSAL_FIELDS", proposals.PROPOSAL_FIELDS + ("visibility",))
    with pytest.raises(HTTPException) as exc5:
        await proposals.propose(
            ctx, db, p_tok, t_priv, "visibility", "public", "Reason over twenty characters"
        )
    assert exc5.value.status_code == 400
    assert exc5.value.detail == "use disclose to make a private ticket public"
