"""The agent brief: what a model holding a desk token is for, and how it works a ticket.

Served as markdown at `/v1/agent/brief.md` (JSON at `/v1/agent/brief`, a page at `/agent`), listed in
`/llms.txt` and the manifest. Built from the same config the desk runs on, so the vocabularies an agent must
send are the ones the desk accepts, and the config hash at the foot tells a runner when the brief changed.
Anything a token's owner wants their own agent to do differently goes in the token's standing instructions,
which `GET /v1/me` returns; this document is the part that is the same for everyone."""

from __future__ import annotations

from .config import Config
from .models import PROPOSAL_FIELDS, AgentToken
from .services.tickets import TRANSITIONS

GATE_NOTES = {
    "before": "the fix lands before mainnet",
    "decide": "a product decision still to be made",
    "later": "can follow launch",
}


def _table(rows: list[tuple[str, str, str]]) -> list[str]:
    out = ["| send | shown as | means |", "|---|---|---|"]
    out += [f"| `{k}` | {label} | {note} |" for k, label, note in rows]
    return out


def _p(*parts: str) -> str:
    """A paragraph from pieces, so the source stays within the line limit."""
    return " ".join(parts)


def build_agent_brief(
    cfg: Config, base_url: str, network_id: str, *, token: AgentToken | None = None, owner: str = ""
) -> str:
    b = base_url.rstrip("/")
    tier_defs = (cfg.copy_programme or {}).get("tier_definitions") or {}
    tracker = (cfg.programme.get("internal_tracker_name") or "internal").strip()
    fields = ", ".join(f"`{f}`" for f in PROPOSAL_FIELDS)
    L: list[str] = []
    add = L.append

    add("# Working the XE desk as an agent")
    add("")
    add(
        _p(
            "> You read and recommend. A person decides and speaks. Nothing you write reaches a",
            "reporter,",
            "sets a fact, changes a status or moves money; it waits on the ticket for a human to adopt or",
            f"reject. Desk `{b}`, network `{network_id}`.",
        )
    )
    add("")

    if token is not None:
        label = f", label `{token.label}`" if token.label else ""
        scopes = ", ".join(f"`{s}`" for s in token.scopes)
        add("## Your token")
        add("")
        add(
            _p(
                f"Model `{token.model_id}`{label}, owned by {owner or 'a team member'}. Scopes: {scopes}.",
                "Everything you write is recorded against the token and its owner; the owner answers",
            "for it.",
            )
        )
        if token.instructions:
            add("")
            add("Standing instructions from your owner; they take precedence over the guidance below:")
            add("")
            for ln in token.instructions.strip().splitlines():
                add(f"> {ln}" if ln.strip() else ">")
        add("")

    add("## The loop")
    add("")
    add("Authenticate every call with `Authorization: Bearer desk_...`. Then:")
    add("")
    add(
        _p(
            f"1. `GET {b}/v1/tickets?kind=bounty&status=open&sort=severity` for the queue, most",
            "severe first;",
            "`status=new` for what nobody has read yet; `pending=true` for tickets that already have",
            "proposals waiting. `kind=support` for the support door.",
        )
    )
    add(
        _p(
            f"2. For each ticket: `GET {b}/v1/tickets/{{id}}` (facts), `/thread` (the public thread),",
            "`/patch-refs`, `/notes` and `/proposals` (what agents and people have already said). Read these",
            "before writing, and do not repeat a note that is already there.",
        )
    )
    add(
        _p(
            "3. Read the code the report points at. Reproduce if you can. Check the tracker for a ticket",
            "that already covers it.",
        )
    )
    add(
        _p(
            f"4. `POST {b}/v1/tickets/{{id}}/notes` with your reading (below). One note per pass; if a later",
            "pass changes your mind, say what changed and why.",
        )
    )
    add(
        _p(
            f"5. `POST {b}/v1/tickets/{{id}}/proposals/bulk` with up to twelve `{{field, value, reason}}`",
            "items. A new proposal on a field you already proposed supersedes your earlier one, so revise",
            "freely.",
        )
    )
    add(
        _p(
            f"6. `POST {b}/v1/tickets/{{id}}/patch-refs` with `{{ref}}` (`#27`, `dao#1`, `owner/repo#5`)",
            "when a PR or commit addresses it.",
        )
    )
    add(f"7. `GET {b}/v1/me` tells you who you are, your scopes, and your owner's standing instructions.")
    add("")
    add(
        _p(
            "Scopes: `read:public` and `read:private` are what you may read (a private ticket's body is",
            "sealed without the second); `write:notes`, `write:proposals`, `write:patch-refs` are the three",
            "things you may write. There is no scope that replies, sets a status, a tier or an award, or",
            "reads a payout address.",
        )
    )
    add("")

    add("## A good note")
    add("")
    add("Markdown, short, and about the code, not about yourself. In this order:")
    add("")
    add("- **Claim.** What the report says happens, in one sentence.")
    add(
        _p(
            "- **Code.** What the code actually does, with file paths and function names; quote the line",
            "that matters.",
        )
    )
    add("- **Reproduced?** Yes, no, or not tried, and how.")
    add("- **Impact.** Who can do what, under which conditions; what it is bounded by.")
    add(f"- **Already known?** The duplicate on the desk, or the {tracker} ticket, if one exists.")
    add("- **Fix.** What it would take, in a sentence; a PR if there is one.")
    add("")
    add(
        _p(
            "Leave out: greetings, restating the title, speculation presented as finding, anything addressed",
            "to the reporter. Notes never leave the desk, but they are read by people in a hurry.",
        )
    )
    add("")

    add("## Suggesting an award")
    add("")
    add(
        _p(
            "A person sets the award; your job is to make that decision easy. Once the verdict is `valid` or",
            "`likely-valid` and a tier is set or you are proposing one, do two things. Propose `award_xe`: a",
            "whole number of XE inside the assessed band, with a reason of one or two sentences about the",
            "report (adopting it sets the amount; a treasurer approves separately). And end your note with",
            "one line:",
        )
    )
    add("")
    add("> **Award:** 2,000 XE (Medium, ceiling 2,500). Top of the band: precise, right fix suggested.")
    add("")
    add("The amount, the tier and its ceiling, where in the band, and why in a clause. What moves it:")
    add("")
    add(
        _p(
            "- **Up**: the report gives the full picture and the right fix, so the team has nothing to add;",
            "a live reproduction; impact stated honestly, including what it is bounded by.",
        )
    )
    add(
        _p(
            "- **Down**: the team had to find half of the consequence; the fix suggested is wrong; the report",
            "stops at the symptom.",
        )
    )
    add(
        _p(
            "- **Over-claiming a tier** costs the top of the band it lands in, never a drop below the midpoint;",
            "the finding is paid on what it is.",
        )
    )
    add(
        _p(
            "- **Duplicates** pay once, to the first verifiable report; later patches and comments do not",
            "change who is paid.",
        )
    )
    add("")
    add(
        _p(
            "One recommendation per ticket per pass; if you revise it, say what changed. If the thread",
            "carries a payout address that differs from the one in the report body, say so in the note: the",
            "report is the submission and its address is the one that counts. The amount is for the note",
            "and nowhere else; it never appears in a reply draft or a public thread.",
        )
    )
    add("")

    add("## Proposals")
    add("")
    add(
        _p(
            f"Fields: {fields}. Every proposal carries a `reason`; one without is rejected on sight.",
            "Send the key in the first column, never the label.",
        )
    )
    add("")
    add("### `assessed_tier`")
    add("")
    add(
        _p(
            "A person with the tier role adopts or rejects; the money follows this field, so argue it.",
            "Ceilings are the programme's targets in XE.",
        )
    )
    add("")
    L += _table(
        [
            (k, cfg.tier_label(k), f"≤ {cfg.ceiling_micro(k) // 1_000_000:,} XE. {tier_defs.get(k, '')}")
            for k in cfg.tier_order
        ]
    )
    add("")
    add("### `verdict`")
    add("")
    L += _table([(k, v, "") for k, v in cfg.verdicts.items()])
    add("")
    add("### `mainnet_gate`")
    add("")
    L += _table([(k, v, GATE_NOTES.get(k, "")) for k, v in cfg.gates.items()])
    add("")
    add("### `effort_eng`")
    add("")
    add("An engineer's clock; the desk derives the agent clock from it.")
    add("")
    bands = cfg.effort_bands.items()
    L += _table([(k, v.get("engineer", k), f"agent {v.get('agent', '')}") for k, v in bands])
    add("")
    add("### `area` (bounty) and topic (support)")
    add("")
    L += _table([(k, v, "bounty") for k, v in cfg.areas.items()])
    L += [f"| `{k}` | {v} | support |" for k, v in cfg.topics.items()]
    add("")
    add("### `duplicate_of`, `internal_ref`")
    add("")
    add(
        _p(
            f"`duplicate_of` is a desk id (`XE-0042`). `internal_ref` is the {tracker} ticket that",
            "tracks the fix, as `#1068` or `repo#10`. The desk links to the tracker and never writes to it.",
        )
    )
    add("")
    add("### `status`")
    add("")
    add(
        _p(
            'A string, or `{"status": "closed", "closed_reason": "duplicate"}`. The target may be several',
            "hops away: on adoption the desk walks the shortest allowed path from the ticket's current",
            "status, one logged hop at a time, never passing through `closed`, `awarded` or `paid`. The",
            "moves are:",
        )
    )
    add("")
    for kind, table in TRANSITIONS.items():
        moves = "; ".join(
            f"`{a}` → {', '.join(f'`{x}`' for x in sorted(bs))}" for a, bs in table.items() if bs
        )
        add(f"- {kind}: {moves}")
    add("")
    add("### `reply_draft`")
    add("")
    add(
        _p(
            "A string: the words a person might send to the reporter. Adopting it only puts the text in",
            "their editor; they edit and send. Write in the programme's voice: plain, specific, no promise",
            "of an award, no tier named unless it has been set, nothing about other reports. On a private",
            "ticket say the fact, not the detail.",
        )
    )
    add("")
    add("### `award_xe`")
    add("")
    add(
        _p(
            "A whole number of XE, never more than twice the assessed tier's ceiling, with a reason of at",
            "least 20 characters that says where in the band and why (see Suggesting an award). Only a",
            "treasurer can adopt it, and adopting sets the amount without approving it; approval comes once",
            "the ticket is patched or disclosed. A new proposal",
            "supersedes your earlier one. The amount belongs here and in your note, nowhere public.",
        )
    )
    add("")

    add("## When you are rejected")
    add("")
    add(
        _p(
            f"`GET {b}/v1/tickets/{{id}}/proposals` shows every proposal with its `state` (`pending`,",
            "`adopted`, `rejected`, `superseded`) and who decided. A rejection is information: do not",
            "re-propose the same value with the same reason. If you still believe it, write a note that says",
            "what the reviewer may have missed, and propose again with that reason.",
        )
    )
    add("")

    add("## Rules that are not negotiable")
    add("")
    add("- Never address the reporter. Notes are internal; the reply draft is for a person to send.")
    add("- Never promise or imply an award, a tier, or a timeline.")
    add(
        _p(
            "- A private report's body, attachments and payout details stay on the desk. Do not paste them",
            "into a public thread, a PR, a commit message or an external tool.",
        )
    )
    add("- Do not propose on a ticket you have not read in full, including its existing notes.")
    add(
        _p(
            "- If the report is a support question wearing a bounty's clothes, propose `verdict: support`",
            "and say so; do not grade it.",
        )
    )
    add("")

    add("## Where things are")
    add("")
    add(f"- `GET {b}/v1`: the manifest, every endpoint, the config hashes.")
    add(f"- `{b}/v1/openapi.json`: the schema.")
    add(f"- `{b}/llms.txt`: the reading list. Every page is also markdown with `.md` appended.")
    add(f"- `{b}/scope.md`: the programme's own words on tiers and scope.")
    add(f"- `{b}/v1/export/triage.md`: the whole desk as triage tables, for a wide read.")
    add("")
    cfg_h = cfg.hashes.get("desk.yaml", "")[:12]
    copy_h = cfg.hashes.get("copy/programme.yaml", "")[:12]
    add(f"Brief version: config `{cfg_h}`, copy `{copy_h}`.")
    add("")
    return "\n".join(L)
