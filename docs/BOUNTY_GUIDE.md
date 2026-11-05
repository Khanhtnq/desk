# Working the bounty: a guide for the team

*How the XE bug bounty runs on the desk at `bounty.xe.network`. Written for reviewers, the tier holders, the treasurers and anyone running an agent against it. The design is [`DESK_BRIEF.md`](DESK_BRIEF.md); this is the working version.*

## 1. The one rule

**An agent recommends; a human decides and speaks.** The desk enforces it: no agent token can send a reply, set a status or tier, or touch an award. Agents read, write internal notes, and propose. People adopt, rule, reply and pay. Every action by either is in a signed, hash-chained log that anyone can verify at `/log`.

## 2. Where tickets come from

Every report is a ticket with an id like `XE-0045`. It has one of four sources, and the source decides how the thread is carried.

| Source | How it arrives | Where the conversation lives |
|---|---|---|
| **GitHub** | Issues on `xeprotocol/xe`, `xeprotocol/dao`, `xeprotocol/sdk`. The worker polls every two minutes and a webhook brings new issues at once. Comments are imported; the issue author becomes the reporter. | The GitHub issue. A desk reply is posted there as a comment by the bot account; the desk's status is a label on the issue. Closing on the desk closes the issue. |
| **Desk (web)** | `/report` on the bounty host. The reporter signs in (GitHub, or a key of their own), fills the form, attaches files. **Private by default**; Critical and Severe are private whatever the box says. | The ticket page. Private tickets are sealed in the vault with their attachments and readable only by the team and the reporter. A reply is mailed to the reporter when they have a confirmed email. |
| **Email** | The three pre-desk reports (`E1`–`E3`), imported from the triage. Historical; `security@` is retired as a reporting path. | The ticket page. |
| **Discord** | A support question that turns out to be a bug: `/bounty` in the thread converts it. | The Discord thread, until converted; then the ticket page. |

Imported history: the 90 rows of the triage document (`BOUNTY_TRIAGE.md`, kept outside the repo because it carries the private email reports) were applied on 29 October. Those tickets already carry a verdict, tier, gate, effort, area and internal ref, plus the triage reasoning as notes under the `triage import` agent token. They are the baseline; everything from here is incremental.

The engineering tracker, `xeprotocol/core`, is read, never written. When an internal ticket names a public report (`xe#63` in its title or body), the desk links it as `internal_ref` and follows its state: open → the report is `accepted`; closed as completed → `patched` and into the outbox; closed as not planned → a note for a human to rule on.

Pull requests in the public repos are watched too (poll every two minutes, webhook live). A PR whose title or body references an issue is linked to that issue's ticket under Patches, with its state kept current. A PR that says it *fixes* the issue (`fixes #27`, `closes #27`, `resolves #27`) also moves the ticket: `fixing` when it opens, `patched` when it merges, and back to where it was if it is closed unmerged and no other PR is open against the ticket. The opening hop is taken only for a maintainer's PR (GitHub says the author is an owner, member or collaborator, or it is the desk's bot account); anyone can open a fork PR against a public repo with `fixes #27` in it, so a stranger's PR is linked under Patches with its author shown and moves nothing until someone merges it. A bare `#27` mention links but moves nothing, since it usually means "related to". Nothing on GitHub moves a ticket past `patched`; disclosure, award and payment are people's decisions. Both paths walk the allowed transitions one hop at a time, so a `new` ticket whose fix merges reads `triaging → accepted → patched` in the log, each hop `via: github:xe#31` or `via: internal`.

Two things GitHub cannot do. Edits to an issue's title or body flow into the ticket only while it is `new`, `triaging` or `needs-info`; from `accepted` on, the desk's copy is what was assessed and stays as it was (each edit that does land is a `ticket.edited` event). And the **team** badge on a thread message comes from the author being the desk's bot account, nothing else; the `<!-- xe-desk -->` footer on mirrored replies is a public string and vouches for nobody.

## 3. The ticket

**Facts** a reviewer sets, or adopts from an agent's proposal:

- `area`: consensus, p2p-sync, node-api, leasing-ledger, dao-harness, sdk-docs-web, ops-testnet, other.
- `claimed_tier`: what the reporter said. Parsed from the issue where it says "Severity: High"; otherwise set by hand.
- `assessed_tier`: what we say. **Only the `tier` role sets this**; any team member can hold it, and it is granted on `/team/users`. Critical 50k, Severe 25k, High 10k, Medium 2.5k, Minor 650 XE ceilings; `none` for notices.
- `verdict`: valid, likely-valid, design-gap, duplicate, notice, support, invalid, out-of-scope.
- `duplicate_of`: the earlier ticket. Duplicates close with that reason; the award goes to the first.
- `mainnet_gate`: **before** (must be fixed before mainnet), **decide** (a design call to make before mainnet), **later** (can follow launch). This is the priority axis after severity.
- `effort_eng`: the engineer's clock, `<1h` to `1-2w`, or `design`. The agent clock is derived from it.
- `internal_ref`: the `core` ticket (`#1068`) or `faucet#10`.
- `assignee`, `visibility`.

**Who sees the facts.** The team and its agents see all of them at every stage. Everyone else sees the ticket, its status, its thread and the reporter's claimed tier from the start, and the assessment (`assessed_tier`, `verdict`, `internal_ref`) only once the ticket is past `fixing`: a confirmed, unfixed bug with the team's tier on it is a ranked entry on a list of what still works against the network, and the desk does not publish that list. `mainnet_gate`, `effort_eng` and the assignee are planning data and are never public; nor are the free-text reasons on fact and status changes, or the values agents proposed, which the public log shows with those parts held back (the hash still covers the stored row). Public filters and sorting follow the same rule, so filtering open tickets by tier matches the claimed tier, not the assessment. `/v1/export/triage.md` is team and agents only. The `accepted` reply therefore does not name the tier; the reporter learns it with the award.

**Status** moves along a fixed path. The desk refuses anything else.

```
new → triaging → accepted → fixing → patched → awarded → paid
         ↓           ↑                   ↓
     needs-info  ───┘               disclosed (private tickets only) → awarded
         ↓
       closed (duplicate | invalid | out-of-scope | withdrawn | answered | stale) → triaging to reopen
```

- `new`: nobody has read it. `triaging`: someone has.
- `needs-info`: we asked the reporter for something; the clock is theirs.
- `accepted`: it's real and will be fixed; there is (or should be) an internal ticket.
- `fixing`: a PR is open. `patched`: the fix is merged. Both are set by GitHub when the PR says `fixes #n` (§2); by hand otherwise. The reporter must be told; this is where the outbox comes in.
- `disclosed`: a private report, now public because the fix shipped. Needs a linked patch ref; the desk opens the public GitHub issue itself with the reporter credited.
- `awarded`: a treasurer has approved an amount *and* the ticket has been moved to say so. The amount can be set from `accepted` on (agents propose it, a treasurer adopts); approval is allowed only once the ticket is `patched` or `disclosed`, and can be taken back until it is `awarded`. Approval alone does not change the status: `awarded` is the public step (it puts the reporter on the leaderboard), and a private report has to be disclosed first. `/team/awards` lists approved awards whose ticket has not caught up, with a one-click move where nothing else is needed. `paid`: it went out at mainnet launch, with a `paid_ref`.

**Thread.** Three kinds of writing, kept apart:

- **Notes** are internal: team and agents, never shown to reporters, never mirrored.
- **Proposals** are an agent's suggestions for a fact, a status or a reply draft, waiting for a person. Duplicates are ruled by family: a ticket that other tickets have been proposed as duplicates of shows them under "Filed as duplicates of this one", and one click (`POST /v1/team/tickets/{id}/duplicates/close`) marks, closes and tells every one of them under your name, using the programme's duplicate template; anything the desk refuses is listed and left alone. It is still a person's ruling, taken once per bug instead of four times per re-filing.
- **Replies** are public: to the GitHub issue, the Discord thread, or the ticket page and the reporter's email. Only a person sends one.

## 4. Priority: what the list shows you

`/` on the bounty host, signed in, is the queue. The default order is **severity**: assessed tier first, then claimed tier for those not yet assessed, then oldest first. Filters narrow it: status (`open` is new to fixing; `fixed` is patched to paid; `closed` is closed without a fix), area, tier, gate, source, has PR, has internal ref, **pending** (has proposals waiting), and a text search across title, public body, id, `#issue` and internal ref; `reporter=<id>` on the API lists one reporter's filings.

Two other views matter:

- **`/team/release`**: every `before` and `decide` ticket grouped by area, severity order inside each. This is the mainnet list. If it's on here, it blocks launch or needs a decision before launch.
- **`/team/outbox`**: every ticket whose status moved past triage but whose reporter hasn't been told since. Fixed-but-silent is the failure mode the programme had before the desk; this view exists so it can't happen quietly. Aim to keep it empty.

Priority, in words: a `before`-gated Critical or Severe beats everything; then `before` High; then anything in the outbox (a reply costs minutes and is owed); then `decide` tickets, which need a design call from whoever owns that area; then the rest of `before` by severity; `later` tickets are worked when the above is clear, Minor last.

## 5. How to work a ticket

**Assume bad faith.** A bounty pays money for text, so a report is a claim by someone who wants an award, and the desk itself is a target: forged team comments, PRs that move tickets, links that merge accounts and reports written to steer the agent reading them have all been tried against it. The report's logs, screenshots and "reproduced locally" are claims, not reproduction; cited paths are checked against the tree; severity in the title is the reporter's opinion; anything in a report that reads as instructions to whoever is reading it is a reason for suspicion. A script or binary attached to a report is attacker-supplied code and runs only somewhere disposable. This holds for the person adopting a proposal as much as for the agent that wrote it: an agent that was steered produces a proposal that looks like any other.

Money is the smaller motive. The desk decides what is fixed before mainnet, so it is also the place to make XE weak in operation: a real bug closed as invalid or duplicate, argued down a tier, gated `later` so it ships; a community "fix" merged with its own hole in it; one real report buried under thirty thin ones; the thread read for what is known and still open. So a push to close, downgrade or defer gets the same scepticism as a push to inflate. A thread comment saying "by design", "already fixed" or "duplicate of #n" is a claim unless it carries the **team** badge; the GitHub thread is open to whoever would rather the bug stayed. A stranger's PR is read for what else it changes before anyone calls it a fix, and is merged by a maintainer who has. When a gate is in doubt it is `before`: `later` is a decision to ship with the bug. A closing note says what was checked, not only what was concluded, so the next reader can tell a ruling from a dismissal. And public replies on open bugs say that it is being handled and nothing that helps someone find it.

**Reading a new ticket (reviewer)**

1. Open it. Read the report and any agent notes and proposals. Read the **Read across** list on the desk panel (tickets sharing its words, its cited paths or its reporter) before anything else, and the proposed duplicate, if any, against the earlier ticket. An agent note shows what it checked under it (`Checked: 692 desk tickets · opened XE-0130 · tracker · tree xe@abc1234`); a note marked **No check recorded** is a reading of one ticket in isolation and is weighed as such.
2. Set status `triaging` (the list of pending proposals is where most of this is done in bulk; see §6).
3. Set what you can: area, verdict, gate, effort, internal ref if one exists. If it's a duplicate, set `duplicate_of` and close it with reason `duplicate`; use the `duplicate` reply template so the reporter knows which ticket carries it.
4. If it needs the reporter: `needs-info`, and reply with the `needs_info` template saying exactly what.
5. If it's real: `accepted`. If no internal ticket exists, anyone on the team makes one in `core` naming the report (`xe#63` in the title); the desk links it on the next poll. Reply with `accepted` so the reporter knows it's taken.
6. If it's not a bug: close with `invalid` / `out-of-scope` / `answered` and the matching template. Say why in a sentence; the reply is public and the next reporter reads it.

**Tier (the `tier` role)**

Set `assessed_tier` on accepted tickets. Adopting an agent's tier proposal also needs the `tier` role; a reviewer without it sees the proposal but can't adopt it. The role is separate from reviewer only because the tier is the money: give it to the people you want deciding awards, however many that is. The tier is what the award follows, so it's set with the fix in view, not from the report alone.

**When the fix lands (anyone)**

Write `fixes #27` in the PR description and the desk does the rest: the PR is linked, the ticket goes to `fixing` when the PR opens and `patched` when it merges (§2). If the PR cannot say so (a commit, a repo the desk does not watch, a ticket that came in by email or Discord and has no issue), link it on the ticket by hand (`#27`, `dao#1`, `owner/repo#5`) and set the status yourself. Either way the ticket now sits in the outbox until someone replies. Use the `patched` template: it names the PR and tells the reporter what happens next.

**Private reports**

Read them on the desk only; the body and attachments come out of the vault for you and the log records each opening. Never paste a private report into GitHub, Discord or an internal ticket body. When the fix has shipped and a patch ref is linked, mark `disclosed`: the desk opens the public issue with the reporter credited and the thread continues there.

**Awards (treasurers)**

On a `patched` or `disclosed` ticket with an assessed tier, set the amount in XE and approve. The desk refuses more than twice the tier's ceiling without a note explaining it. Status `awarded`.

**How much.** The ceiling is the most a report in its tier can earn, not the going rate. An award is one of the steps in `config/desk.yaml` (`award_steps`: top 50%, standard 35%, reduced 20%, minimal 10% of the ceiling, rounded down to the tier's grain; desk findings in area `other` take a quarter of the step). Top is measured on the live network with the shipped fix being the one the report gave; standard is a confirmed first filing the team still had to fix; reduced is an over-claimed tier, a root cause or consequence the team found, a symptom already written down, or a fix shared with another award; minimal is known internally before filing, latent code, a design gap or a symptom-only report. Agents propose on the same steps and their reason names the step; adopt the step, not a number, and put the step and its one-sentence reason in the award note so the reporter reads a rule. Duplicates pay nothing; the first verifiable report is paid. Changing the shares is a pull request against `config/desk.yaml`, like any other policy change. Awards are paid at mainnet launch to the address the reporter bound on `/account` by signing with its key; the desk never takes an address from a GitHub comment. `/v1/team/payouts.csv` is the payment list: only approved awards with bound addresses appear, so chase reporters without one (the ticket page shows it). After payment, status `paid` with the transaction as `paid_ref`.

## 6. Agents

Agents do the reading. A new ticket arrives, an agent reads it against the tree, and within minutes there's a note with its reading and a set of proposals: tier, verdict, duplicate, gate, effort, the internal ticket if one already covers it, any community PR that looks relevant, and a reply draft. The reviewer's job becomes adopt-or-reject, in bulk, from the list view filtered to **pending**.

**Where an agent gets its direction.** The desk serves a brief at `/v1/agent/brief.md` (readable at `/agent`): the role, the loop below, every vocabulary it may send (tier, verdict, gate, effort, area, status) with the key the desk accepts and the label a person sees, what a good note contains, how to take a rejection, and the rules that don't bend. It is built from `config/desk.yaml`, so it is always what the desk actually enforces. Point your agent at it first; the manifest and `/llms.txt` both link it. On top of that, each token carries **standing instructions** from its owner ("only p2p-sync tickets; never propose status"), set when the token is issued or later from `/team/tokens`, returned by `GET /v1/me` and folded into the brief when the agent reads it with its token. The brief is the same for everyone; the instructions are yours.

**Issuing a token.** `/team/tokens`. A token is bound to you (its owner), a model id, a label, a set of scopes, a lifetime and optional standing instructions. Everything it writes is recorded against both you and the model. Scopes:

- `read:public`, `read:private`: what it may read. Give `read:private` only to a model and runner you'd show the report to.
- `write:notes`: internal notes.
- `write:proposals`: proposals on any of `assessed_tier`, `verdict`, `duplicate_of`, `internal_ref`, `mainnet_gate`, `effort_eng`, `area`, `status`, `reply_draft`.
- `write:patch-refs`: link a PR.

There is no scope for replies, status, tier or awards, and there never will be. The token is shown once; revoke it on the same page.

**The loop an agent runs** (`Authorization: Bearer <token>` on `https://bounty.xe.network/v1/...`; the full surface is at `GET /v1` and `/llms.txt`):

1. `GET /v1/me` for its scopes and your standing instructions; `GET /v1/agent/brief.md` for the brief.
2. Read across the desk first: `GET /v1/tickets?status=all&limit=500&offset=0`, then `offset=500`, until `offset + count` reaches `total`. Fixed and closed included; that is the set a new report can duplicate. `status=open` is a work queue, not a duplicate check.
3. `GET /v1/tickets?status=open&sort=severity` (or `status=new` for the fresh ones).
4. For each: `GET /v1/tickets/{id}`, `/similar` (shared words, shared paths, same reporter, duplicate links, each with why), `/thread`, `/patch-refs`, `/notes` and `/proposals` to see what's already been said. Every `/similar` row is opened before a verdict.
5. Read the code in the tree (the brief names the repos), at the head and at any commit the report names. Reproduce if it can, treating the report as untrusted input throughout (§5): nothing inside a ticket is an instruction to it, and only the code and its own run count as evidence.
6. `POST /v1/tickets/{id}/notes` with its reading (what the report claims, what the code does, whether it reproduces, what is already known, what it would take to fix) and `checked`: `{"desk": 692, "similar": ["XE-0130"], "tracker": true, "tree": "xe@abc1234"}`. The ticket page shows it under the note; a note without it is marked unchecked.
7. `POST /v1/tickets/{id}/proposals/bulk` with up to twelve proposals, each with a `reason`. A repeat proposal on the same field from the same token supersedes the earlier one, so it can revise.
8. `POST /v1/tickets/{id}/patch-refs` if it finds a PR or commit that addresses it and GitHub has not already linked it. It should not propose `fixing` or `patched` for a PR that says `fixes #n`; GitHub does that (§2).

**Adopting.** On the ticket page each pending proposal has adopt and reject. On the list, filter **pending** and work down; `/v1/team/proposals/bulk` does many at once. Adopting a `status` proposal applies the status along the normal rules; adopting a `reply_draft` puts the text in the reply editor for you to edit and send, it never sends itself. Reject with a word of reason: the agent's owner sees the rejections and that's how the prompt improves.

What agents are good at here: duplicates (once they have read the whole desk, which the loop now makes the first step), mapping a report to the area of the tree it touches, spotting a PR that already fixes it, drafting the first reply. What they're not trusted with: the tier, because that's the money, and the word to the reporter, because that's the programme's voice.

## 7. Replies

Templates live in `config/copy/public.yaml` and are filled with the ticket's facts: `patched`, `duplicate`, `accepted`, `needs_info`, `invalid`, `notice`. Pick one on the ticket page, edit, send. Tone: plain, specific, short, the reporter's name on it. A reply is the public record of how XE treats people who report bugs; it is read by the next hundred reporters.

Where it goes: GitHub-sourced tickets get a comment on the issue (the worker posts it within a minute; the mirror state shows on the ticket); desk tickets get it on the page and by email where the reporter has one; private tickets get the fact and a link by email, never the text.

## 8. GitHub, labels and the webhook

The desk owns the status labels on the three repos: `triaged`, `needs-repro`, `accepted`, `fixing`, `patched`, `disclosed`, `awarded`, `paid`, and the closed reasons. Anything else on an issue is removed on first touch; the desk's labels are the only labels. Don't set them by hand on GitHub; set the status on the desk and the worker's `push` job (every minute) does the rest, including closing issues the desk closed and reopening ones the desk reopened.

An issue closed on GitHub by someone before the desk ruled is left open on the desk with a `github.closed_externally` event, so it isn't lost; rule on it.

## 9. Every day

- Someone owns the queue each day. Morning: `/team/outbox` to zero, then `new` tickets to `triaging` with proposals adopted or rejected, then anything `needs-info` older than two weeks closed `stale` with the `needs_info` reply left as the last word.
- Whoever holds `tier` rules on anything `accepted` without one, weekly at least.
- Treasurers approve awards as tickets reach `patched`/`disclosed`, not in a batch at mainnet launch.
- `/live` is the event stream; `/log` is the ledger. The worker writes a daily note with the counts, so the log reads as a diary.
- Policy (tiers, ceilings, areas, templates, scope text) is `config/desk.yaml` and `config/copy/*.yaml`, changed by pull request, hashed and published at `GET /v1`. Nobody edits policy from a screen.

## 10. Where things are

| | |
|---|---|
| Queue | `https://bounty.xe.network/` (signed in) |
| Mainnet list | `/team/release` |
| Owed replies | `/team/outbox` |
| Agent tokens | `/team/tokens` |
| Users and roles | `/team/users` (admin) |
| Payout list | `/v1/team/payouts.csv` (treasurer) |
| Public API and manifest | `GET /v1`, `/llms.txt`, `/index.md` |
| Agent brief | `/agent`, `/v1/agent/brief.md` |
| Event log | `/log`, `/live`, `GET /v1/log/verify` |
| Support door | `https://support.xe.network/` and the Discord bot; `/bounty` in a thread converts a question into a report |
| Deployment | [`DEPLOY.md`](DEPLOY.md) |
