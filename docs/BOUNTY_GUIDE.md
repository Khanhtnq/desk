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
- `fixing`: a PR is open. `patched`: the fix is merged. The reporter must be told; this is where the outbox comes in.
- `disclosed`: a private report, now public because the fix shipped. Needs a linked patch ref; the desk opens the public GitHub issue itself with the reporter credited.
- `awarded`: a treasurer has approved an amount. The amount can be set from `accepted` on (agents propose it, a treasurer adopts); approval is allowed only once the ticket is `patched` or `disclosed`, and can be taken back until it is `awarded`. `paid`: it went out at mainnet launch, with a `paid_ref`.

**Thread.** Three kinds of writing, kept apart:

- **Notes** are internal: team and agents, never shown to reporters, never mirrored.
- **Proposals** are an agent's suggestions for a fact, a status or a reply draft, waiting for a person.
- **Replies** are public: to the GitHub issue, the Discord thread, or the ticket page and the reporter's email. Only a person sends one.

## 4. Priority: what the list shows you

`/` on the bounty host, signed in, is the queue. The default order is **severity**: assessed tier first, then claimed tier for those not yet assessed, then oldest first. Filters narrow it: status (`open` is everything not closed or paid), area, tier, gate, source, has PR, has internal ref, **pending** (has proposals waiting), and a text search across title, id, `#issue` and internal ref.

Two other views matter:

- **`/team/release`**: every `before` and `decide` ticket grouped by area, severity order inside each. This is the mainnet list. If it's on here, it blocks launch or needs a decision before launch.
- **`/team/outbox`**: every ticket whose status moved past triage but whose reporter hasn't been told since. Fixed-but-silent is the failure mode the programme had before the desk; this view exists so it can't happen quietly. Aim to keep it empty.

Priority, in words: a `before`-gated Critical or Severe beats everything; then `before` High; then anything in the outbox (a reply costs minutes and is owed); then `decide` tickets, which need a design call from whoever owns that area; then the rest of `before` by severity; `later` tickets are worked when the above is clear, Minor last.

## 5. How to work a ticket

**Reading a new ticket (reviewer)**

1. Open it. Read the report and any agent notes and proposals. Check the proposed duplicate, if any, against the earlier ticket.
2. Set status `triaging` (the list of pending proposals is where most of this is done in bulk; see §6).
3. Set what you can: area, verdict, gate, effort, internal ref if one exists. If it's a duplicate, set `duplicate_of` and close it with reason `duplicate`; use the `duplicate` reply template so the reporter knows which ticket carries it.
4. If it needs the reporter: `needs-info`, and reply with the `needs_info` template saying exactly what.
5. If it's real: `accepted`. If no internal ticket exists, anyone on the team makes one in `core` naming the report (`xe#63` in the title); the desk links it on the next poll. Reply with `accepted` so the reporter knows it's taken.
6. If it's not a bug: close with `invalid` / `out-of-scope` / `answered` and the matching template. Say why in a sentence; the reply is public and the next reporter reads it.

**Tier (the `tier` role)**

Set `assessed_tier` on accepted tickets. Adopting an agent's tier proposal also needs the `tier` role; a reviewer without it sees the proposal but can't adopt it. The role is separate from reviewer only because the tier is the money: give it to the people you want deciding awards, however many that is. The tier is what the award follows, so it's set with the fix in view, not from the report alone.

**When the fix lands (anyone)**

Link the PR on the ticket (`#27`, `dao#1`, or a full `owner/repo#5`). Status to `fixing` when the PR opens, `patched` when it merges; the internal tracker closing moves it to `patched` by itself. The ticket now sits in the outbox until someone replies. Use the `patched` template: it names the PR and tells the reporter what happens next.

**Private reports**

Read them on the desk only; the body and attachments come out of the vault for you and the log records each opening. Never paste a private report into GitHub, Discord or an internal ticket body. When the fix has shipped and a patch ref is linked, mark `disclosed`: the desk opens the public issue with the reporter credited and the thread continues there.

**Awards (treasurers)**

On a `patched` or `disclosed` ticket with an assessed tier, set the amount in XE and approve. The desk refuses more than twice the tier's ceiling without a note explaining it. Status `awarded`. Awards are paid at mainnet launch to the address the reporter bound on `/account` by signing with its key; the desk never takes an address from a GitHub comment. `/v1/team/payouts.csv` is the payment list: only approved awards with bound addresses appear, so chase reporters without one (the ticket page shows it). After payment, status `paid` with the transaction as `paid_ref`.

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
2. `GET /v1/tickets?status=open&sort=severity` (or `status=new` for the fresh ones).
3. For each: `GET /v1/tickets/{id}` and `/thread`, `/patch-refs`, `/notes` and `/proposals` to see what's already been said.
4. Read the code. Reproduce if it can.
5. `POST /v1/tickets/{id}/notes` with its reading: what the report claims, what the code does, whether it reproduces, what it would take to fix.
6. `POST /v1/tickets/{id}/proposals/bulk` with up to twelve proposals, each with a `reason`. A repeat proposal on the same field from the same token supersedes the earlier one, so it can revise.
7. `POST /v1/tickets/{id}/patch-refs` if it finds a PR that addresses it.

**Adopting.** On the ticket page each pending proposal has adopt and reject. On the list, filter **pending** and work down; `/v1/team/proposals/bulk` does many at once. Adopting a `status` proposal applies the status along the normal rules; adopting a `reply_draft` puts the text in the reply editor for you to edit and send, it never sends itself. Reject with a word of reason: the agent's owner sees the rejections and that's how the prompt improves.

What agents are good at here: duplicates (they've read all 90), mapping a report to the area of the tree it touches, spotting a PR that already fixes it, drafting the first reply. What they're not trusted with: the tier, because that's the money, and the word to the reporter, because that's the programme's voice.

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
