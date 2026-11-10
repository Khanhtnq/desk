# XE Desk, Brief

Working brief for a ticketed bug bounty and community support tool for XE. Version 0.3, 28 October 2026. Draft for Joseph, Will and Adam. 0.2 added the internal engineering ticket to the data model and the import, following the engineering pass over the triage; 0.3 applies the XE project stack and principles from `xeprotocol/dao`.

It fixes scope, the data model, the roles, the integrations and the sequencing. It is not the bounty rules; those stay on [test.network/bounty](https://test.network/bounty) and the tool enforces them rather than restating them.

---

## 1. Why

The bounty programme runs on public GitHub issues and a shared mailbox. As of 28 October there are 87 open issues, 36 open PRs, no labels, no maintainer replies, three Severe reports that went public because `security@` bounced, two accounts posting payout wallets into other people's threads, and a leaderboard that updates when the website is redeployed. The triage of all of it is in `BOUNTY_TRIAGE.md` (kept outside the repo: it carries the private email reports), and it lives in a markdown file because there is nowhere else to put it.

The engineering side already works the other way round. The engineering pass on 28 October put an internal ticket against every actionable report (`#1047`–`#1103` opened for it, nine existing ones linked), re-tiered five, marked two partial and ten fixed or closed. None of that reaches GitHub: eleven issues that are fixed or closed internally are still open there with no reply. The gap the desk closes is between the internal tracker, where the work happens, and the public thread, where the reporter is waiting.

Adam's ask, which this brief adopts as the shape of the thing:

> see a list of bug reports in severity order, and give my agent an API to it so it can read and update, but for the updates from my agent to be internal notes. Almost like support tickets. I do the internal work and the internal notes, then a human reviews, does the public response and marks status. Could even become a public portal, with a backend login, so people can manage their reports, and even have the wallet generation in it.

Plus Joseph's: the same system should take general project support from Discord and Telegram, with a web front too, so there is one queue and one dashboard.

One line: **a ticket desk where agents do the work in private, humans speak in public, and reporters can see their own case.**

## 2. What it is

One application, two front doors, one backend.

- **Bounty portal.** Reporters file findings (public or private), manage them, generate a payout wallet, and watch the leaderboard. The core team triages, estimates, decides, patches, discloses and pays, with an audit trail.
- **Support desk.** Community questions arrive from Discord, Telegram and a web form, become tickets in the same queue, and are answered where they came from.
- **Agent API.** Every ticket is readable and annotatable by an agent with a scoped token. Agent writes are internal notes and proposals. Nothing an agent does is visible to a reporter until a human adopts it.

Not in scope: the bounty rules page, the explorer, the wallet, the DAO harness. Each is linked, none is absorbed.

## 3. Where it lives

Recommendation: **`bounty.xe.network`** for the bounty portal and **`support.xe.network`** for the desk. One deployment, host-based routing, shared accounts.

Why `xe.network` rather than `test.network`:

- Payouts happen at mainnet launch and the programme is meant to continue on mainnet. Reporter accounts, tracking IDs and award records should not be tied to a testnet brand that rotates with each network reset (`testnet-0005` is the current one).
- Support is for XE, not for the testnet.
- `test.network/bounty` stays as the rules and marketing page and links in. Nothing there breaks.

Why `bounty` rather than `bugs`: the thing reporters are looking for is the programme and the reward. `bugs.xe.network` on the mainnet brand reads as a confession and would also be the wrong name for the support half.

If a single hostname is preferred, `desk.xe.network` with `/bounty` and `/support` works and is what the working name assumes.

Either way there is also a staging instance at `desk.test.network`, per the project rule that everything ships to `*.test.network` first (§14). It holds throwaway data and is not the bounty portal; the production instance on `xe.network` is, and it reads the testnet node until mainnet launch.

## 4. Roles

| Role | Who | Can |
|---|---|---|
| Reporter | Anyone with an account | File, read and update own tickets; add a payout address; see own award status; see the public leaderboard and public tickets |
| Agent | A pinned model with a scoped token, run by a team member | Read every ticket including private ones it is scoped to; write internal notes; propose severity, duplicate, internal ticket, status, estimate, gate; attach a patch reference. Cannot send a public reply, change public status, or touch awards |
| Reviewer | Core team humans (Adam, Joseph, Will, named others) | Everything an agent can, plus: adopt or reject proposals, send public replies, set status and tier, mark duplicates, set the mainnet gate, link patches, mark disclosed |
| Treasurer | Members only (Joseph, Will) | Approve awards; export the payout list |
| Admin | Members | Manage users, tokens, integrations. Scope text, tiers, ceilings and templates are config (§14), changed by review, not from an admin screen |

The rule from the DAO harness carries over: **an agent recommends; a human decides and speaks.** Enforced in the authorisation layer, not in prompts.

## 5. The ticket

One table, two kinds.

```
ticket
  id              short public id, e.g. XE-0142 (bounty) / XS-0031 (support)
  kind            bounty | support
  visibility      public | private           private: body and attachments encrypted at rest
  source          web | github | email | discord | telegram
  source_ref      github issue number, discord thread id, message id, ...
  reporter_id
  title
  body            markdown; reporter-editable until triaged
  attachments     PoC scripts, logs, captures; encrypted when private

  -- bounty fields
  area            consensus | p2p-sync | node-api | leasing-ledger | dao-harness | sdk-docs-web | ops-testnet | other
  claimed_tier    critical | severe | high | medium | minor | none
  assessed_tier   same set, or null until triaged
  verdict         valid | likely-valid | design-gap | duplicate | notice | support | invalid | out-of-scope
  duplicate_of    ticket id
  mainnet_gate    before | decide | later | null
  effort_eng      <1h | 1-4h | half-1d | 1-3d | 3-5d | 1-2w | design
  effort_agent    derived label, same bands as BOUNTY_TRIAGE.md §Two clocks
  internal_ref    engineering ticket in xeprotocol/core, e.g. #1064, #870 (faucet#10 for the faucet repo); many public tickets may share one
  patch_refs      PRs or commits, with repo; the fixing PR from the internal ticket lands here
  disclosed_at    when the public issue went up (private reports)
  award_xe        micro-units, set on acceptance
  payout_address  XE address, reporter-supplied or generated in the portal
  paid_ref        transaction hash at mainnet launch

  -- workflow
  status          new | triaging | needs-info | accepted | fixing | patched | disclosed | awarded | paid | closed
  closed_reason   duplicate | invalid | out-of-scope | withdrawn | answered | stale
  assignee
  created_at, updated_at

ticket_event      append-only, signed, hash-chained: who, what, before, after, when   (the audit trail; §14)
note              internal; author is a human or an agent token; never shown to reporters
reply             public; a person's, or the desk's own stock reply (never a token's); mirrored to the source channel
proposal          agent-authored change to any ticket field; state pending | adopted | rejected; adopting writes the field and an event
```

The bounty fields are exactly the columns of `BOUNTY_TRIAGE.md`, including the Internal column, so the triage imports without translation and the tool's own export reproduces the doc.

`assessed_tier` is the ruling of whoever holds the `tier` role; any team member can. The triage agent's reading is a proposal against it, never the value itself. Where the two differed on 28 October (#8, #4, #96, E2, #20) the team's tier stands and the agent's reading survives as a note; the desk should make that the normal shape of a disagreement.

Status flow for bounty tickets:

```
new → triaging → (needs-info ⇄) → accepted → fixing → patched → disclosed → awarded → paid
                              ↘ closed (duplicate | invalid | out-of-scope | withdrawn)
```

The internal tracker's states map onto this flow rather than adding a parallel one: a report with an internal ticket is `accepted`; a partial fix is `fixing`; a merged fix is `patched` with the PR in `patch_refs`. "Exists" (the internal ticket predates the report) is an event on the ticket, not a state. The desk never writes to the internal tracker; it links to it, and it reads it. The tracker is the private `xeprotocol/core` issues. The internal ticket names the public report, `security: bounty bundle xe#8` meaning `xeprotocol/xe#8` (several reports can be named by one ticket; `dao#1`, `sdk#11` for the other repos). The worker reads `core` with the same GitHub token it uses for the public repos: the tag fills `internal_ref`; an open internal ticket moves a `triaging` report to `accepted`; one closed as completed moves `accepted` or `fixing` to `patched` and the report into the outbox; one closed for any other reason (not planned, duplicate) leaves a note, since the public verdict is the Reviewer's. The tracker links a report once: a link a person has cleared is not put back by the ticket still naming the report. Where the triage doc already named a different internal ticket, the desk notes the second rather than overwriting.

Support tickets: `new → triaging → (needs-info ⇄) → closed (answered | stale)`. A support ticket that turns out to be a bug is converted to `bounty` with one click and keeps its history.

## 6. The human view

The default screen is the one Adam asked for: every open bounty ticket, sorted by assessed tier then claimed tier then age, with the verdict, the gate, both effort clocks, the assignee, the internal ticket, the count of pending agent proposals, and whether a patch is linked. Filters match the triage doc: area, verdict, gate, status, source, has-PR, has-internal-ref.

Each ticket page has three columns: the report (and the reporter thread), the internal thread (notes and proposals, with who or which agent wrote each), and the facts (tier, verdict, gate, effort, dups, patches, award). A pending proposal shows as a diff on the fact it would change, with Adopt and Reject. Adopting a proposed public reply opens it in the reply editor; it is not sent until the human sends it.

A second screen is the **release view**: every `before` ticket grouped by area, with status and internal ticket, so the mainnet gate from the triage doc is a live checklist rather than a snapshot. Tickets that share an internal ticket (the #4 bundle and #68; #15, #89, #14 and E1 on `#1028`) collapse to one line with the public ids listed.

A third is the **outbox**: every ticket whose status moved internally but whose public thread has not been told. On day one that is eleven issues, fixed or closed and still open on GitHub with no reply. It is the queue a Reviewer clears by sending the drafted replies.

Everything is also available as markdown at `.md` and in `llms.txt`, same middleware as the DAO site, so the tool is as readable by an agent through the front door as through the API.

## 7. The agent API

REST, JSON under `/v1`, `no-store`, CORS open, same conventions as the harness. Public tickets, the leaderboard and `GET /v1` (commit, config hashes, network) need no auth, so anyone can curl them. The triage export is the assessment of every open bounty ticket, which the desk does not publish while a bug is open: it is for the team and agent tokens, and refused to anyone else. Everything else is a bearer token bound to a human owner, a model id, a scope set and an expiry; every write it makes is recorded against both the token and the owner.

```
GET    /v1/tickets?kind=bounty&status=open&sort=severity
GET    /v1/tickets/{id}                       full ticket, notes, proposals, events (scoped)
POST   /v1/tickets/{id}/notes                 internal note
POST   /v1/tickets/{id}/proposals             { field, value, reason }  — tier, verdict, duplicate_of, internal_ref, gate, effort, status, reply_draft
GET    /v1/tickets/{id}/attachments/{n}       PoC download, scoped
POST   /v1/tickets/{id}/patch-refs            link a PR or commit
GET    /v1/export/triage.md                   the BOUNTY_TRIAGE.md shape, live
GET    /v1/events?since=                      firehose for the owner's agent, SSE at /v1/events/stream
```

Scopes: `read:public`, `read:private`, `write:notes`, `write:proposals`, `write:patch-refs`. There is no agent scope that sends a reply, sets a status, sets an award, or reads a payout address. An agent's token can see a private report's PoC only if its owner can and granted it.

An agent's typical loop: pull `new` tickets, read the report against the tree, post a note with its reading, propose tier, verdict, duplicate, the existing internal ticket if one already covers it, and both efforts, link any community PR it judges relevant. The human adopts in bulk from the list view. This is what produced `BOUNTY_TRIAGE.md` by hand, and what the engineering pass then corrected in five places; the API makes both halves the daily default.

## 8. The reporter portal

- **Accounts.** Each door offers the ways its people have: on bounty, GitHub OAuth (most reporters already have one and it lets us map the imported issues) or a key of your own, a challenge signed in the harness's signed-request shape under the `xe/desk/login/v1` domain, same WebCrypto Ed25519 flow as the DAO site's browser signer; on support, Discord or an email link. One account can hold several. A payout address is bound by signature, under `xe/desk/payout/v1`, so the address on a ticket is one the reporter has proven they control. Replies are mailed to a confirmed email where the account has one. Next is the XE wallet itself as the first way in, through the same connect kit the governance site uses: [`WALLET_BRIEF.md`](WALLET_BRIEF.md).
- **Filing.** Form mirrors the rules page: area, suggested tier, repro, impact, PoC attachment, payout address, and a checkbox for "this is Critical or Severe, keep it private". Private tickets are encrypted at rest and never mirrored to GitHub until disclosed. The reporter gets a tracking id immediately, which replaces the "ask for an encryption key, wait for a reply" step on the rules page.
- **Wallet generation.** Generate an Ed25519 keypair in the browser, show the seed once, derive the address exactly as the node does (`sha256("xe/account/v1" || pubkey)`), and store only the address. The private key never leaves the page. This is the "even have the wallet generation in it" line and it also ends payout addresses being pasted into PR threads. *As built:* the seed is shown as 64 hex characters, the form the harness's CLI and the DAO site's signer already take, not a mnemonic; a mnemonic encoding can be added when the wallet tooling settles on one.
- **My reports.** Status, tier, the assessed tier once the fix has shipped, the award once the ticket is `awarded`, the public thread, and a "withdraw" button. Reporters see no internal notes and no proposals.
- **Public tickets.** Every public bounty ticket is browsable with its status and thread. Duplicates show what they duplicate. This replaces reading 87 GitHub issues to find out whether something is already known.
- **Leaderboard.** Computed from `awarded` and `paid` tickets. Live, not redeployed.

Disclosure rule, enforced: a private ticket becomes public when a reviewer marks it `disclosed`, which requires a linked patch ref. The tool then opens the public GitHub issue itself, with the reporter credited.

## 9. GitHub

Two-way, scoped to `xeprotocol/xe`, `xeprotocol/dao`, `xeprotocol/sdk` and whatever else is added in config.

- **Import.** Every existing issue becomes a ticket with `source=github`, the reporter mapped by GitHub login (claimed when they sign in), comments kept as the public thread, and linked PRs as patch refs. Every PR that references an issue is attached to it; a PR that says `fixes #n` also moves the ticket to `fixing` when it opens and `patched` when it merges.
- **Inbound.** New issues become tickets. New comments append to the public thread. Labels are set by the tool, not by hand.
- **Outbound.** A public reply posted in the tool is posted on the issue. A status change sets the label (`triaged`, `accepted`, `duplicate`, `invalid`, `needs-repro`, `fixing`, `patched`, `disclosed`). Closing a ticket closes the issue with the reason. The tool's labels are the only labels. Labels follow status automatically; replies and closes always go through a human.
- **Patched means told.** When a ticket reaches `patched`, the tool drafts the public reply (fix, PR, what the reporter can verify) and puts the ticket in the outbox. The internal ticket number is not part of the reply unless the Reviewer leaves it in.
- **Dedup help.** When a new ticket arrives, the agent loop above runs, and the proposal UI shows the three nearest existing tickets by title and area.

The rules page keeps saying "report on GitHub". That stays true; GitHub becomes one source among four and stops being the system of record.

## 10. Importing the triage

`BOUNTY_TRIAGE.md` is the seed. One-off importer, run once after the GitHub import:

- Reads the triage tables (or a JSON export of the same rows, which the canvas can produce) and, for each `#n`, sets `verdict`, `claimed_tier`, `assessed_tier`, `area`, `effort_eng`, `mainnet_gate`, `duplicate_of`, `internal_ref`, `patch_refs`, and files the italic note as an internal note attributed to the triage agent token dated 28 October. `assessed_tier` is the ruled value as it stands in the doc; where the doc records that the first reading differed, the first reading goes into the note.
- Maps the Internal column onto status:

  | Internal | status | also |
  |---|---|---|
  | `#n` (open) | `accepted` | |
  | `#n exists` | `accepted` | event: internal ticket predates the report |
  | `#n partial` | `fixing` | `patch_refs` = the partial PR |
  | `#n fixed (#pr)` | `patched` | `patch_refs` = `#pr`; ticket goes to the outbox |
  | duplicate | `closed` / `duplicate` | `duplicate_of`; `internal_ref` of the target |
  | notice | `closed` / `answered` | `verdict = notice` |
  | invalid | `closed` / `invalid` | |
  | support (faucet, stale genesis, the `#1027` incident) | `verdict = support`, `closed` / `answered` (or `stale`); stays a bounty ticket, since it is a researcher's GitHub issue, not a community question | `internal_ref` kept (`faucet#10`, `#1027`) |

- Creates E1, E2 and E3 as private tickets from the emails, with the payout addresses in `payout_address` and the reporters invited by email to claim them. E1 imports as `closed` / `duplicate` of #14, whose own ticket is `patched` on `#1028`; whether a duplicate of a fixed finding is paid is a programme decision, not the importer's.
- Imports the facts as facts, not as proposals. The doc is already the team's ruling, so re-proposing it to the people who made it would be noise; the import event records the triage agent token as the source and the engineering pass as the authority. Proposals start with the first new ticket after import.

After import, the tool is the source of truth and `BOUNTY_TRIAGE.md` becomes a dated snapshot; `GET /v1/export/triage.md` produces the current one.

## 11. Discord and Telegram

Both bots do the same four things, in the same shape.

- **Create.** A message in the designated support channel (Discord: a forum channel, one thread per ticket; Telegram: a group with topics, or DM to the bot) creates a `support` ticket with `source` and `source_ref`. The bot replies with the ticket id and a portal link.
- **Thread.** Later messages in the thread append to the ticket. The reporter's platform identity is linked to their portal account when they sign in with it, or stays as a platform-only reporter.
- **Reply.** A public reply from the tool is posted into the thread by the bot, attributed to the human who wrote it. Agents' notes never go to the channel.
- **Status.** Closing the ticket closes or archives the thread with a one-line reason.

A support ticket that is actually a bug report is converted to `bounty` by a reviewer; the bot tells the reporter where to find it and asks them to add a payout address. A PoC must never be posted into Discord or Telegram; the bot's message on conversion says so and points at the private filing form.

Web support is the same ticket via a form at `support.xe.network`, with email magic link so people can be replied to.

*As built, 29 October (Discord):* a `/panel` in `#support` with the eight support topics as a select menu; picking one opens a two-field modal; submitting opens a private thread (public if the server cannot) and the ticket, `source=discord`, `source_ref=<thread id>`. Thread messages append to the public thread; desk replies are posted into the thread by the bot under the author's name; closing on either side archives the thread. `/close`, `/reopen`, `/bounty`, `/rename`, `/add`, `/answer <support template>`, `/ticket`. Reporters are keyed on Discord id and merge with a web account on Discord sign-in. The thread is private and the ticket public, so the asker is not exposed in the moment and the answer still serves the next person. Telegram follows in the same shape (`desk/services/channels.py` is platform-neutral; only the gateway glue is Discord's).

## 12. Awards and payout

Acceptance sets `award_xe` within the tier ceiling, which is a published config value, not a column. A Treasurer approves awards; approvals are signed events in the chained log. At mainnet launch, `GET /v1/export/payouts.csv` produces `(ticket, address, micro-units)` for every `awarded` ticket with an approved award and a payout address.

That export is a treasury movement, which under the Operating Agreement is a reserved matter. It is therefore an input to a member resolution in the DAO harness, not something the desk executes. The desk records `paid_ref` when the harness reports the transaction. Same rule as everywhere else: the tool prepares, the keyset signs.

## 13. Security of the tool itself

It will hold working exploits for a live network, so:

- Private ticket bodies and attachments encrypted at rest with PyNaCl SecretBox under a scoped key in the service keyfile, the keyfile itself unlocked from an env-injected secret, rotated; decrypted per request for scoped readers only.
- Team accounts require a passkey or TOTP. Agent tokens expire, are scoped, and are revocable in one click.
- Every read of a private attachment is an event in the chained log, so the question "who has seen this exploit" has an answer that can be verified, not just queried.
- No PoC body in any outbound integration message. Ever. Enforced by the mirroring code only sending `reply` rows, never `body` or `attachment`.
- Rate limits and PoW-free captchas on the public filing form; the DAO inbox lesson (#49) applies.
- The tool is in scope for the bounty from the day it is public, and says so on its front page.

## 14. Stack, principles and deployment

Same stack and principles as the DAO harness (`xeprotocol/dao`, the reference implementation), so the two share patterns, reviewers and eventually the Python SDK. What follows is the XE project spec applied to the desk; where the desk has to differ, it says so.

### Stack

- **Language and runtime.** Python 3.12, fully async, type hints everywhere, `from __future__ import annotations`. `pyproject.toml` (setuptools), one package per concern: `xe/` protocol, `desk/` application. A console script gives a CLI from day one (import, export, token management, re-sync). `ruff` for lint and format, line length 110.
- **Web.** FastAPI + uvicorn. JSON under `/v1`, `Cache-Control: no-store`, CORS open. Server-rendered HTML via Jinja2 everywhere else. No SPA, no build step, no JS framework; a few hundred lines of vanilla JS only where the browser has to hold a key: the wallet generator and the XE-key sign-in (WebCrypto Ed25519), plus the SSE listener. SSE via `sse-starlette` for `/v1/events/stream`, with a human-readable `/live` page on top. Every page also served as markdown (`/path.md`, `Accept: text/markdown`) and `/llms.txt`. `markdown-it-py` renders config-authored text and reporter bodies; `markdownify` + `beautifulsoup4` turn GitHub and email HTML into markdown on intake.
- **Data.** PostgreSQL 16 on the `pgvector/pgvector:pg16` image, so nearest-ticket dedup (§9) can move from title matching to embeddings later without changing the engine. SQLAlchemy 2.x async with asyncpg; Alembic, run as its own one-shot Compose service before the app starts. Anything hashed or signed (sign-in challenges, payout-address attestations, event payloads) is stored as the exact bytes that were hashed, as a string, never round-tripped through JSONB.
- **Crypto and protocol.** `pynacl` for Ed25519 and for the at-rest encryption of private tickets (SecretBox); `hashlib` for SHA-256 and BLAKE2b. No other crypto dependency. The `xe/` package from the harness supplies address derivation (`sha256("xe/account/v1" || pubkey)`), canonical encoding and hashing, the signed-request shape, and the httpx async node client, which the desk uses to check that a payout address exists on the network and to read `network_id`. Take it as the shared Python SDK if it has been extracted by then; otherwise copy it. No code dependency on `xeprotocol/dao` itself.
- **Signed requests.** One shape for everything a reporter signs: `{"payload", "timestamp", "pub_key", "signature"}`, a per-action domain string (`xe/desk/login/v1`, `xe/desk/payout/v1`, `xe/desk/withdraw/v1`), canonical JSON (sorted keys, no whitespace, ASCII), ±10 min timestamp window, one-time signatures. `pub_key` is exactly 64 hex digits and `signature` exactly 128, either case, nothing else: anything longer, shorter or spaced is refused when the request is parsed. The harness's verifier is the verifier.
- **Config and secrets.** `pydantic-settings` reading `.env`; `.env.example` committed, `.env` never. Config as data in YAML under `config/`, mounted read-only, hashed at boot, hashes published at `GET /v1`: tiers and award ceilings, areas, the label set, reply templates, bot messages, scope text, the kill-list. One encrypted keyfile (`secrets/signer.json`) for the keys the service itself holds, each with a fixed scope: the event-log signing key and the at-rest encryption key. Human keys never touch the server; reporters' keys never leave their browser.
- **Deployment.** Docker Compose: `db`, `migrate`, `app`, `worker`. Same image for `app` and `worker`, selected by env. The worker runs the GitHub sync, the Discord and Telegram bots, email intake, the outbox mirroring and the agent event stream. `GIT_COMMIT` baked in as a build arg and reported by `GET /v1`, which is the #57 lesson applied to ourselves. Caddy in front for TLS; app binds `127.0.0.1` only and trusts `X-Forwarded-For` from Caddy alone, first hop, which is the #81 lesson.
- **Testing.** pytest + pytest-asyncio, run in the container on the VPS, not locally. Byte-exact fixtures pin the wire formats the desk depends on: GitHub webhook payloads, the signed-request shape, the triage export. Unit tests for hashing, signing, log chaining, the authorisation matrix in §4 (every agent scope against every write), and the mirroring rule in §13 (no `body` or `attachment` ever leaves). Template tests: parse, copy lint, Jinja pitfalls.

### Dependencies beyond the harness list

Postgres, FastAPI, SQLAlchemy, PyNaCl, httpx, Jinja, plus the harness's small extras, are the list. The desk needs a few more; each is justified here so it does not have to be in a commit:

- **GitHub:** none. REST and webhooks over httpx.
- **Telegram:** none. Bot API over httpx, webhook mode.
- **Discord:** `discord.py`, because the gateway is a websocket protocol with heartbeats and resume, not an HTTP API.
- **Email intake:** stdlib `imaplib` and `email` against the `security@` mailbox, polled by the worker. No library.
- **Passkeys:** `webauthn` for the team sign-in. TOTP as the fallback is stdlib `hmac`.

Anything else is a justification in the commit.

### Principles that carry over

- **The desk never holds a key that can move funds.** It assembles the payout export; the keyset signs under a member resolution in the harness. Reads are from one trusted node; the desk submits no blocks at all.
- **Hash-chained event log.** `ticket_event` is the harness's log: append-only, signed by the service key, each event hashing the previous, with `/v1/events/verify` and `/v1/events/replay`, anchored periodically to the state chain. Award approvals, agent writes, adopt and reject, every read of a private attachment: if it is not in the log, it did not happen. The audit trail in §5 is this, not a `created_at` column.
- **Config is data, and it is public.** Tier ceilings, scope, templates and copy are YAML, hashed and served. Changing the award ceiling is a config change through review, not a database edit. Code changes behaviour; config changes policy. The one thing the public hash set cannot cover is the encrypted ticket content, and the front page says so.
- **Server-rendered, agent-readable.** HTML from Jinja, JSON at `/v1`, markdown twins, SSE for live. A page that cannot be curled is a bug. This is what makes the agent loop in §7 and the human view in §6 the same data.
- **Frozen paths.** Ticket ids and their URLs appear in payout resolutions and in disclosure credits; they keep their URL and meaning forever. They may redirect (a hostname decision in §16 Q1 is survivable), never change.
- **Two registers of language.** Public copy (portal, bot messages, reply templates) and programme copy (the rules, the tier definitions, anything the awards depend on) are separate YAML files with separate vocabularies and a kill-list lint between them that fails the build. Reply templates are public register; they must never promise an award, which is the lint's first entry.
- **Testnet is the rehearsal.** A staging desk at `desk.test.network` with throwaway data takes every release first. The production desk is one deployment on `xe.network` (§3) whose `XE_NODE_URL` points at the testnet node until mainnet launch and at mainnet after; the network badge is drawn from the node's `network_id` by positive match on mainnet. One codebase; `XE_NODE_URL` and `PUBLIC_BASE_URL` are the only differences between any two instances.
- **Minimal dependencies, boring choices.** The list above, and the justifications above.

Separate repository, `xeprotocol/desk`, GPL-3.0-or-later, public from the start.

## 15. Sequencing

Three releases. Each is usable on its own; none waits for the next. Both clocks, as in the triage doc.

| Release | Contents | Engineer | Fable 5.1 |
|---|---|---|---|
| **1. Backend and team UI** | Schema, auth, roles, ticket and note and proposal model, severity-ordered list, ticket page with adopt/reject, release view, outbox, GitHub import and two-way sync, triage import with internal refs and status mapping, agent API with scoped tokens, markdown mirror, deploy | 3–4 weeks | 3–4 days |
| **2. Reporter portal** | Accounts (GitHub, email, XE key), filing form, private tickets with encryption, wallet generation, my reports, public ticket browser, leaderboard, disclosure flow, award approval and payout export | 2–3 weeks | 2–3 days |
| **3. Support** | Discord bot, Telegram bot, web support form, convert-to-bounty, channel mirroring | 1–2 weeks | 1–2 days |

Release 3 so far (29 October): the web support form shipped with Release 2; the support door was rebuilt around holders' questions (topics, answered-first list, safety notice, answer templates); the Discord bot and Discord sign-in shipped. Telegram is the remaining item. Also 29 October: the desk took the governance site's styling (tokens, header, light and dark themes); sign-in became per door (bounty: GitHub, a desk key; support: Discord, email link); replies are mailed to reporters with a confirmed email. The wallet connection is specified in [`WALLET_BRIEF.md`](WALLET_BRIEF.md) and waits on the connect kit as a bundle.

Release 2 shipped 28 October: three sign-ins, the filing form on both doors (`/report`, `/ask`), private reports sealed with their attachments, the in-browser key and payout binding, `/my`, reporter replies and withdrawal, and the treasurer's `payouts.csv`. Release 1 alone fixes the programme hygiene problems in the triage doc (no labels, no replies, triage in a file, wallets in threads), clears the eleven fixed-but-silent issues through the outbox, and gives Adam the API. Release 2 retires `security@` as the Critical path. Release 3 gives Joseph the single dashboard.

The agent clock assumes a human spends a few hours per release on review and a day on the Discord and Telegram app registrations and permissions, which no agent can shortcut.

## 16. Open questions

1. Hostnames: `bounty.` and `support.` on `xe.network`, or one `desk.xe.network`? Recommendation is the pair.
2. ~~Does `test.network/bounty` keep "report on GitHub" as step one, or does it send people to the portal with GitHub as the fallback?~~ Decided 28 October: portal first. The rules page sends people to `bounty.xe.network/report`; GitHub stays a channel the desk reads, not the front door. Rules-page copy change pending.
3. ~~Reporter identity for payouts: is a GitHub login plus a payout address enough, or do we require an XE key signature on the payout address to prove control?~~ Decided 28 October: the signature is required. `/account` binds an address only through a signed request under `xe/desk/payout/v1` whose key derives to that address; the treasurer's payout export carries only bound addresses.
4. Which agent runs the triage loop day to day, under whose token? Adam's, by his own description; Joseph's for the DAO harness tickets.
5. Who is a Reviewer on day one, and is Adam a Treasurer? The Operating Agreement says treasury is members-only; the desk should mirror that unless a resolution says otherwise. Tier rulings should sit with a named `tier` role that any team member can hold, rather than with every Reviewer.
8. ~~Where does the internal tracker live, and does the desk get read access?~~ Answered 28 October: `xeprotocol/core` issues, tagged `xe#NN`; the desk reads them (§5) and the outbox fills from the tracker's state.
6. Bounty scope for `xeprotocol/dao` and `xeprotocol/sdk`: three reporters have asked. The desk can take tickets for them regardless; whether they pay is a programme decision to put on the rules page.
7. Retention of PoCs after disclosure and payout: keep encrypted indefinitely, or purge after N days? Recommendation: keep, encrypted, as the record of what was paid for.

## 17. References

- `BOUNTY_TRIAGE.md` (not in the repo; private reports): the state of the queue on 28 October and the data model this brief copies.
- [`MAINNET_REQS.md`](MAINNET_REQS.md): what the DAO harness needs from mainnet; the `before` gate in the desk is the bounty side of the same question.
- [`BRIEF.md`](BRIEF.md): the DAO harness brief; roles, registers and the recommend/decide rule are inherited from it.
- [xeprotocol/dao](https://github.com/xeprotocol/dao): the reference implementation; the stack and principles in §14 are the project spec from it, applied to the desk.
- [test.network/bounty](https://test.network/bounty): the rules, tiers and scope the desk enforces.
