# XE Desk

The ticket desk for the XE bug bounty and support: reports come in from GitHub (and, privately, by email), the team triages, agents suggest, people decide and reply, and every move is in a signed, hash-chained log. Two front doors, one app: `bounty.xe.network` and `support.xe.network`.

The design is [`docs/DESK_BRIEF.md`](docs/DESK_BRIEF.md); the team's working guide is [`docs/BOUNTY_GUIDE.md`](docs/BOUNTY_GUIDE.md); sign-in and the wallet connection are [`docs/WALLET_BRIEF.md`](docs/WALLET_BRIEF.md). The seed data was the triage document, `BOUNTY_TRIAGE.md`, which the desk imported once; it carries private reports and is not in the repo. The live equivalent is `/v1/export/triage.md`. Deployment is [`docs/DEPLOY.md`](docs/DEPLOY.md).

## What it does (releases 1 to 3, Telegram pending)

- **Tickets.** `XE-0001` bounty, `XS-0001` support. Facts exactly as the triage columns: verdict, claimed and assessed tier, area, gate (before / decide / later), effort band, duplicate-of, internal ticket, patches. Status `new → triaging → needs-info ⇄ → accepted → fixing → patched → disclosed → awarded → paid`, or `closed` with a reason. The ticket, its status and its thread are public; the team's assessment of a confirmed, unfixed bug (tier, verdict, internal ticket) is published when the fix ships, and the gate and effort never are. A ranked list of what still works against the network is the one thing the desk must not be.
- **An agent recommends; a human decides and speaks.** Agent tokens can read, write internal notes, propose changes to facts and draft replies, and link PRs. No token scope sends a reply, sets a status or award, or reads a payout address. Adopting a proposal writes the field through the same checks a human edit uses; adopting a reply draft only fills the editor. No report is read alone: the brief's first step is the whole desk, every ticket carries a **Read across** list (shared words, shared source paths, same reporter, duplicate links), and a note records what it checked (`desk`, `similar`, `tracker`, `tree`) as data, so a reviewer can tell a reading from a shrug.
- **GitHub both ways.** Issues and comments become tickets and threads (poll and webhook); the desk's status label and open/closed state follow the ticket; replies written on the desk are mirrored as comments; a disclosed private report opens a public issue.
- **The engineering tracker, read-only.** The engineering tickets in the private `xeprotocol/core` name the reports they cover (`security: bounty bundle xe#8`, or by desk id, `XE-0232`). The desk reads the tag into `internal_ref` and follows the ticket's state: open → `accepted`, closed → `patched` and into the outbox. It never writes there.
- **The vault.** Private bodies are sealed with a SecretBox key from the keyfile; the desk refuses to store or open private content when the key is absent; every opening is a log event.
- **The log.** `events` is append-only, each entry hashing the previous and signed by the `log` key. `/v1/log/verify` replays it. Private-ticket events are in the chain but not served publicly. A weekly head snapshot is offered for anchoring on the state chain.
- **Team sign-in.** Passkeys (WebAuthn, RP id `xe.network` so one key works on both hosts), TOTP as the fallback, one-time invite links. No passwords.
- **Two doors.** `bounty.xe.network` for researchers (reports, scope, leaderboard, `/report`); `support.xe.network` for holders and the community: when does the token launch, how do I make a wallet, I have lost my key, is this message real (topics, `/ask`, every answer public and kept). Same desk, same log; distinct menus, vocabulary and copy. Support knows nothing of tiers, areas or awards; the bounty knows nothing of topics.
- **Reporters.** Sign in per door: on bounty with GitHub or a key of your own (`xe/desk/login/v1`), on support with Discord or an email link; one account holds several. Team replies are mailed to a confirmed email. The XE wallet as a way in is specified in [`docs/WALLET_BRIEF.md`](docs/WALLET_BRIEF.md). File with attachments; Critical and Severe reports are private whatever the box says, sealed on arrival with their files. `/my` follows each report; reporters reply and withdraw from the ticket page. A payout address is bound only by a signature from its key (`xe/desk/payout/v1`); the key can be made in the browser and never leaves it. Treasurers export `payouts.csv`.
- **Discord.** A panel in `#support` with the topic menu; a form; a private thread per question that *is* the ticket's thread. Team answers from Discord or the desk; the bot carries desk replies into the thread and archives it on close. `/bounty` moves a question that is really a bug, with the no-PoC-in-chat warning. Sign in on the web with Discord and the threads are under `/my`.
- **Reading surfaces.** Server-rendered pages, every one also markdown (`/path.md` or `Accept: text/markdown`), `/llms.txt`, JSON under `/v1`, SSE at `/v1/events/stream`. Every public page carries a social card (`og:image`, drawn on demand at `/og/…`) with the XE mark, the programme and, for a public ticket, its id, title, tier and status.

## Layout

```
desk/            the app: settings, models, auth/authz, log, vault, services, api, ui, worker, cli
desk/services/   tickets, thread (notes/messages/replies/patches), proposals, users, github, sync, triage
desk/templates/  Jinja2 pages; desk/static/ site.css and desk.js
xe/              the protocol package, copied unchanged from xeprotocol/dao
config/          desk.yaml (policy), copy/ (public, programme, kill list); hashed at boot
alembic/         migrations; 0001 lays down the full schema from the models
tests/           pure tests, the triage parser against the real doc, and DB tests (skipped without a URL)
```

## Running

Nothing runs on a laptop. See [`docs/DEPLOY.md`](docs/DEPLOY.md) for the VPS: build, run the tests in the container, migrate, create keys, add the first user, import GitHub and the triage.

## Licence

GPL-3.0-or-later, as the DAO harness.
