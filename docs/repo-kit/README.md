# Repo kit

Files for the engineering repos, so the fix brief is read where the fix starts. The desk cannot write to those repos; copy these in.

| File here | Goes to | In which repos |
|---|---|---|
| `AGENTS.md` | `/AGENTS.md` | `xeprotocol/xe`, `xeprotocol/dao`, `xeprotocol/sdk`, `xeprotocol/core` |
| `ISSUE_TEMPLATE_bounty-fix.md` | `/.github/ISSUE_TEMPLATE/bounty-fix.md` | `xeprotocol/core` (the engineering tracker) |
| `PULL_REQUEST_TEMPLATE.md` | `/.github/PULL_REQUEST_TEMPLATE.md` | `xeprotocol/xe`, `xeprotocol/dao`, `xeprotocol/sdk` |

`AGENTS.md` is what Cursor, Claude Code, Codex and most agents read before touching a repo; if a repo already has one, append the "Fixing a bounty report" section rather than replacing the file. The issue template puts the three lines of the brief's §2 in front of whoever opens the engineering ticket, so the rule is written before the branch. The pull request template asks the brief's §7 questions of the reviewer.

The brief itself is served by the desk at `https://bounty.xe.network/fix` (markdown: `/v1/agent/fix.md`), so these files link rather than copy; the text has one home.
