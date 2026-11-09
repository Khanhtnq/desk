---
name: Bounty fix
about: An engineering ticket for a class of bug reported through the bounty desk
title: "security: <the rule, in a few words> xe#NN XE-NNNN"
labels: security, bounty
---

<!--
One ticket per class of bug, not per report. Name every report this covers in the title or here, by
GitHub number (xe#63) or desk id (XE-0232); the desk links them and moves them with this ticket:
open → accepted, closed as completed → patched. Edit freely; links made are kept.
The brief: https://bounty.xe.network/fix
-->

**Reports.** xe#NN, XE-NNNN, …

**The rule.** One sentence, present tense, that the code is supposed to keep and does not. If it takes a paragraph, there are two rules: open a second ticket.

**Where the rule applies.** Every site, found by reading the tree (grep the call, the column, the check). The report's path is one entry. The pull request is reviewed against this list.

- `path:function` — the report's path
- `path:function`
- …

**What the report got wrong, if anything.** Right rule wrong site, wrong rule, or nothing.

**Sweep.** Before `patched`: who swept the tree with the rule in hand, at which commit, what they found. Findings that are gaps go into this ticket, not into a new public issue.

**Fix.** One sentence; the pull request when it exists. The PR says `Closes #NNN` (this ticket): the merge closes it, and the closed ticket moves the reports to `patched`. `fixes xe#NN` in a `core` PR does nothing; the desk reads `core` issues, not `core` PRs.
