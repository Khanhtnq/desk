# Fixing a report

How a bounty report becomes a fix. For whoever picks up the engineering ticket, person or agent, and for whoever reviews the pull request. The desk's working guide is [`BOUNTY_GUIDE.md`](BOUNTY_GUIDE.md); this is the part between `accepted` and `patched`.

The desk serves this at `https://bounty.xe.network/fix` (markdown at `/v1/agent/fix.md`), and it is linked from `/llms.txt` and the agent brief. The engineering repos point at it from `AGENTS.md` and the bounty-fix issue template; the files to drop in are in [`repo-kit/`](repo-kit/).

It binds every part of the platform: the node (`core`), the DAO harness, the SDK, the sites, and this desk. Where a repository lands changes without pull requests, the commit message carries the three lines of §2 and the sweep result of §5. A fix that skips them is not deployed, whoever or whatever wrote it. The day the desk fixed sixty-seven reports in one commit without a sweep, the next morning's intake carried a dozen follow-ups on those fixes; the sweep is cheaper than that.

## 1. The one rule

A report names a path. The bug is a rule the code broke, and the path is one place it broke it. The fix closes the rule, not the path. `patched` means there is nothing left in that class for the next report to find.

The pattern this exists to stop: a report arrives, the fix closes the request in the proof of concept, the test replays the proof of concept, the ticket is patched, and a fortnight later the same reporter files the same bug on the sibling path, and is paid again. Reviewing the first batch of follow-ups on the desk, two in five new reports named a ticket that was already fixed. The thread endpoint logged every opening of a sealed body after its fix; the similar-tickets endpoint still opened them silently. The account-merge takeover was closed in the link flow; the merge itself still kept the attacker's key. Tokens died with their owner's roles; sessions did not. None of those second reports found anything the first fix should not have.

## 2. Before writing code: the rule

In the engineering ticket, before the branch, three lines:

1. **The rule.** One sentence, in the present tense, that the code is supposed to keep and does not. "A sealed body is only opened through `body_for`, which records `ticket.read`." "A credential is removed from an account when the account that held it is unmerged." "A one-time token is consumed under a row lock." If it takes a paragraph, there are two rules; write both.
2. **Where the rule applies.** Every site, listed, found by reading the tree rather than remembering it: grep for the call, the column, the check. The report's path is one entry. The list is what the reviewer checks the pull request against.
3. **What the report got wrong, if anything.** A report can name the right rule and the wrong site, or the wrong rule. Say which, so the fix is not shaped by the proof of concept.

A ticket without these is not ready to work. Writing them takes ten minutes and is most of the fix.

## 3. The change

- Fix the rule at the point the rule lives, so every site inherits it, rather than at each site. A check added to one handler is a check missing from the next one written. Where the rule has to be enforced at the sites, the list in §2 is the checklist and every entry is in the diff.
- One class, one change. If the reading in §2 turned up a second rule, that is a second ticket with its own three lines, linked, and the report is tagged onto whichever one is its root. Do not fold it in silently and do not leave it unwritten.
- Remove the mechanism, not the symptom, when you can. A check that was never enforced is better deleted and replaced by a type or a path that cannot skip it than guarded in one more place.
- No new surface in a fix. A fix that adds an endpoint, a flag or a mode has widened what the next report can read.

## 4. The test

The test asserts the rule, not the proof of concept.

- Replaying the report's request and asserting the new status code proves that request is dead. It says nothing about the sibling. Keep it if you like; it is not the test.
- The test walks the sites in §2 and checks the rule at each: every endpoint that can return a sealed body appears in the read log; every path that consumes a one-time token refuses the second concurrent use; every credential is gone after the unmerge. When a new site is added later, the test is what fails.
- A test written against the list is also how the reviewer knows the list was read.

## 5. The sibling sweep

Before `patched`, someone who did not write the fix reads the tree for what the fix missed, with the rule in hand, not the report. This is work the triage agent does on request and well: give it the rule and the list and it searches the tree for every other place the rule is assumed, and reports what it found as an internal note on the ticket, never as a public ticket. Anything it finds is folded into the fix or filed internally and tagged onto the same engineering ticket. The sweep is what turns the reporter's second ticket into a line in the first fix. It costs an hour. The second ticket costs an award.

## 6. One engineering ticket per class

The internal ticket is for the class, not the report. When a sibling report arrives, it is tagged onto the existing ticket (by desk id or `xe#n` in the title or body; the desk links it on the next poll and keeps the link if the text is later edited) rather than given a new one, and the ticket stays open until the class is closed. Several reports moving to `patched` at once from one closing ticket is the sign of a resolution; one at a time is the sign of a patch.

## 7. Review

The pull request is reviewed against §2, not against the report:

- Is the rule stated, and is it the rule the code broke?
- Is every site on the list in the diff or shown not to need it?
- Does the test assert the rule across the sites?
- Has the sweep run, and what did it find?
- Does the change add any surface?

A pull request that closes the report's request and nothing else is sent back with the list. The reporter who found the first path will find the second; the point is that there is no second.

## 8. After

- A sibling filed within a few weeks of `patched` is read as a verdict on the fix, not only as a new report. Note it on the engineering ticket. The desk's per-reporter list makes the chain easy to see; the triage agent is told to read a follow-up on a shipped fix against the fix commit, not as a duplicate of the original.
- A fix that produced no siblings is the measure. Keep count.
