# Claude — resume Donino Panel

Start here on **every session**, including when the entire user message is
`ادامه`, `ادامه بده` or `continue`.

1. Read `AGENTS.md`, `docs/coordination/README.fa.md`, then run
   `python scripts/coordination.py status --actor claude`.
2. Read the returned task document and checkpoint. Inspect `git status`, branch,
   recent commits and any existing PR. Fetch `origin` when network is available.
   Resume the existing task branch instead of starting it again from scratch.
   Check `origin/main:docs/coordination/assignments.json` for a newer assignment;
   if it changed, preserve the old branch and read the new task before proceeding.
3. On a new checkout, use the assigned remote branch if it exists. Otherwise
   create the assigned branch from current `origin/main`. Never reset a dirty
   tree or replace a task branch with a fresh clone's checkpoint.
4. If status is `assigned` or `in_progress`, continue the next unfinished step
   autonomously within the task scope. Treat the user's new corrections as
   steering. Do not ask the user to restate the plan or say “continue” per step.
5. After a meaningful milestone, before switching context, and when nearing a
   limit, save `docs/coordination/checkpoints/claude.json`. Use
   `python scripts/coordination.py checkpoint --actor claude --input /tmp/claude-checkpoint.json`.
   The input must use the fields shown in the coordination guide. Commit the
   work and checkpoint and push the task branch. In `last_verified_commit`,
   record the **code commit actually tested**, not an untested later commit.
6. If interrupted without a final checkpoint, reconcile the checkpoint with the
   actual diff and commits first. Never treat an unchecked box as proof that a
   committed feature is absent. Retry failed commands only after diagnosing why.
7. Once acceptance is met, create/update a PR to main, record its URL and checks,
   set status `waiting_for_review`, commit/push the checkpoint, and stop that
   assignment. Do not merge, tag, bump product version, or pick another phase.
   On a later “continue”, check for Codex's new assignment/review feedback first;
   if there is none, report the existing PR is awaiting review, without inventing
   more work. A user-assigned new task always takes precedence.
8. For a genuine dependency outside your scope, record status `blocked`, the
   exact dependency, completed work and useful independent next steps. Continue
   authorized independent work while possible; never silently change schema or
   code owned by another task to avoid recording a blocker.

This is asynchronous collaboration through GitHub, not an automatic connection
to another chat. Limits do not reset themselves; a human must reopen/resume the
session. Do not claim that Codex has read a checkpoint until review is recorded.
