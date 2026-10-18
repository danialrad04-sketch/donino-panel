# Donino Panel: shared development contract

Read `docs/coordination/README.fa.md`, `docs/coordination/assignments.json`,
your assigned task and your checkpoint before changing code. User instructions
override this workflow. No acknowledgement or extra permission is needed to
continue work already assigned by the user.

- Work from current `origin/main` on a task branch. Preserve uncommitted work;
  inspect remote branches/PRs before assuming another contributor did nothing.
- Codex coordinates integration. Claude owns only the task assigned to `claude`
  in `assignments.json`; `CLAUDE.md` explains resuming with «ادامه».
- Record completed work, remaining steps, exact next action, test evidence and
  blockers in a checkpoint. Push recoverable commits to your task branch.
  A local checkpoint alone is not visible to a different machine.
- A checkpoint is a handoff, not a distributed lock or a live messaging service.
  Never force-push, overwrite another contributor's in-progress checkpoint, or merge an
  unrelated development branch to resolve concurrency.
  After review, the coordinator may archive a completed handoff intact under
  `docs/coordination/history/` and initialize the checkpoint for a new assignment.
- Schema 12 is the current database baseline. Do not import the incompatible
  Alembic model from the old `development/1.0` branch.
- Keep private keys, pairing codes, DB snapshots, tokens and private plans out of
  Git, PR bodies, checkpoints and screenshots. Report redacted evidence only.
- Preserve device IDs, period accounting, signed node configuration and TLS
  verification. An engine is supported only after real-client acceptance.
- Regenerate `release-manifest.json` after product/docs edits; run relevant
  tests and `git diff --check`. Describe actual limits and skipped checks.
- No real user VPS/domain is currently available. Local CI is not evidence of
  public ACME issuance, Iranian ISP reachability, game compatibility or stable 1.0.

Do not deploy, change host firewall policy, or expose services merely because
this development workflow exists. Follow the user's actual operational scope.
