# Donino releases

## 0.2.0 — 2026-10-15

New users can be added to existing Xray inbounds without restarting the core or interrupting established streams. Revocations and transport changes intentionally restart the node to terminate existing access.

- Durable node-side SQLite usage journal, bounded replay batches, acknowledgement tracking and node/origin binding. Observed traffic survives agent restarts and lost HTTP responses without double-counting.
- Xray candidate validation, live-add success-count checks, full-restart reconciliation after failed live updates and recovery of the previous running configuration when new startup fails.
- Versioned schema migration from 0.1 with a private consistent pre-migration backup and preservation of users, credentials, tokens and legacy combined usage.
- Customer portal with status, remaining quota, upload/download totals, expiry, raw connection links and locally generated subscription/profile QR SVGs.
- Inbound editing and enable/disable controls, preserving REALITY keys for same-protocol edits.
- Node agent version, process status, apply mode and pending usage diagnostics. Exclusive state-directory process lock.
- CLI `--version` and `migrate`, expanded API/migration/journal/browser tests, real encrypted-stream continuity and real occupied-port rollback tests.

Operational limits: the five-second synchronization interval and stale cutoff still apply. Unsampled bytes can be lost in a crash. Rollback can temporarily restore prior access settings and does not acknowledge the failed desired revision. Full revocations still interrupt all connections on the node. Existing 0.1 traffic cannot be split retrospectively into upload/download. WireGuard, sing-box, billing, MFA and IP/HWID limits are not part of this release.

## 0.1.0 — 2026-10-15

Initial independent Persian dashboard, user/quota/expiry management, owner/operator/viewer roles, multi-node Xray agent, VLESS/REALITY, VMess/WS/TLS and Trojan/TLS, subscriptions, backups, audit logs and deployment templates.
