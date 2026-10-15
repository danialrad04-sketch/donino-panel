# Donino releases

## Unreleased — planning documentation

Development checkpoint `1.0.0a1` (not a stable release):

- SQLAlchemy connection layer and immutable Alembic foundation schema for SQLite and PostgreSQL. Supported legacy SQLite migrations retain their original backup and preservation behavior.
- Per-device/per-protocol credentials, device expiry/disable/rotation, selective node assignments and matching subscription filtering. Xray revocations still restart the node.
- Encrypted TOTP seeds, replay protection, one-use recovery codes and scoped, expiring/revocable API tokens. MFA enable/disable revokes existing sessions and automation tokens.
- Read-only source snapshots for SQLite import into an empty destination, consistent PostgreSQL logical backups and transactional archive restoration. The matching MFA master key must be preserved separately.
- Browser controls for devices, assignments, MFA and API tokens; real PostgreSQL integration CI. Period-aware report handling is preliminary until the upgraded node agent is implemented in phase 3.

- Add the Persian 1.0 master plan, feature parity and protocol matrices, gaming DNS/doctor-dns migration design, installer/SSL specification and acceptance contract.
- Pin additional research references and connect the roadmap to the phased plan. This documentation does not add runtime protocols or change the 0.2.0 product version.

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
