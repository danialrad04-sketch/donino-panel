# Donino releases

## Unreleased — phase 1 (partial): security, devices, schema 3

- Schema 3 (`PRAGMA user_version=3`) with a private pre-migration backup. Every existing user gets one default device whose id equals the user id and whose secret equals the legacy credential, so Xray client emails, counter baselines and subscription links are unchanged and no node restarts because of the upgrade.
- Devices: each user can have up to 20 devices, each with its own Xray credential, enable/disable, rotation and per-device traffic totals. The default device cannot be deleted. Disabling or rotating a device uses the existing full-restart revocation path.
- Admin two-factor authentication (TOTP, RFC 6238) with ten single-use recovery codes, replay protection per time step and the shared login lockout.
- Scoped API tokens (`read`, `users`, `full`) stored as digests, with expiry and revocation. Token scopes cannot reach account-security or owner-only endpoints.
- Session metadata: list, revoke one, revoke others. Password change revokes other sessions and API tokens.
- Paginated `/api/users` with `limit`, `offset`, `q` (literal substring) and `state`, returning `X-Total-Count`. Without `limit` the legacy response is kept.
- Node agents from 0.2 keep working: the heartbeat accepts the Xray client id, which is the device id for the default device.

Not done in this entry: PostgreSQL, mTLS, node assignment, budget leases, per-device subscription links, admin management API, usage periods, and UI pagination (the interface still loads the newest 1000 users and filters them in the browser).


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
