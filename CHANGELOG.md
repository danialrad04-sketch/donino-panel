# Donino releases

## 1.0.0-alpha.4 — secure node identity, 2026-10-16

- Schema 7 preserves legacy node credentials and adds expiring enrollment records, certificate identity/revocation and monotonic config sequences.
- Enroll with a node-local P-256 key and signed CSR; a 10-minute token can issue one identity and retry only the same CSR after a lost response. The agent state lock prevents concurrent enrollment or replacement while its supervisor runs.
- Native NGINX installation verifies node client certificates and overwrites certificate headers; the private proxy key prevents forged forwarding headers. Enrolled nodes reject old bearer tokens. Certificate renewal rotates keys, with one previous identity allowed a bounded ten-minute handoff; certificates live fourteen days and renewal starts seven days before expiry.
- Sign desired config with pinned Ed25519 verification, node identity, sequence and a sixty-second validity window. Persist verification state, reject tampering/replay/wrong-node messages and stop the engine through an independent expiry watchdog. A rejected candidate cannot extend the previous config's execution window.
- Include node CA/signing material in encrypted recovery bundles; restore and reload the proxy trust root. Preserve node-local private keys separately. Add Persian enrollment/revocation actions and a secure node guide.
- Real native acceptance now exercises the enrolled supervisor, signed config, renewal, API revocation and continued certificate authentication after control-plane recovery. Shared budget leases and rate-bounded quota enforcement remain a separate unfinished part of phase 3.

## 1.0.0-alpha.3 — continuation of merged main, 2026-10-16

- Continue from PRs #2–#6 without adopting the incompatible database schema of the earlier `development/1.0` branch. Schema 6 preserves existing users, device credentials and subscriptions; that earlier schema is explicitly refused.
- Encrypt MFA seeds using a separate private master key; migrate plaintext seeds, require password reauthentication for enrollment, persist security lockouts and revoke other sessions/API tokens on MFA transitions. Local CLI password resets now revoke API tokens too.
- PostgreSQL restores use one transaction; private safety copies and SQLite foreign-key/schema checks are enforced. Restored admin sessions and API tokens are invalidated. Invalid database URLs cannot silently select SQLite.
- Add verified native control-plane installation, local PostgreSQL provisioning, systemd/NGINX, HTTP-01 renewal, one-use first-owner setup, readiness, repair and data-preserving uninstall. Debian 12's Python 3.11 is supported. The earlier `app.installer` render scaffold remains available for compatibility.
- Add authenticated streaming AES-256-GCM bundles including DB/config/TLS/MFA key, daily backup timer, verification before service interruption and empty-target recovery. Preserve the backup encryption key separately. DB-only downloads do not contain the MFA key.
- Add usage-period history and generation-aware reports/journals. Late explicitly labeled reports stay in their old period; reset/rollover changes generation and restarts Xray before new counters are collected. Legacy unlabeled journals retain their previous attribution limitation.
- Add per-user selected/all node assignments, filtered node configs and subscriptions, Persian assignment/history UI, a typed engine boundary and durable apply-config jobs with matching node/revision acknowledgements. Job list APIs omit secret config payloads.
- Expand CI to Python 3.11/3.12, the full PostgreSQL suite, browser bootstrap/MFA/assignment flows and real native service/container acceptance on both target distributions.

This is a development preview, not stable 1.0. Public ACME/VPS/ISP acceptance, mTLS enrollment, signed desired config, shared-quota budget leases, DNS products and additional VPN engines remain outstanding; see the implementation status.

## Unreleased — panel visual redesign

- New neutral graphite design system for both themes: dark mode is no longer pure black, light mode uses a cool gray surface, and one muted teal is the only accent. Status colors are separate from the accent.
- Layout: fixed side navigation on desktop, bottom navigation on phones, a slim top bar with the page title and sync time. Login is a single centered card.
- Removed decorative text: all-caps labels, eyebrows above headings, middle-dot separators, arrows in link text, and glyph characters used as icons. Icons are inline SVG line icons.
- Tables, cards, badges, forms and dialogs share one set of tokens; numbers use tabular figures. The subscription portal uses the same tokens.
- No behaviour change: the same endpoints, IDs and actions. The browser smoke test was updated for the new status text.

## Unreleased — phase 2 (partial): PostgreSQL backend

- Optional PostgreSQL backend selected by `DONINO_DATABASE_URL=postgresql://…`. SQLite remains the default and needs no change. Install `requirements-postgres.txt` for the driver.
- Writers are serialized with a PostgreSQL advisory lock, which plays the role of `BEGIN IMMEDIATE`. Integer columns are 64-bit on PostgreSQL so byte counters cannot overflow.
- Schema version is kept in a `donino_meta` table on PostgreSQL and in `PRAGMA user_version` on SQLite.
- `backup`, `restore` and `doctor` work on both backends. PostgreSQL backups are `pg_dump` custom archives verified with `pg_restore --list`; restores use `pg_restore --clean --if-exists` and keep a `.dump` safety copy first. Requires the `postgresql-client` package on the panel host.
- `GET /api/backup` returns a `.dump` on PostgreSQL and a `.db` on SQLite.
- Tests run on SQLite by default. `DONINO_TEST_DATABASE_URL` runs the same suite against PostgreSQL (the public schema is recreated per test). CI runs both.

Not done in this entry: a PostgreSQL-side migration test from schema 2 or 3 (the upgrade path is tested on SQLite only), connection pooling, and installer support for provisioning PostgreSQL.

## Unreleased — phase 2 (partial): installer scaffold and operations CLI

- `python -m app.installer preflight|plan|render --domain D [--root DIR]`: read-only preflight (OS, architecture, Python, ports, disk, DNS), a secret-free plan, and render of the panel env file (0600), systemd unit and NGINX vhost under a root directory. Locked, resumable, and it refuses to overwrite files that differ (exit 7). Exit codes follow the installer spec.
- Services, NGINX reload, certificates and firewall are not changed by this slice.

## Unreleased — phase 2 (partial): operations CLI

- `python -m app.cli doctor`: read-only health report (database permissions, schema version, integrity check, owner account, public URL and cookie settings). Exits 1 on any failure. Never prints secrets and never migrates the database.
- `backup DEST`: consistent SQLite copy plus `DEST.manifest.json` with SHA-256, schema version and app version. Refuses to overwrite.
- `restore SRC [--replace]`: refuses unless the manifest checksum, schema version and integrity check all pass. Keeps a timestamped safety copy of the current database before replacing it. Stop the panel service first.

Not done in this entry: the interactive installer, ACME/SSL automation, NGINX generation, port ownership checks and the upgrade state machine.

## Unreleased — phase 1 (complete except PostgreSQL and node-side mTLS): security, devices, schema 4

- Schema 3 (`PRAGMA user_version=3`) with a private pre-migration backup. Every existing user gets one default device whose id equals the user id and whose secret equals the legacy credential, so Xray client emails, counter baselines and subscription links are unchanged and no node restarts because of the upgrade.
- Devices: each user can have up to 20 devices, each with its own Xray credential, enable/disable, rotation and per-device traffic totals. The default device cannot be deleted. Disabling or rotating a device uses the existing full-restart revocation path.
- Admin two-factor authentication (TOTP, RFC 6238) with ten single-use recovery codes, replay protection per time step and the shared login lockout.
- Scoped API tokens (`read`, `users`, `full`) stored as digests, with expiry and revocation. Token scopes cannot reach account-security or owner-only endpoints.
- Session metadata: list, revoke one, revoke others. Password change revokes other sessions and API tokens.
- Paginated `/api/users` with `limit`, `offset`, `q` (literal substring) and `state`, returning `X-Total-Count`. Without `limit` the legacy response is kept.
- Node agents from 0.2 keep working: the heartbeat accepts the Xray client id, which is the device id for the default device.

- Schema 4: monthly usage periods. A period starts at the user's first recorded usage and resets used, uploaded and downloaded totals when it ends, keeping counter baselines so old bytes are not billed again. Period counter `period_no` increments on each reset. Switching the period clears the cycle start.
- Administrator management for owners: list, create, change role, reset password and delete. The last owner cannot be demoted or deleted, and nobody can delete their own account. Role changes and password resets end that admin's sessions and API tokens. These endpoints require a browser session, not an API token.
- Users page uses server-side search (literal substring), state filter and paging of 25 rows.

Not done in this entry: PostgreSQL, mTLS, node assignment, budget leases, per-device subscription links, and late-report protection for periods. Late-report protection needs the agent to send the time each sample was taken; until then, bytes sampled before a reset but reported after it count toward the new period.


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
