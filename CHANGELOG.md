# Donino releases

## 1.0.0-alpha.12 — independent Smart DNS exit installation, 2026-10-18

- Add `install.sh --role smart-exit` with a dedicated service account, immutable verified releases and private stable gateway credentials; no control-plane database is installed.
- Add HTTP-01/Certbot or existing TLS, safe certificate delivery to the service user, renewal/readiness rollback, plan/doctor/repair/upgrade and preserving uninstall.
- Preserve exit mode, allowlist and credential on upgrades; refuse occupied listeners, modified/unmanaged files and mixed role options. No host firewall/routes are changed.
- Add independent Debian/Ubuntu service acceptance and focused failure/rollback tests. Public ACME, WAN/game acceptance, credential rotation/distributed configuration and remaining v1 protocols are still open.

## 1.0.0-alpha.11 — managed Smart DNS HTTPS routing, 2026-10-18

- Add opt-in SNI passthrough through authenticated TLS exit nodes, ordered primary/two fallback routes and per-domain exceptions; fail closed without a direct fallback.
- Add source-IP ownership, independent relay byte quotas and connection limits, draining, live authorization guards, sealed exit credentials and restore invalidation (schema 13, pre-migration backup).
- Add Persian node/routing/catalog/quota forms and optional native NGINX stream frontend sharing public 443 with the verified panel HTTPS/mTLS backend. Remote exits are explicitly provisioned.
- Exercise real UDP DNS → TLS passthrough → two exits/origins, switching, carrier loss, TLS/auth refusal, quota and revocation. Gaming/WAN/public ACME and stable-v1 acceptance remain open.

## 1.0.0-alpha.10 — real tunnel VPN verification and leased endpoints, 2026-10-18

- Add owner-only real Mihomo acceptance against an operator-configured HTTPS target, with TLS verification at both layers, a known bounded response digest, private temporary credentials and no direct fallback or HTTP redirects.
- Bind durable verification receipts to the installed plan/job, origin revision and active device. Publish only tested inbounds as additional subscription endpoints, with explicit confirmation and a 24-hour lease. Retesting, replacement and restoration withdraw previous affected publications; changed origins and expired leases are filtered from future exports.
- Add schema-12 pre-upgrade backup, Persian verification/publication UI and real loopback FRP WSS/QUIC + Xray/Mihomo acceptance for all six TLS profiles, abrupt carrier loss, failover, restart and failure withdrawal. No real VPS/ISP/public-ACME or continuous health guarantee is inferred.

## 1.0.0-alpha.9 — verified Mihomo and durable tunnel plans, 2026-10-18

- Fix Trojan Mihomo SNI export (`sni`), including the existing TCP profile. All six TLS profiles now pass real-client transfer, CA/hostname rejection, device accounting and revocation without expected failures.
- Pin the Mihomo fetcher and real-client CI on SQLite/PostgreSQL. Preserve the Claude handoff and suspend further Claude work at the user’s request; Codex continues.

- Add schema-11 durable tunnel plans compiled from selected node/inbounds, with revision/expiry/peer guards, atomic start claims, lost-response reconciliation and restored preview UI. Application verification and automatic endpoint publication remain separate gates.
- Back up schema 10 before migration; preserve job history after node deletion and refuse restore over binding history.

## 1.0.0-alpha.8 — Claude handoffs and local tunnel bridge, 2026-10-18

- Add root Claude/shared instructions, assigned task and persistent resumable checkpoints with a validating atomic-write CLI. Completed Claude work waits in a review PR; no live cross-chat messaging or limit reset is claimed.
- Add an opt-in owner-only local Unix-socket Donino Tunnel bridge for pinned HTTPS pairing, connection checks, private two-node previews and durable installation jobs. Initially exposes TCP services over FRP WSS/QUIC, with whitelist responses and redacted validation errors.
- Add Persian tunnel setup/status UI, explicit whole-set replacement review, plan invalidation after edits and form-preserving background refresh. Initial role installation and automatic subscription endpoint binding remain separate work.
- Pin a real Donino Tunnel worker/renderer contract in CI; record Hashem architecture research without importing its implementation. No Iran/VPS/carrier-transfer acceptance is claimed by the contract fixture.

### Xray WS and gRPC transports (reviewed Claude PR #13)

- Add VLESS over WebSocket+TLS, VLESS over gRPC+TLS, VMess over gRPC+TLS and Trojan over WebSocket+TLS. The existing VLESS REALITY/Vision, VMess WS+TLS and Trojan TCP+TLS are unchanged. Transport and gRPC service name are stored in the existing inbound settings; there is no schema or migration change.
- Subscription URIs, VMess base64 JSON and Mihomo proxies are emitted for each new transport. Vision flow is applied only to REALITY/TCP.
- The inbound form selects the transport per protocol and shows only the fields it needs.
- Real pinned-Xray acceptance covers encrypted transfers for two devices, per-device accounting, device and user cut-off, quota exhaustion, period reset, and rejection of a client that does not trust the test CA.
- Not claimed: real Mihomo, v2rayN or sing-box client import, live client additions on the new transports, and expiry-based cut-off.

## 1.0.0-alpha.7 — doctor-dns catalog and staged import, 2026-10-18

- Bundle the pinned MIT doctor-dns catalog with attribution: 42 services, 48 groups and 505 domains. Owners can build independent DNS rewrite policies from selected groups and explicit relay addresses; no relay is installed or claimed by this action.
- Add read-only source inspection, fingerprint confirmation, private pre-action backups and transactional, idempotent staging of doctor-dns accounts and templates. Preserve original Smart DNS byte totals, periods, expiry and private source metadata without converting them into DNS-query quotas, VPN usage or active wallet credit.
- Keep imported accounts/devices disabled, refuse normal API activation, and require new proof before any source-IP permission. Source sessions are omitted. Password/receipt archives are encrypted with the existing private master key.
- Add selective rollback that refuses changed users/related data, owner-only import metadata, catalog controls in the Persian DNS UI and a concrete Claude handoff for independent Xray transport work.

Live Smart DNS relay/exit, game/ISP acceptance and operational activation of staged imports remain unfinished. This is a prerelease, not stable 1.0. See [catalog and import](docs/DOCTOR-DNS-IMPORT.fa.md).

## 1.0.0-alpha.6 — authenticated DNS preview, 2026-10-16

- Add DNS policies with suffix priority, block/allow and A/AAAA rewrites; isolate caches by policy revision and DNSSEC flags, inspect aliases/targets, clear AD on synthesized answers and bound negative caching and UDP response size.
- Add independent DNS accounts, hashed/rotatable DoH credentials, transactional query quotas, shared per-account rate windows, byte/error/block counters and historical periods. Proof from the portal's actual public source address grants expiring IP leases; shared-IP ownership conflicts are refused.
- Add authenticated RFC 8484 DoH and an optional same-host UDP/TCP/DoT gateway backed by a dedicated validating Unbound. `--with-dns` installs private listeners by default; explicit public binds preserve existing resolvers and refuse occupied ports. Certificate pairs switch atomically, and the unprivileged service receives them over a private pipe.
- Add Persian DNS management and guest controls, disable managed Uvicorn access logs, and extend browser, real DNSSEC, native service and backup/restore acceptance.

This remains a preview: DoQ, remote DNS nodes, Smart DNS relay/exit, doctor-dns import, game/ISP acceptance and capacity testing are unfinished. DNS query bytes are separate from VPN/game traffic. See [DNS setup and limits](docs/DNS-PREVIEW.fa.md).

## 1.0.0-alpha.5 — experimental shared quota, 2026-10-16

- Add opt-in shared-quota users with transactional per-node/per-supervisor budget reservations, signed 60-second execution windows and a persistent local budget ledger. Expired, unreported credit stays reserved instead of being allocated again.
- Meter enrolled nodes independently of panel HTTP requests and stop Xray when a grant is exhausted, expired or cannot be accounted locally. Bind the Linux engine process lifetime to its supervisor. A clean, fully reported shutdown releases unused credit; an unknown crashed instance does not.
- Preserve duplicate/out-of-order usage handling and period isolation, retain observed overshoot, guard quota reductions/node deletion and expose reservation metadata in the Persian panel and portal.
- Add concurrent allocation/journal, closed-grant, identity, period and parent-death checks, plus an actual encrypted VMess transfer that exhausts a grant while the control plane is unreachable and reconciles after reconnection.

This feature is experimental and available only for newly created users and enrolled agents. Sampled metering can overshoot, unsampled crash traffic can be lost, and stopping one exhausted grant currently stops the whole node core. Rate enforcement, capacity testing and stable 1.0 acceptance remain outstanding. See [shared quota](docs/SHARED-QUOTA.fa.md).

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
