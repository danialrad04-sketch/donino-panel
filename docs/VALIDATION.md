# Validation record

## Smart DNS HTTPS routing and native SNI frontend — 2026-10-18

The final integrated local suite discovered **227 checks: 225 passed, 2 skipped** with pinned real Xray, Mihomo, FRP and the Unix worker enabled. The skips are the PostgreSQL-specific restore fault and local real Unbound; dedicated CI provides those environments.

Schema 13 adds sealed TLS exit credentials, per-account relay entitlement/quota/concurrency, separate period byte counters, immutable session periods and a live gateway lease. Seventeen focused API/DB/framing/network checks passed. They exercise actual UDP DNS and verified HTTPS through a real gateway and two TLS-authenticated exits/origins, policy switching, first-exit loss, both-exit failure without DIRECT, quota exhaustion, expiry/revision revocation, bad CA/auth, ECH/duplicate SNI refusal, IP ownership, atomic concurrent reservations, pending-fallback lease renewal and migration/restore invalidation. Only the network fixture injects loopback origin resolution/dial ports; the production resolver's all-public, single-resolution destination restriction is tested separately.

Both Debian 12 and Ubuntu 24.04 isolated systemd/NGINX/PostgreSQL fixtures passed installation, reinstallation, restart, encrypted backup, second-host DB/MFA/PKI restoration and data-preserving uninstall. Debian converts the original 443 TLS listener to the SNI frontend on reinstall; Ubuntu installs Smart DNS from the start. Real panel TLS and mTLS enrollment/renewal/revocation still pass. An additional native assertion sends panel SNI to the verified panel backend and rejects unauthorized non-panel SNI through the Smart gateway. The edge-to-origin transfer test is a separate loopback fixture; no public game/WAN/public-ACME acceptance is inferred. The standalone exit role is explicitly provisioned, not automatically installed by the native control-plane installer.

Chromium acceptance passed creating exits, a simulated TLS/auth probe observation, activation with retained private credentials, ordered routes, raw rule round-trip, managed catalog policies, independent quota/concurrency, preservation through ordinary DNS account editing and a 390px routing form. Actual TLS/auth exchange is covered by the separate real-network fixture. Existing portal/MFA/subscription/tunnel/mobile flows, no third-party requests and no JavaScript errors still pass. Ten installer unit checks cover option/conflict handling, runtime-only heartbeat during empty restore and two-file NGINX rollback. Native restore now pauses active Smart/DNS services, and a runtime heartbeat alone does not make an otherwise empty destination nonempty.

Byte accounting measures TLS bytes admitted before each write in both directions; a failed write can retain its reservation. It is independent of DNS queries and VPN counters, not provider wire billing or UDP game traffic. Gateway readiness expires after ten seconds and synthesized DNS TTL is thirty seconds. The existing global DB writer lock and per-chunk transactions need capacity acceptance. Remote role provisioning/rotation, retention, UDP/ECH/HTTP3 support, game/ISP tests and remaining engine/release phases remain open. See [setup and limits](SMART-DNS.fa.md). Exact-commit full-suite/CI results are recorded in the PR/release before publication.

## Real tunnel VPN verification and leased publication — 2026-10-18

Schema 12 adds durable real-client acceptance receipts and additive, 24-hour subscription endpoint leases. The integrated local suite discovered 207 checks: 205 passed with real pinned Xray, Mihomo, FRP and the Unix worker enabled; the PostgreSQL-only restore fault and local real Unbound checks were skipped. The final opt-out delta passed all 11 focused endpoint tests; all six HTTPS/watchdog/parent-death tests passed. Dedicated CI provides PostgreSQL/Unbound and repeats the final commit before publication. Exact-commit results are attached to PR #19 and the release. The production verifier also passes focused tests for authenticated loopback SOCKS, verified HTTPS, unknown CA/name rejection, refused redirects, response-size and slow-drip deadlines, operator-only destination configuration and Linux parent-death cleanup.

The dedicated real-carrier fixture uses reviewed Donino Tunnel `4c19214598d32bd2868f9f46030d8a5dbd494d97`, verified FRP v0.71.0 binaries, pinned Xray and pinned Mihomo. It renders two roles, runs actual WSS/QUIC, the mutual-TLS front, framed relays and gateway on loopback, and transfers all six TLS VPN profiles. Tests kill the actual WSS processes, verify all six profiles over QUIC, restart WSS and transfer again, reject an invalid VPN SNI, then stop both carriers and refuse further publication. Agent reports reach the original device and user counters. The control job state is simulated in this fixture; the real Unix-worker contract remains separate. It is a single-host network test, not two-VPS installation or a WAN benchmark.

API/DB tests cover source and credential changes during I/O without a held DB writer lock, one concurrent verifier, revoked/expired devices and fresh-proof deadlines, node assignment filtering, explicit owner-only publication, added URI/Mihomo output without changing the origin SNI/credential, lease expiry, idempotent withdrawal, failed-retest withdrawal, both manual/bound replacement invalidation, external worker/peer/history changes, schema-11 backup/failure-before-DDL and invalidation during SQLite/PostgreSQL restoration. Browser acceptance covers device selection, verify/confirm/publish/withdraw and 390px layout alongside previous flows.

A successful receipt is point-in-time evidence for selected inbounds and the gateway path actually used. It does not prove every carrier, continuous health, shared-lease quota support, REALITY in this verifier, public ACME, gaming, ISP reachability or stable 1.0. Out-of-panel worker changes are detected on the next worker observation; existing downloaded client configs are not revoked by withdrawing an endpoint. Public two-VPS tests, initial role provisioning and safe automatic monitoring/lease renewal remain open. See [setup and limits](TUNNEL-BRIDGE.fa.md).

## Durable inbound-bound tunnel plans — 2026-10-18

Schema 11 adds persistent node/inbound-to-plan bindings. The final local integrated suite discovered 189 checks: 187 passed with real pinned Xray, Mihomo and the Unix-socket tunnel worker enabled. Two environment-specific checks (PostgreSQL restore fault injection and real Unbound) were skipped locally; dedicated CI provides those environments. After correcting Mihomo startup readiness to wait for its post-up running state, all nine real Mihomo tests passed again. Remote results for the final commit are recorded on PR #18 before publication.

Binding coverage checks DB-derived targets and metadata privacy, preservation across reinitialization, changed port/settings/disabled or removed origins, mutation during worker preview, expiry/peer drift and raw-start bypass refusal, single concurrent start, recovery of a lost start response by plan/job identity, refusal of substituted worker targets/jobs, schema-10 upgrade backup and failure-before-DDL. Restore also refuses an otherwise empty destination that still contains binding history.

The pinned real Unix worker contract now builds both manual and inbound-bound two-role plans, checks generated private files and confirms stale-origin rejection before any install. Service identity uses the complete inbound UUID encoded within the pinned worker's 32-character limit. Chromium acceptance covers panel selection, DB target planning, persistent preview re-review, explicit replacement, manual mode and 390px layout, alongside existing portal/DNS/account flows.

These are plan/control acceptance results. No carrier transfer, real two-VPS install, automatic subscription endpoint cutover, game/ISP/public ACME acceptance or independent active-path health is inferred. Worker `succeeded` remains installation history; application verification and endpoint publication are explicitly false.


## Claude coordination and local tunnel bridge — 2026-10-18

New coverage validates task/checkpoint matching, safe paths, review evidence, atomic JSON checkpoints, owner/scope and opt-in boundaries, strict typed service specs, explicit boolean replacement confirmation, rejected command/path/experimental inputs, redacted validation and worker errors, bounded/redirect-free transport, socket ownership and no automatic retry of an uncertain mutation.

The pinned Donino Tunnel `4c19214598d32bd2868f9f46030d8a5dbd494d97` worker runs on a real Unix socket in the contract fixture. Real renderer/OpenSSL output produces a private two-node FRP WSS + QUIC plan; loopback destination, both paths, key file privacy and response credential omission are checked. Host service discovery is stubbed. No carrier is installed and no Iran/foreign VPN traffic is claimed by this fixture. The dedicated `tunnel-contract` CI job fetches this exact source revision.

Chromium acceptance passed for the disabled integration view and a simulated enabled controller: plan preview, edit invalidation, explicit replacement confirmation, job status and 390px layout. Existing admin, DNS, portal, MFA and theme flows still pass with no JavaScript errors or third-party requests. The enabled browser fixture validates UI behavior; it is separate from the real worker contract test. Local full-suite and exact-commit remote results are recorded in the release/PR checks before publication.

Initial two-role installation, automatic subscription endpoint binding, least-privilege worker isolation, two-node install/restart/partition acceptance and real ISP/ACME/game validation remain open. Coordination is Git-based asynchronous handoff; it cannot automatically resume a rate-limited chat or recover uncommitted work from another machine.

## doctor-dns catalog and staged migration — 2026-10-18

The local SQLite suite discovered 150 checks and passed with the PostgreSQL-only restore fault and optional real Unbound checks skipped. Seven new cases cover the full 505-domain catalog, unknown-group refusal and owner permissions, read-only/deterministic source inspection, preserved source byte units and private archives, unrecognized hashes/shared-IP conflicts, idempotent staging, pre-action backup failure, transactional rollback on a mid-import identity conflict, selective rollback and refusal after target changes. Normal account activation is refused for staged users.

Chromium acceptance passed for catalog group selection, DNS policy creation and the owner import view, including the catalog form at 390px. A header overflow discovered during this check was corrected with wrapping; existing admin, guest DNS, VPN, MFA and theme flows still pass with no page JavaScript errors or third-party requests. The commit CI repeats Python 3.11/3.12, PostgreSQL, real Xray/Unbound and both native OS fixtures before merge.

The supported format was read from doctor-dns commit a2b2ff843cb1fc8f0a5712a88149f5c379198ff1; integration fixtures contain generated users, timestamps, counters and receipt bytes, not a real customer's production database. Imported accounts/devices remain disabled and source sessions are not copied. No active wallet/password/IP permission, live Smart DNS relay, game/ISP acceptance or automatic service cutover is claimed. See [catalog and staged import](DOCTOR-DNS-IMPORT.fa.md).

## Authenticated DNS preview — 2026-10-16

Schema 9 adds independent DNS policies, accounts, source-IP leases and query/byte periods. The local full suites discovered 143 checks: SQLite/Python 3.12 passed with the PostgreSQL-only restore fault and optional Unbound checks skipped; PostgreSQL 16/Python 3.11 passed with nine SQLite-only checks skipped and actual Unbound enabled. The added checks cover concurrent quota admission, shared account rates, delayed-period responses, private credential rotation, proof/conflict/expiry of source IPs, policy/cache isolation, explicit allow exceptions, CNAME, A/AAAA, negative TTL, TCP fallback, UDP truncation and atomic TLS-pair replacement without damaging the previous pair.

A real Debian Unbound 1.17.1 validates a generated signed private zone, sets AD on a valid answer and returns SERVFAIL for a deliberately invalid signature. Authenticated DoH preserves that result and clears AD for a policy rewrite. Browser acceptance passed for policy creation, DNS account activation, guest quota/IP controls and mobile navigation alongside prior VPN/MFA flows. No third-party browser requests or page JavaScript errors were observed.

Native acceptance passed on Debian 12 and Ubuntu 24.04 with optional Unbound and the gateway, actual verified HTTPS DoH, source-leased UDP/TCP/DoT, refusal after lease deletion, same-host reinstall and second-host preservation of DNS accounts during encrypted recovery. Ubuntu uses standard ports 53/853 and Debian the private defaults. The final CI commit repeats both fixtures and all six jobs. A local test CA is explicitly trusted; public ACME, public recursive reachability, ISP/game behavior, DoQ, remote DNS deployment and capacity are not established. See [DNS setup and limits](DNS-PREVIEW.fa.md).

## Experimental shared quota — 2026-10-16

Schema 8 adds nine checks to the previous 122: eight reservation/accounting tests and a real Linux parent-death test. SQLite/Python 3.12 passed the 131 discovered checks with the PostgreSQL-only restore fault check skipped. PostgreSQL 16/Python 3.11 passed the same suite with nine SQLite-only checks skipped, including the real offline-budget transfer. Concurrent allocation cannot duplicate the same remaining credit; expired unknown reservations remain held, reports bind to the allocated node/period, positive growth after closure is refused, late periods remain isolated and concurrent journal snapshots do not double-charge local totals.

The pinned Xray acceptance now additionally enrolls a real supervisor identity, starts an encrypted VMess client, makes the control-plane transport unavailable before transfer and verifies local grant exhaustion stops the real Xray core. Reconnection retains and reconciles the observed sampled overshoot. Browser acceptance passed for shared-quota creation/reservation display alongside existing portal, mobile, theme and security flows. Debian 12 native acceptance passed; both native operating-system fixtures are checked before publication; consult the exact commit checks for final remote results.

These checks establish conservative reservation accounting and the exercised failure paths, not a strict global byte cap. Sampling and process shutdown can overshoot, unsampled crash traffic can be lost, and exhaustion currently stops the whole core. Unreported crashed-instance credit is held until explicit reconciliation or a new period. Public multi-host partition tests, rate bounds and capacity remain outstanding. See [shared quota](SHARED-QUOTA.fa.md).

## Secure node identity — 2026-10-16

Schema 7 and the node identity/signing slice add seven checks to the previous 115: 122 tests discovered, SQLite passing with the PostgreSQL-only restore fault check skipped; PostgreSQL passing with nine SQLite-only checks skipped. New tests exercise concurrent same-CSR enrollment retries with one certificate issuance, expiry/rate limits/owner access, retirement of bearer credentials, forged proxy headers, API revocation, bounded rotation overlap, private identity writes and replay/tamper/expiry/wrong-node rejection. Agent tests verify that an independent watchdog stops the core and that a candidate cannot extend the previous config's lifetime. Enrollment is refused while the supervisor holds the state lock.

Native acceptance passed on Debian 12 and Ubuntu 24.04 with actual NGINX client-certificate verification, pinned signed configuration, certificate/key renewal, an enrolled supervisor reporting over HTTPS, restoration of CA/signing keys on a second control host and API revocation of the recovered node certificate. Header-spoofing requests and old bearer credentials are refused through the real proxy. Public ACME/VPS/ISP acceptance remains separate. The existing browser regression also passed; exact-commit CI reruns all six jobs before merge.

These checks do not establish shared budget leases, hard byte-level multi-node quota enforcement, automatic node-role installation, public CRL distribution or unattended trust-root rotation. See [node security](NODE-SECURITY.fa.md).

## Main continuation and 1.0 alpha 3 — 2026-10-16

Continued merged main through PRs #2–#6 and integrated the newer redesign from PR #7. The incompatible earlier `development/1.0` data model is refused explicitly. This entry records executed checks, not completion of the entire master plan.

- SQLite/Python 3.12: 115 discovered tests, 114 passed and the PostgreSQL-only fault-injection test skipped. Includes real pinned Xray VLESS/VMess/Trojan transfer, live additions, active quota revocation, rollback after occupied-port startup, and a real period reset followed by new VMess traffic charged to the new period.
- PostgreSQL 16/Python 3.11: the same 115 tests, 106 passed with nine SQLite-only checks skipped. Includes a deliberately failing `pg_restore` via an event trigger: earlier DDL and existing user data survive because the restore transaction rolls back. The disposable database is isolated from panel fixtures.
- Added checks for encrypted/migrated MFA seeds, enrollment password and committed lockouts, revocation of other sessions/API tokens on MFA transitions, CLI token revocation, rejection of a non-Bearer header attempting to skip cookie CSRF protection, unknown backend refusal, and explicit refusal of the incompatible development schema.
- Added checks for streaming encrypted backup tampering/wrong keys/no overwrite, DB+MFA restoration into an empty target and preservation of a populated target/key after refusal.
- Accounting checks cover out-of-order old-period delivery after new-period traffic, duplicate reports, immutable process/device generation, rejection of invented periods without updating baselines, durable journal generations and a mandatory core restart at a generation boundary.
- Assignment checks cover filtered node configs and actual subscription contents, transactional refusal of an unknown node and viewer denial. Deployment checks cover restart persistence, superseding, failed/retried jobs, node/revision-matched ACKs and omission of credential payloads from list APIs.
- Chromium/Playwright acceptance passed after integrating the redesign: one-use owner setup and URL-fragment removal, user/inbound editing, node selection, period history, password-confirmed MFA enrollment and one-time recovery display, separate guest portal, local QR, themes, logout and 390px overflow checks. No page JavaScript errors. Screenshots are taken before MFA secrets are displayed.
- Native acceptance passed on both Debian 12 (Python 3.11/PostgreSQL 15) and Ubuntu 24.04 (Python 3.12/PostgreSQL 16): real systemd/NGINX/PostgreSQL installation, same-domain reinstallation, container restart, HTTPS verified against an explicit local test CA, expiring/one-use first owner, encrypted backup, installation on a second empty host, DB+MFA-key restore, real second-factor login and uninstall preserving user data. Fixture containers use their own network and cgroup namespace and share the host kernel.
- Python unused-import checks, JavaScript syntax, source-manifest generation/check and `git diff --check` passed. CI also runs both Python 3.11/3.12 API suites, PostgreSQL, browser and both native target OS fixtures; consult the check attached to the commit being reviewed for remote status.

Public Let's Encrypt issuance/renewal, external VPS/VM behavior, real ISP/console/game acceptance, load/chaos/DR, mTLS enrollment, signed desired config and shared quota leases were not validated here. Existing global PostgreSQL writer serialization and unlabeled legacy usage attribution remain documented limits. DNS/gaming and additional engines are not claimed as implemented. See [actual phase status](IMPLEMENTATION-STATUS.fa.md) and [native preview instructions](INSTALLER-PREVIEW.fa.md).

## Phase-zero planning documents — 2026-10-15

The 1.0 planning update is documentation only; the executable product remains 0.2.0. The six linked Persian planning documents define 39 feature rows, 22 protocol/family rows and 26 acceptance scenarios. These are requirements, not completed runtime features or executed future tests.

Local verification passed: `git diff --check`, local Markdown file/image links and the cross-document heading anchor, balanced fenced blocks, unique requirement IDs, requirement/test reference resolution and JSON parsing with 40-character commit pins for five additional research repositories. Source files named in the supplementary snapshot were checked for existence in the read-only research checkouts. No upstream installer was executed and no upstream source was imported.

These document checks do not establish PostgreSQL, mTLS, gaming DNS, additional VPN engines, automatic SSL or production deployment. Existing runtime regression CI remains separate from the phase-zero document checks. See [the master plan](MASTER-PLAN.fa.md) and [future acceptance contract](ACCEPTANCE-TESTS.fa.md).

## Phase 1 partial, second pass — 2026-10-16

Added schema 4 (monthly periods), owner-only administrator management and server-side paging of users. Local checks: `python -m unittest discover -s tests` passed with 70 tests, including period rollover, reactivation after a period ends, the last-owner rules and token refusal for admin management. Browser checks at 390px confirmed paging (25 per page), search keeping focus, the period field, the admin card and admin creation, with no JavaScript errors. The real Xray test with the pinned v26.3.27 binary also passed on the same tree.

## Phase 1 partial — working tree, 2026-10-16 (merged as PR #2)

Changes: schema 3 with devices, admin TOTP and recovery codes, scoped API tokens, session management, paginated users and a device/security UI. Checks run locally on Python 3.13 with the pinned requirements:

- `python -m unittest discover -s tests`: 59 tests passed (34 earlier checks, 25 new in `tests/test_accounts.py`, including a v3 upgrade test and a future-schema refusal).
- `DONINO_TEST_XRAY=<pinned v26.3.27 binary> python -m unittest discover -s tests`: all 59 passed, including real VLESS/VMess/Trojan transfer and revocation.
- `tests/browser_smoke.py` passed with the existing admin, portal, mobile and theme checks. A separate headless check of the new device list, device creation, security panel and one-time token display passed at 390px with no JavaScript errors.

Not verified here: GitHub Actions, PostgreSQL, a real VPS, external TLS, and third-party client import. Node agents from 0.2 were not run against this panel.

## Version 0.2 runtime validation

Version 0.2 was checked on 2026-10-15 with Python 3.12, Chromium via Playwright 1.62.0 and Xray v26.3.27 (pinned release asset SHA-256 in `scripts/fetch_xray.py`). All 34 API/agent/journal/migration/Xray checks passed using the repository dependencies; the expanded browser acceptance check also passed.

- API tests exercise authentication, CSRF, roles, rate limits, input validation, token rotation, subscription formats, expiry, quota, concurrent duplicate traffic reports and SQLite backup readability.
- Real Xray test starts both ends of VLESS/REALITY, VMess/WebSocket/TLS and Trojan/TLS and passes HTTP response data through SOCKS into each encrypted transport. It keeps an encrypted stream open across a live user addition, verifies the unchanged server PID/epoch and Xray user counts on all three protocols, checks quota revocation restarts the core, and induces an actual occupied-port startup failure to verify recovery of the previous config.
- Journal and integration tests preserve snapshots across restart, exercise lost HTTP acknowledgements after the panel has processed usage, ensure replay does not double-charge, split large snapshots into bounded batches and reject reuse by another node/origin.
- Migration tests upgrade an actual 0.1 schema fixture, preserve credentials/tokens/totals, read the pre-migration backup, reject future schemas and abort on backup failure.
- Browser acceptance covers admin flows, inbound editing, local QR image loading, a customer portal in a separate context without admin cookies, no third-party requests from the portal, theme switching and overflow checks at a 390px viewport. Screenshots use isolated disposable fixtures, including temporary non-operational subscription credentials.
- JavaScript syntax and Python compilation were checked.

The systemd and Nginx files are deployment templates; they were not installed on an external VPS during this session. External TLS issuance, real-domain reachability, scanning QR codes in every third-party client and load tests were not performed. GitHub Actions results are recorded separately by GitHub; a local passing result is not a claim that remote CI has run.
