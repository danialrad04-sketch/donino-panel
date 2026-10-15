# Validation record

## Native installer development checkpoint — 2026-10-15

All 54 local unit/integration checks passed with real PostgreSQL 16 and Xray. Added checks cover atomic first-owner enrollment, expiry/rate limiting, DB readiness without error-detail leakage, actual OpenSSL certificate identity/key validation and reload rollback, streaming backup authentication/tampering, DB+MFA-key restoration with admin-session revocation, and bounded source-archive integrity/extraction. Expanded Chromium acceptance also passed first-owner browser setup and the previous foundation/portal/mobile flows.

Real OS service acceptance passed on isolated privileged systemd containers for Debian 12/PostgreSQL 15 and Ubuntu 24.04/PostgreSQL 16. Each performed install, repeated installation, container restart, verified HTTPS using a temporary local test CA, one-use bootstrap, user preservation, encrypted backup, recovery into a separate clean container with working TOTP, and data-preserving uninstall. These containers share the execution host's kernel; they are not independent VMs or proof of external VPS behavior. Public Let's Encrypt issuance/renewal, provider firewall reachability and real ISP/game tests remain unperformed. The same service acceptance is now part of CI; its remote result is recorded by GitHub separately.

Python 3.11.17 also passed the 44-check foundation suite before the installer increment; the native Debian service runs its distribution Python 3.11.2. New CI executes the full unit suite on Python 3.11 and 3.12. No production server, domain, payment endpoint or customer data was used.

## Development foundation checkpoint — 2026-10-15

The phase-one increment was checked locally with PostgreSQL 16 in an isolated Docker service, Xray v26.3.27 and Chromium. All 44 unit/integration checks passed, including three actual PostgreSQL scenarios: concurrent duplicate accounting and cascade deletion, SQLite-to-PostgreSQL identity/legacy-usage preservation, and consistent archive restore into another schema with sequence continuity. Seven new foundation scenarios cover device credentials and revocation views, selective assignment/subscription filtering, explicit late-period accounting, first-use validity, concurrent master-key creation, TOTP/recovery and scoped-token isolation, plus non-destructive SQLite import. The existing 34 checks remain passing.

Expanded browser acceptance passed devices, node assignment, scoped-token creation, MFA enrollment and recovery login alongside the previous portal/mobile/QR checks, with no JavaScript errors. Python lint and JavaScript syntax checks passed. These results do not establish end-to-end period-aware node reporting, distributed budget enforcement, external TLS issuance, new protocol engines or production capacity. The matching master key remains a separate backup requirement; see [implementation status](IMPLEMENTATION-STATUS.fa.md).

## Phase-zero planning documents — 2026-10-15

The 1.0 planning update is documentation only; the executable product remains 0.2.0. The six linked Persian planning documents define 39 feature rows, 22 protocol/family rows and 26 acceptance scenarios. These are requirements, not completed runtime features or executed future tests.

Local verification passed: `git diff --check`, local Markdown file/image links and the cross-document heading anchor, balanced fenced blocks, unique requirement IDs, requirement/test reference resolution and JSON parsing with 40-character commit pins for five additional research repositories. Source files named in the supplementary snapshot were checked for existence in the read-only research checkouts. No upstream installer was executed and no upstream source was imported.

These document checks do not establish PostgreSQL, mTLS, gaming DNS, additional VPN engines, automatic SSL or production deployment. Existing runtime regression CI remains separate from the phase-zero document checks. See [the master plan](MASTER-PLAN.fa.md) and [future acceptance contract](ACCEPTANCE-TESTS.fa.md).

## Version 0.2 runtime validation

Version 0.2 was checked on 2026-10-15 with Python 3.12, Chromium via Playwright 1.62.0 and Xray v26.3.27 (pinned release asset SHA-256 in `scripts/fetch_xray.py`). All 34 API/agent/journal/migration/Xray checks passed using the repository dependencies; the expanded browser acceptance check also passed.

- API tests exercise authentication, CSRF, roles, rate limits, input validation, token rotation, subscription formats, expiry, quota, concurrent duplicate traffic reports and SQLite backup readability.
- Real Xray test starts both ends of VLESS/REALITY, VMess/WebSocket/TLS and Trojan/TLS and passes HTTP response data through SOCKS into each encrypted transport. It keeps an encrypted stream open across a live user addition, verifies the unchanged server PID/epoch and Xray user counts on all three protocols, checks quota revocation restarts the core, and induces an actual occupied-port startup failure to verify recovery of the previous config.
- Journal and integration tests preserve snapshots across restart, exercise lost HTTP acknowledgements after the panel has processed usage, ensure replay does not double-charge, split large snapshots into bounded batches and reject reuse by another node/origin.
- Migration tests upgrade an actual 0.1 schema fixture, preserve credentials/tokens/totals, read the pre-migration backup, reject future schemas and abort on backup failure.
- Browser acceptance covers admin flows, inbound editing, local QR image loading, a customer portal in a separate context without admin cookies, no third-party requests from the portal, theme switching and overflow checks at a 390px viewport. Screenshots use isolated disposable fixtures, including temporary non-operational subscription credentials.
- JavaScript syntax and Python compilation were checked.

The systemd and Nginx files are deployment templates; they were not installed on an external VPS during this session. External TLS issuance, real-domain reachability, scanning QR codes in every third-party client and load tests were not performed. GitHub Actions results are recorded separately by GitHub; a local passing result is not a claim that remote CI has run.
