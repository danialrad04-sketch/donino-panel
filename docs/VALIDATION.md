# Validation record

## Main continuation and 1.0 alpha 3 — 2026-10-16

Continued merged main through PRs #2–#6 and integrated the newer redesign from PR #7. The incompatible earlier `development/1.0` data model is refused explicitly. This entry records executed checks, not completion of the entire master plan.

- SQLite/Python 3.12: 114 discovered tests, 113 passed and the PostgreSQL-only fault-injection test skipped. Includes real pinned Xray VLESS/VMess/Trojan transfer, live additions, active quota revocation, rollback after occupied-port startup, and a real period reset followed by new VMess traffic charged to the new period.
- PostgreSQL 16/Python 3.11: the same 114 tests, 105 passed with nine SQLite-only checks skipped. Includes a deliberately failing `pg_restore` via an event trigger: earlier DDL and existing user data survive because the restore transaction rolls back. The disposable database is isolated from panel fixtures.
- Added checks for encrypted/migrated MFA seeds, enrollment password and committed lockouts, revocation of other sessions/API tokens on MFA transitions, CLI token revocation, unknown backend refusal, and explicit refusal of the incompatible development schema.
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
