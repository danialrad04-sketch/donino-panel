# Validation record

Version 0.2 was checked on 2026-10-15 with Python 3.12, Chromium via Playwright 1.62.0 and Xray v26.3.27 (pinned release asset SHA-256 in `scripts/fetch_xray.py`). All 34 API/agent/journal/migration/Xray checks passed using the repository dependencies; the expanded browser acceptance check also passed.

- API tests exercise authentication, CSRF, roles, rate limits, input validation, token rotation, subscription formats, expiry, quota, concurrent duplicate traffic reports and SQLite backup readability.
- Real Xray test starts both ends of VLESS/REALITY, VMess/WebSocket/TLS and Trojan/TLS and passes HTTP response data through SOCKS into each encrypted transport. It keeps an encrypted stream open across a live user addition, verifies the unchanged server PID/epoch and Xray user counts on all three protocols, checks quota revocation restarts the core, and induces an actual occupied-port startup failure to verify recovery of the previous config.
- Journal and integration tests preserve snapshots across restart, exercise lost HTTP acknowledgements after the panel has processed usage, ensure replay does not double-charge, split large snapshots into bounded batches and reject reuse by another node/origin.
- Migration tests upgrade an actual 0.1 schema fixture, preserve credentials/tokens/totals, read the pre-migration backup, reject future schemas and abort on backup failure.
- Browser acceptance covers admin flows, inbound editing, local QR image loading, a customer portal in a separate context without admin cookies, no third-party requests from the portal, theme switching and overflow checks at a 390px viewport. Screenshots use isolated disposable fixtures, including temporary non-operational subscription credentials.
- JavaScript syntax and Python compilation were checked.

The systemd and Nginx files are deployment templates; they were not installed on an external VPS during this session. External TLS issuance, real-domain reachability, scanning QR codes in every third-party client and load tests were not performed. GitHub Actions results are recorded separately by GitHub; a local passing result is not a claim that remote CI has run.
