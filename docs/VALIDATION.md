# Validation record

Run on 2026-10-15 with Python 3.12, Chromium via Playwright 1.62.0 and Xray v26.3.27 (pinned release asset SHA-256 in `scripts/fetch_xray.py`). All 18 API/agent/Xray checks passed in a fresh virtual environment using the repository dependencies; the separate browser acceptance check also passed.

- API tests exercise authentication, CSRF, roles, rate limits, input validation, token rotation, subscription formats, expiry, quota, concurrent duplicate traffic reports and SQLite backup readability.
- Real Xray test starts both ends of VLESS/REALITY, VMess/WebSocket/TLS and Trojan/TLS and passes HTTP response data through SOCKS into each encrypted transport. It verifies counters reach the panel, repeated snapshots do not double-charge, and an exhausted user disappears from the applied Xray config.
- Browser acceptance covers login/logout, user creation/edit, secret subscription retrieval, node enrollment/one-time token, inbound creation, navigation, theme switching and document overflow checks at a 390px viewport. Screenshots use isolated disposable fixtures.
- JavaScript syntax and Python compilation were checked.

The systemd and Nginx files are deployment templates; they were not installed on an external VPS during this session. External TLS issuance, real-domain reachability, third-party mobile client compatibility and load tests were not performed. GitHub Actions results are recorded separately by GitHub; a local passing result is not a claim that remote CI has run.
