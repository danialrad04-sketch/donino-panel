# Xray transport acceptance evidence

Task `xray-acceptance-v1`. Scope: VLESS WS+TLS, VLESS gRPC+TLS, VMess gRPC+TLS and
Trojan WS+TLS, tested with the pinned Xray binary (`v26.3.27`, the version in
`scripts/fetch_xray.py`). The transports themselves were delivered in PR #13; this
document records the additional acceptance evidence.

## How the checks run

Every real check starts the panel (SQLite file, or a disposable PostgreSQL schema
via `tests/support.configure`), one node agent, and real Xray on the node and on
each client. Client configs are built from the subscription URIs the panel
publishes (`/sub/{token}?format=raw`), so the links are tested as users receive
them. TLS uses a test CA and a leaf certificate for `localhost`. Verification is
never disabled and `allowInsecure` is never set.

Commands used for the evidence below:

```sh
DONINO_TEST_XRAY=/path/to/xray-v26.3.27 PYTHONPATH=. \
  python -m unittest discover -s tests -p test_xray_transports.py -v
DONINO_TEST_XRAY=... DONINO_TEST_DATABASE_URL=postgresql://... PYTHONPATH=. \
  python -m unittest discover -s tests -p test_xray_transports.py -v
DONINO_TEST_XRAY=... DONINO_TEST_UNBOUND=/usr/sbin/unbound \
  python -m unittest discover -s tests
```

## Results

| Check | What it proves | Result |
|---|---|---|
| `test_live_add_is_hot_and_keeps_an_open_stream` | A new user and a new device added while the agent runs are applied `hot`. Xray PID and epoch do not change. A stream opened before the change keeps passing data. The new client transfers on all four transports. Bytes reach the new device IDs and the current period. | Pass |
| `test_real_expiry_stops_stored_and_new_links` | A user with a real `expires` (30 s after creation) transfers on all four transports before expiry. After real wall-clock expiry and one tick, the node applies `restart`, the PID changes, the new inbounds have no clients, the stored links are refused on all four, and the subscription returns 404 for both formats. | Pass |
| `test_expiry_set_to_past_via_api_revokes_on_tick` | Changing `expires` to a past time through the API revokes the user on the next tick. The stored links are refused and the subscription returns 404. | Pass |
| `test_tls_controls_for_each_transport` | For each transport: the valid CA with hostname `localhost` succeeds; a different CA is refused; a wrong hostname (`wrong.example`) is refused. Refusals are verified from the client log, not only from the absence of data. | Pass |
| `test_device_user_quota_and_period_cut_offs` | Per-device counters increase for two devices on all four transports. Disabling a device cuts only that device. Disabling a user removes all clients. Quota exhaustion removes clients and sets status `limited`. Period reset restarts Xray and restores transfers. A client without the test CA is refused. | Pass |
| Unit checks (5 tests) | Vision flow only on REALITY/TCP; legacy rows keep their transport; URI, VMess JSON and Mihomo fields per transport; API accepts only the listed protocol/transport pairs; TLS transports require certificate paths. | Pass |

Runs reported with the initial implementation, before the final handoff checkpoint:

- SQLite, all files: 168 tests OK, 2 skipped (PostgreSQL-only and Unbound-only cases, which need their environment variables).
- PostgreSQL 16, `test_xray_transports.py`: 10 tests OK.
- SQLite, `test_xray_transports.py`: 10 tests OK.

## Codex integration review

The final handoff initially failed CI: the source manifest was stale after the
checkpoint update, and a coordination test incorrectly assumed the tracked
checkpoint was always in its initial state. Those failures were fixed rather
than treating the earlier green implementation run as proof for the final head.
The checkpoint CLI now refreshes the manifest, with an isolated CLI regression.
Socket reads handle partial replies and EOF, and config validation has a timeout.

Codex independently reran all 10 real-Xray checks successfully and all three
coordination checks successfully. Full exact-head results, including PostgreSQL,
real Unbound and both native OS fixtures, are attached to
[PR #15](https://github.com/danialrad04-sketch/donino-panel/pull/15). The unchanged
Claude handoff is archived under `docs/coordination/history/` and its subsequent
assignment is recorded separately; it is not evidence of real Mihomo acceptance.

## Observed behaviour

- **Live add:** applied `hot`. PID and epoch unchanged. The stream opened before the change kept passing data.
- **Revocation (expiry, disable, quota, device cut-off):** applied as `restart`. Xray restarts so that established sessions end. Live additions do not restart.
- **Negative TLS evidence.** The client log reports the refusal, for example:
  `transport/internet/websocket: failed to dial ... tls: failed to verify certificate: x509: certificate signed by unknown authority`.
  The server side logs `tls: bad certificate` for the same refusal.

## Limitations (not claimed)

- Not tested with real Mihomo, v2rayN or sing-box clients importing the URIs or YAML. Xray clients built from the same URI fields are the acceptance client.
- Expiry checks use real wall-clock time with a 30 s window, so each run waits about 30 s. The clock is not mocked.
- Only the four new transports are covered by the real checks in this file. The older three are still covered by `tests/test_xray.py`.
- No real VPS, domain, public ACME certificate, or Iranian network path was available. This is local acceptance only.
- Shadowsocks, HTTPUpgrade, XHTTP, and HTTP/SOCKS/Mixed are outside this document.
- The PostgreSQL run used a local PostgreSQL 16 server, not the CI service container.
