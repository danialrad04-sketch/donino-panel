# Real Mihomo TLS acceptance

Codex completed the PR #17 handoff while Claude is paused by user instruction.
Tested client: MetaCubeX/mihomo v1.19.32 compatible Linux amd64, compressed asset
SHA256 `ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20`.
Node: pinned Xray v26.3.27. Fetchers verify digests before execution; no binaries
are committed. Upstream engine licenses apply independently.

## Executed local result

All nine tests passed, with no expected failures, using real Mihomo and Xray.
The six tested profiles are VLESS WS/TLS, VLESS gRPC/TLS, VMess WS/TLS,
VMess gRPC/TLS, Trojan TCP/TLS and Trojan WS/TLS. Each receives its proxy body
from the actual `/sub/{token}?format=clash` response. No positive-control proxy
body is repaired or replaced in the test.

For every profile, valid CA/name transfers succeeded and unknown CA / wrong
hostname failed with explicit certificate errors. Two-device traffic reached
the correct device counters and current usage period. After device revocation,
its stored profiles failed on all six paths and the other device still worked;
the fresh subscription omitted the disabled device.

## Fixed product defect

The original handoff correctly found that Mihomo ignores `servername` for Trojan
and reads `sni` instead. With an IP dial and a localhost certificate, the old
export verified the IP and failed. Codex corrected `app/core.py` to export
Trojan `sni`, preserving `servername` for VLESS/VMess. Both Trojan profiles now
pass ordinary real-transfer tests. There is no expected-failure decorator.
A separate regression moves the field back to its historical wrong key and
checks the exact certificate failure; this is an intentional negative control.

## Fixture and limits

Mihomo runs one exported proxy per process, with a loopback SOCKS listener,
explicit proxy selection, no external controller, no providers and geodata
auto-update disabled. The fixture CA is supplied through `SSL_CERT_FILE` in
the client subprocess; normal certificate directories remain available.
TLS verification stays enabled. Negative hostname controls change only the
protocol's actual SNI field. The node fixture trims the private-network routing
block solely to reach the loopback echo target, as in existing Xray acceptance.
Observed Mihomo dial destinations are checked to be loopback.

The dedicated pinned workflow runs the real checks on SQLite and PostgreSQL.
Exact-head remote results are attached to PR #17. Local command:

```sh
DONINO_TEST_XRAY=/path/to/verified/xray DONINO_TEST_MIHOMO=/path/to/verified/mihomo \
  python -m unittest discover -s tests -p test_mihomo.py -v
```

REALITY, other Mihomo builds/platforms, sing-box, v2rayN, real VPS, public ACME,
games and Iranian ISP paths are outside this evidence. This does not assert
universal client or network compatibility.
