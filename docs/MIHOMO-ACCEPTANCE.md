# Mihomo client acceptance for TLS profiles

Task `mihomo-tls-acceptance-v1`. This document records real-client evidence for six
TLS profiles produced by the panel's Mihomo/Clash subscription output. It does not
cover REALITY, sing-box or v2rayN, and it makes no claim about those clients.

## Pinned versions

| Component | Version | Verification |
|---|---|---|
| Mihomo client | `MetaCubeX/mihomo` `v1.19.32`, `mihomo-linux-amd64-compatible-v1.19.32.gz` | SHA-256 of the `.gz` asset `ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20`, checked by `scripts/fetch_mihomo.py` before extraction. `mihomo -v` reports `Mihomo Meta v1.19.32 linux amd64`. |
| Node Xray | `v26.3.27` | `scripts/fetch_xray.py`, as before. |

The decompressed binary is not committed. `scripts/fetch_mihomo.py` writes it to an
empty destination outside the repository. The workflow `.github/workflows/mihomo.yml`
runs only `tests/test_mihomo.py`, with both binaries fetched and verified.

## How the fixture works

- A real panel, a node agent and real Xray run on loopback. Six inbounds are created
  through the API: VLESS WS+TLS, VLESS gRPC+TLS, VMess WS+TLS, VMess gRPC+TLS,
  Trojan TCP+TLS and Trojan WS+TLS.
- Each Mihomo profile is taken unmodified from `/sub/{token}?format=clash`. One Mihomo
  process is started per profile, with a local SOCKS listener and that single proxy in
  a select group, then `mihomo -t` validates the config and the process is torn down.
- The traffic goes SOCKS → Mihomo → Xray node → local HTTP echo, and the test checks the marker body.
- Every Mihomo log is checked: all dialled destinations must be `127.0.0.1`. The test fails if not.

### Lab-only differences from production

These are the only changes made to the test environment. Each is listed so reviewers can see the difference.

1. **Trust.** Mihomo runs with `SSL_CERT_FILE` set to the test CA, so Go's root pool is the test CA only. Verification stays on. `skip-cert-verify`, `allowInsecure` and `fingerprint` pinning are not used.
   - An earlier attempt with the top-level `custom-certifactes` key did not affect the TLS path for these profiles. It was dropped.
2. **Single-proxy selection** and a local SOCKS listener on loopback, with `allow-lan: false` and no external controller, so no management port is opened.
3. **Geodata and providers disabled** (`geo-auto-update: false`, `geodata-mode: false`). No external download or provider fetch is configured.
4. **Trojan CA control only.** The untrusted-CA test adds `sni` equal to the exported `servername` for the trojan profiles. This isolates CA verification from the export defect below. Every other test uses the exported body unchanged.

## Results

Run on Linux amd64, with `DONINO_TEST_XRAY` and `DONINO_TEST_MIHOMO`:

| Test | What it checks | Result |
|---|---|---|
| `test_binary_is_the_pinned_version` | The client binary reports v1.19.32. | Pass |
| `test_four_working_profiles_transfer_through_real_mihomo` | VLESS WS, VLESS gRPC, VMess WS and VMess gRPC transfer through real Mihomo with the valid CA and correct name. | Pass (4/4) |
| `test_wrong_ca_is_refused_with_a_certificate_error_for_all_six` | An untrusted CA is refused on all six, with the log line `x509: certificate signed by unknown authority`. The trojan profiles pass the sni-isolation above for this test. | Pass (6/6) |
| `test_wrong_hostname_is_refused_for_the_four_working_profiles` | `wrong.example` is refused on the four working profiles, with a Go hostname error that names `not wrong.example` (the test asserts on that substring). | Pass (4/4) |
| `test_known_defect_trojan_servername_is_ignored_by_mihomo` | Reproduces the trojan defect below and checks its exact log signature. | Pass (2/2 reproduced) |
| `test_trojan_profiles_transfer_once_the_export_is_fixed` | Expected failure until the export is fixed. | Expected failure |
| `test_device_bytes_and_cut_off_with_mihomo` | Bytes reach both device IDs and the current period. Disabling a device stops its stored Mihomo profiles on the four working profiles, and the default device keeps working. | Pass |
| `MihomoFetcherTest` (2 tests) | Pinned version, asset and digest constants. A digest mismatch refuses to extract. | Pass |

Test run totals on the final code: 9 tests, OK, 1 expected failure.

## Export defect: trojan `servername` is not used by Mihomo

The subscription sets the trojan SNI in `servername`. This Mihomo build reads the trojan SNI from `sni`. With only `servername`, Mihomo verifies the certificate against the dial address `127.0.0.1` instead of the configured name, and the handshake fails.

Minimal reproducer (password redacted; the values are not secrets):

```json
{"socks-port": 7897, "bind-address": "127.0.0.1", "allow-lan": false, "mode": "rule",
 "log-level": "info", "geo-auto-update": false, "geodata-mode": false,
 "proxies": [{"name": "t", "type": "trojan", "server": "127.0.0.1", "port": 443,
   "password": "<redacted>", "tls": true, "servername": "localhost", "udp": true}],
 "proxy-groups": [{"name": "G", "type": "select", "proxies": ["t"]}],
 "rules": ["MATCH,G"]}
```

Run with `SSL_CERT_FILE` set to a test CA that signs a leaf for `localhost`. The log shows:

```text
tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs
```

Adding `"sni": "localhost"` to the same proxy removes the error: the certificate chain and name are verified and the handshake completes. The same defect applies to the existing trojan TCP+TLS profile, not only the new trojan WS+TLS profile. VLESS and VMess set `servername`, and those profiles verify correctly.

Fixing this changes the product export (`app/core.py`, `profiles()`). That change is outside this task, so it has not been made here. It needs coordination with Codex.

## Limitations (not claimed)

- Trojan profiles do not transfer through real Mihomo on the current export. Trojan acceptance is blocked until the export defect is fixed. The expected-failure test is the tripwire: once trojan transfers, unittest reports an unexpected success and the decorator should be removed.
- REALITY, sing-box and v2rayN are not covered.
- Local acceptance only: no VPS, public domain, public ACME certificate, or Iranian network path. Loopback only.
- The Mihomo binary is the `compatible` amd64 build, and only Linux amd64 is fetched by the script.
- The lab trust mechanism (`SSL_CERT_FILE`) is a test setting. Client trust on real devices is not tested.
