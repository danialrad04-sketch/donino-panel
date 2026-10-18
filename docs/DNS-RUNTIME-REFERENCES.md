# DNS runtime references

The Donino gateway and policy/accounting code are independent project code. No doctor-dns runtime code is imported in this slice. The earlier pinned research remains in `planning-reference-snapshots.json`.

- dnspython **2.8.0**, Python >=3.10, ISC license: <https://github.com/rthalley/dnspython/tree/v2.8.0>. PyPI wheel `dnspython-2.8.0-py3-none-any.whl`, SHA-256 `01d9bbc4a2d76bf0db7c1f729812ded6d912bd318d3b1cf81d30c0f845dbf3af`. This dependency is installed with its license metadata; it is not vendored.
- Unbound is provisioned from the signed Debian 12 / Ubuntu 24.04 package repositories, together with dns-root-data. Security updates are permitted; this is not a claim of a fixed binary checksum across distributions. Reference: <https://github.com/NLnetLabs/unbound>, <https://unbound.docs.nlnetlabs.nl/>. The executed local DNSSEC fixture used Debian Unbound 1.17.1; native CI also exercises the target distribution's package.
- DNS wire/framing and negative-cache behavior: RFC 1035 and RFC 2308. DoT: RFC 7858. Authenticated DoH uses the RFC 8484 wire format plus a separate Bearer credential. Cache-Control is intentionally `no-store` on the authenticated HTTP endpoint.
- dnsdist DoQ documentation was rechecked: <https://www.dnsdist.org/guides/dns-over-quic.html>. Incoming DoQ requires dnsdist >=1.9.0 and a compatible feature build. DoQ is **not implemented or advertised as available** in this release; the OS package version alone is not sufficient evidence.

Upstream DNSSEC validity is checked with a generated private trust anchor, a real Unbound validator and a deliberately invalid signature. This deterministic fixture does not contact public authoritative servers or establish acceptance for every public DNSSEC delegation.
