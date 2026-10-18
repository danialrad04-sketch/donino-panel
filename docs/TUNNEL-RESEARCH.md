# Tunnel integration research — 2026-10-18

Reviewed source snapshots (no upstream installer executed):

| Source | Reviewed commit | License | Use in this change |
| --- | --- | --- | --- |
| [Donino Tunnel](https://github.com/danialrad04-sketch/donino-tunnel/tree/4c19214598d32bd2868f9f46030d8a5dbd494d97) | `4c19214598d32bd2868f9f46030d8a5dbd494d97` | MIT; engines have separate licenses | Local typed controller contract and pinned CI fixture. No vendored implementation. |
| [Hashem Panel](https://github.com/pdnczone/hashem-panel/tree/35f990c5caaa9b4983d5ebc4f3c8f85c4ecc1972) | `35f990c5caaa9b4983d5ebc4f3c8f85c4ecc1972` | LICENSE contains AGPL-3.0 text; API metadata says NOASSERTION | Architecture/requirements comparison. No source copied. |

Hashem separates the relay engine (GRE+FRP, GRE+Backhaul, standalone Backhaul)
from the GRE carrier (direct IP protocol 47 or WSS). Its README distinguishes
fallback of the foreign dial address from manual carrier selection; it says the
carrier advisor does not automatically switch carriers and auto-restart is off
by default. These are useful distinctions to preserve in product claims. See its
`docs/ENGINES.md`, README “Automation” and “Limitations”. A passing GRE interface
or a running service does not prove that the destination application works.

Donino Tunnel already supplies bounded plans, HTTPS certificate pinning,
one-use pairing, typed root-worker operations, persistent installation jobs,
prepare/activate sequencing, guarded rollback and signed path probes. See
`donino_link/provision.py`, `peer.py`, `management.py`, `plan.py`, and its
`docs/management.md`, `docs/panel-installer.md`. Reusing that boundary avoids a
second competing tunnel installer and avoids activating its independent VPN
backend/user store. The panel bridge initially exposes only TCP services over
FRP WSS / QUIC; the rest remain separate acceptance work.

The Instagram URL returned HTML (HTTP 200); its public title/description refers
to scenery at گردنه حیران, rather than a tunnel implementation. No video-derived
technical method or network evidence is inferred from that metadata:
https://www.instagram.com/reel/DctxsGJs19q/

Remaining integration gates include a durable node/inbound-to-plan binding,
endpoint publication after real transfer acceptance, independent least-privilege
worker access, two-node restart/network-partition tests and real Iran/foreign
operator acceptance. No claim of universal carrier/protocol support is made.
