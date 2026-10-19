"""Separate enrolled OpenVPN supervisor; uses the shared signed usage lifecycle."""

import argparse
import ipaddress
import logging
import re
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agent.wireguard import WireGuardAgent
from agent.openvpn_driver import OpenVPNDriver
from app.openvpn_pki import fingerprint


def validate_interfaces(interfaces):
    if not isinstance(interfaces, list) or len(interfaces) > 4:
        raise ValueError("Invalid OpenVPN interface set")
    pools, names, ports, keys = [], set(), set(), set()
    count = 0
    for i in interfaces:
        if (
            not re.fullmatch("[a-f0-9]{32}", i["id"])
            or i["name"] != "dno" + i["id"][:8]
            or i["name"] in names
        ):
            raise ValueError("Invalid owned OpenVPN name")
        names.add(i["name"])
        pool = ipaddress.ip_network(i["pool"], strict=True)
        if (
            pool.version != 4
            or not 16 <= pool.prefixlen <= 28
            or not any(
                pool.subnet_of(ipaddress.ip_network(n))
                for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
            or any(pool.overlaps(n) for n in pools)
        ):
            raise ValueError("Invalid or overlapping OpenVPN pool")
        pools.append(pool)
        if i["address"] != f"{pool.network_address + 1}/{pool.prefixlen}":
            raise ValueError("Invalid server address")
        if (
            type(i["port"]) is not int
            or not 1024 <= i["port"] <= 65535
            or i["protocol"] not in ("udp", "tcp")
            or (i["port"], i["protocol"]) in ports
        ):
            raise ValueError("Invalid OpenVPN port/protocol")
        ports.add((i["port"], i["protocol"]))
        ca = x509.load_pem_x509_certificate(i["ca_cert"].encode())
        ca.verify_directly_issued_by(ca)
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Invalid OpenVPN authority")
        cert = x509.load_pem_x509_certificate(i["server_cert"].encode())
        cert.verify_directly_issued_by(ca)
        if (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            != "donino-" + i["id"]
            or ExtendedKeyUsageOID.SERVER_AUTH
            not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ):
            raise ValueError("Invalid OpenVPN server identity")
        private = serialization.load_pem_private_key(
            i["private_key"].encode(), password=None
        )

        def der(key):
            return key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        if (
            der(private.public_key()) != der(cert.public_key())
            or fingerprint(i["server_cert"]) != i["public_key"]
        ):
            raise ValueError("OpenVPN server key mismatch")
        if not re.fullmatch(
            r"-----BEGIN OpenVPN Static key V1-----\n(?:[a-f0-9]{32}\n){16}-----END OpenVPN Static key V1-----\n",
            i["tls_key"],
        ):
            raise ValueError("Invalid TLS crypt material")
        addresses = set()
        for p in i["peers"]:
            count += 1
            if (
                count > 128
                or not re.fullmatch("[a-f0-9]{32}", p["public_key"])
                or p["public_key"] in keys
            ):
                raise ValueError("Invalid or excessive OpenVPN peer set")
            keys.add(p["public_key"])
            if not p["serial"].isdecimal() or not 0 < int(p["serial"]) < 2**159:
                raise ValueError("Invalid certificate serial")
            address = ipaddress.ip_address(p["address"])
            if (
                address not in pool
                or address
                in (
                    pool.network_address,
                    pool.network_address + 1,
                    pool.broadcast_address,
                )
                or address in addresses
            ):
                raise ValueError("Invalid OpenVPN peer address")
            addresses.add(address)
            for field in ("device_id", "user_id"):
                if str(uuid.UUID(p[field])) != p[field]:
                    raise ValueError("Invalid device identity")
            if type(p["period_no"]) is not int or p["period_no"] < 0:
                raise ValueError("Invalid period")
            for field in ("remaining", "expires"):
                if p[field] is not None and (type(p[field]) is not int or p[field] < 0):
                    raise ValueError("Invalid quota/expiry")


class OpenVPNAgent(WireGuardAgent):
    namespace = "openvpn"
    state_env = "DONINO_OVPN_STATE"
    default_state = "/var/lib/donino-openvpn"
    driver_factory = OpenVPNDriver
    validate = staticmethod(validate_interfaces)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if args.cleanup:
        OpenVPNAgent.cleanup()
    else:
        OpenVPNAgent().run()
