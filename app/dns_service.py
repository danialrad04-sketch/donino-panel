"""DNS authorization and a separate query/byte ledger. No query names are stored."""

import ipaddress
import time

import dns.exception
import dns.flags
import dns.message
import dns.rcode
from fastapi import HTTPException

from .db import database, digest, upsert
from .dns_policy import DNSResolver, parse_query, serialize


def canonical_address(value):
    if "%" in value:
        raise ValueError("Scoped IP addresses are not public client identities")
    address = ipaddress.ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def account_row(db, *, token=None, source_ip=None):
    if token:
        if not token.startswith("dns_") or not 40 <= len(token) <= 100:
            raise HTTPException(401, "DNS credential required")
        clause, args = "a.token_hash=?", (digest(token),)
    elif source_ip:
        try:
            source_ip = str(canonical_address(source_ip))
        except ValueError as exc:
            raise HTTPException(401, "Invalid source address") from exc
        clause, args = (
            "EXISTS(SELECT 1 FROM dns_ip_leases l WHERE l.account_id=a.id AND l.ip=? AND l.expires>?)",
            (source_ip, int(time.time())),
        )
    else:
        raise HTTPException(401, "DNS credential or active source lease required")
    row = db.execute(
        f"""SELECT a.*,u.enabled AS user_enabled,u.expires AS user_expires,
        p.revision,p.rules FROM dns_accounts a JOIN users u ON u.id=a.user_id
        JOIN dns_policies p ON p.id=a.policy_id WHERE {clause}""",
        args,
    ).fetchone()
    if not row:
        raise HTTPException(401, "DNS credential or source lease is invalid")
    if (
        not row["enabled"]
        or not row["user_enabled"]
        or (row["user_expires"] and row["user_expires"] <= int(time.time()))
    ):
        raise HTTPException(403, "DNS service is disabled or expired")
    return dict(row)


def reserve_request(size, *, token=None, source_ip=None):
    now = int(time.time())
    with database() as db:
        account = account_row(db, token=token, source_ip=source_ip)
        period = db.execute(
            "SELECT queries FROM dns_periods WHERE account_id=? AND period_no=?",
            (account["id"], account["period_no"]),
        ).fetchone()
        if account["query_limit"] and period["queries"] >= account["query_limit"]:
            raise HTTPException(403, "DNS query quota exhausted")
        rate = db.execute(
            "SELECT * FROM dns_rate WHERE account_id=?", (account["id"],)
        ).fetchone()
        count = rate["requests"] if rate and rate["window_started"] == now else 0
        if count >= account["qps"]:
            raise HTTPException(429, "DNS request rate exceeded")
        upsert(
            db,
            "dns_rate",
            ["account_id", "window_started", "requests"],
            [account["id"], now, count + 1],
            ["account_id"],
        )
        db.execute(
            "UPDATE dns_periods SET queries=queries+1,request_bytes=request_bytes+? WHERE account_id=? AND period_no=?",
            (size, account["id"], account["period_no"]),
        )
    return account


class DNSService:
    def __init__(self, resolver=None):
        self.resolver = resolver or DNSResolver()

    def answer(self, wire, *, token=None, source_ip=None, udp=False):
        query = parse_query(wire)
        account = reserve_request(len(wire), token=token, source_ip=source_ip)
        failed, blocked = False, False
        try:
            from .smart_dns import route_rules

            response, blocked = self.resolver.resolve(
                query,
                {
                    "id": account["policy_id"],
                    "revision": account["revision"],
                    "rules": route_rules(account, source_ip=source_ip),
                },
            )
            failed = response.rcode() == dns.rcode.SERVFAIL
            output = serialize(response, query, udp=udp)
        except (dns.exception.DNSException, OSError, ValueError):
            failed = True
            response = dns.message.make_response(query)
            response.flags |= dns.flags.RA
            response.flags &= ~dns.flags.AD
            response.set_rcode(dns.rcode.SERVFAIL)
            output = serialize(response, query, udp=udp)
        with database() as db:
            # Response accounting stays in the reserved period across a reset.
            db.execute(
                "UPDATE dns_periods SET response_bytes=response_bytes+?,errors=errors+?,blocked=blocked+? WHERE account_id=? AND period_no=?",
                (
                    len(output),
                    int(failed),
                    int(blocked),
                    account["id"],
                    account["period_no"],
                ),
            )
        return output
