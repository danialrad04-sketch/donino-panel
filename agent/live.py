"""Allow live additions; revocations restart Xray to terminate established sessions."""

import copy


def user_additions(current, desired):
    def shape(config):
        value = copy.deepcopy(config)
        for inbound in value.get("inbounds", []):
            if inbound.get("tag") == "api":
                continue
            if inbound.get("protocol") not in ("vless", "vmess", "trojan"):
                return None
            inbound["settings"]["clients"] = []
        return value

    before, after = shape(current), shape(desired)
    if before is None or after is None or before != after:
        return None
    changes = []
    for old, new in zip(current["inbounds"], desired["inbounds"]):
        if old.get("tag") == "api":
            continue
        old_clients = {c["email"]: c for c in old["settings"]["clients"]}
        new_clients = {c["email"]: c for c in new["settings"]["clients"]}
        if any(new_clients.get(email) != c for email, c in old_clients.items()):
            return None
        add = [c for email, c in new_clients.items() if old_clients.get(email) != c]
        if add:
            changes.append((new, add))
    return changes
