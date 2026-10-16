"""Validate signed shared-quota grants and aggregate local device ownership."""


def parse_grants(desired):
    grants, devices = {}, {}
    periods = desired.get("periods", {})
    for value in desired.get("budgets", []):
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not isinstance(value.get("devices"), list)
        ):
            raise ValueError("Invalid budget grant")
        if value["id"] in grants or not all(
            type(value.get(name)) is int and value[name] >= 0
            for name in ("granted", "spent", "period_no", "expires")
        ):
            raise ValueError("Duplicate grant or invalid budget counter")
        if not value["granted"] or value["spent"] >= value["granted"]:
            raise ValueError("No remaining budget in an active grant")
        for device in value["devices"]:
            if (
                not isinstance(device, str)
                or device in devices
                or periods.get(device) != value["period_no"]
            ):
                raise ValueError("Device belongs to an inconsistent budget or period")
            devices[device] = value["id"]
        grants[value["id"]] = dict(value)
    return grants, devices


def exhausted(grants, spent, now):
    return any(
        now >= grant["expires"]
        or max(spent.get(lease_id, 0), grant["spent"]) >= grant["granted"]
        for lease_id, grant in grants.items()
    )
