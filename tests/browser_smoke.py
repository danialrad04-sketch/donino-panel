"""Optional browser acceptance check. Requires playwright + `playwright install chromium`."""

import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db import initialize, digest
from app.security import hotp
from playwright.sync_api import sync_playwright


def exercise_smart_dns_ui(page):
    """Real API forms; only the link-probe observation is simulated here."""
    from app.db import database
    from app.smart_dns import health

    def probe(route):
        exit_id = route.request.url.rsplit("/", 2)[-2]
        with database() as db:
            revision = db.execute(
                "SELECT revision FROM smart_exits WHERE id=?", (exit_id,)
            ).fetchone()[0]
        health(exit_id, revision, True, 4)
        route.fulfill(json={"ok": True, "application_verified": False})

    pattern = "**/api/dns/smart/exits/*/probe"
    page.route(pattern, probe)
    try:
        for index in (1, 2):
            page.locator('[data-action="dns-smart-add"]').click()
            for key, value in {
                "name": f"خروجی آزمایشی {index}",
                "host": f"exit{index}.example.com",
                "sni": f"exit{index}.example.com",
                "username": "fixture-private-user",
                "password": secrets.token_urlsafe(24),
            }.items():
                page.locator(f"#edit-form [name={key}]").fill(value)
            page.locator("#edit-form button[type=submit]").click()
            page.locator("#modal").wait_for(state="hidden")
            page.locator('[data-action="dns-smart-edit"]').nth(index - 1).wait_for()
            exit_id = (
                page.locator('[data-action="dns-smart-edit"]')
                .nth(index - 1)
                .get_attribute("data-id")
            )
            page.locator(
                f'[data-action="dns-smart-probe"][data-id="{exit_id}"]'
            ).click()
            page.wait_for_function(
                "id => smartData.exits.some(n => n.id === id && n.healthy === 1)",
                arg=exit_id,
            )
            page.locator(f'[data-action="dns-smart-edit"][data-id="{exit_id}"]').click()
            assert page.locator("#edit-form [name=password]").input_value() == ""
            page.locator("#edit-form [name=mode]").select_option("active")
            page.locator("#edit-form button[type=submit]").click()
            page.locator("#modal").wait_for(state="hidden")
        ids = page.evaluate("smartData.exits.map(n => n.id)")
        policy_id = page.evaluate(
            "dnsData.policies.find(p=>p.name==='سیاست آزمایشی DNS').id"
        )
        page.locator(f'[data-action="dns-smart-route"][data-id="{policy_id}"]').click()
        page.locator("#edit-form [name=domains]").fill("play.example.com")
        page.locator("#edit-form [name=primary]").select_option(ids[0])
        page.locator("#edit-form [name=fallback1]").select_option(ids[1])
        page.locator("#edit-form button[type=submit]").click()
        page.locator("#modal").wait_for(state="hidden")
        page.locator(f'[data-action="dns-edit-policy"][data-id="{policy_id}"]').click()
        assert (
            f"route play.example.com {ids[0]},{ids[1]}"
            in page.locator("#edit-form [name=rules]").input_value()
        )
        page.locator("#edit-form button[type=submit]").click()
        page.locator("#modal").wait_for(state="hidden")
        page.locator('[data-action="dns-smart-account"]').click()
        page.locator("#edit-form [name=relay_enabled]").select_option("true")
        page.locator("#edit-form [name=gib]").fill("2")
        page.locator("#edit-form [name=connections]").fill("4")
        page.locator("#edit-form button[type=submit]").click()
        page.locator("#modal").wait_for(state="hidden")
        page.locator('[data-action="dns-edit-account"]').click()
        page.locator("#edit-form button[type=submit]").click()
        page.locator("#modal").wait_for(state="hidden")
        account = page.evaluate("api('/dns/accounts').then(a=>a[0])")
        assert account["relay_enabled"] and account["relay_limit"] == 2 * 1073741824
        assert account["relay_connections"] == 4 and account["query_limit"] == 500
        page.locator('[data-action="dns-smart-catalog"]').click()
        page.locator("#edit-form [name=name]").fill("کاتالوگ خروجی مدیریت‌شده")
        page.locator("#edit-form [name=group_0]").check()
        page.locator("#edit-form [name=primary]").select_option(ids[1])
        page.locator("#edit-form button[type=submit]").click()
        page.locator("#modal").wait_for(state="hidden")
        page.get_by_text("کاتالوگ خروجی مدیریت‌شده", exact=True).wait_for()
    finally:
        page.unroute(pattern, probe)


def exercise_tunnel_ui(page):
    page.locator("a[data-page=tunnels]").click()
    page.get_by_role("heading", name="آماده‌سازی اتصال تانل").wait_for()
    state = {
        "enabled": True,
        "available": True,
        "busy": False,
        "profiles": [
            {
                "id": "a" * 32,
                "name": "خارج آزمایشی",
                "host": "198.51.100.20",
                "management": "https-v1",
            }
        ],
        "jobs": [],
        "bindings": [],
        "probe_available": True,
    }
    requests = []
    inbound = page.evaluate(
        "(({id,node_id,port}) => ({id,node_id,port}))(data.inbounds[0])"
    )

    def worker(route):
        path = route.request.url.split("/api/tunnels/", 1)[-1]
        endpoint = path.rsplit("/", 1)[-1]
        body = (
            route.request.post_data_json
            if route.request.method in ("POST", "PUT")
            else None
        )
        if endpoint == "state":
            return route.fulfill(json=state)
        if path.startswith("bindings/") and route.request.method == "GET":
            return route.fulfill(json=state["bindings"][0])
        requests.append((endpoint, body))
        if endpoint == "bindings":
            value = {
                "id": "d" * 32,
                "plan_id": "b" * 32,
                "node_id": body["node_id"],
                "profile_id": body["profile_id"],
                "phase": "previewed",
                "source_matches": True,
                "can_start": True,
                "job_id": None,
                "services": body["services"],
                "checks": [],
                "monitor": {
                    "enabled": False,
                    "phase": "disabled",
                    "service_ready": True,
                },
                "summary": {
                    "iran": body["iran"],
                    "foreign": "198.51.100.20",
                    "transports": body["transports"],
                    "services": [
                        {
                            "id": "vpn-" + inbound["id"].replace("-", ""),
                            "listen": "0.0.0.0:"
                            + str(body["services"][0]["listen_port"]),
                            "target": "127.0.0.1:" + str(inbound["port"]),
                        }
                    ],
                },
            }
            state["bindings"] = [value]
            return route.fulfill(status=201, json=value)
        if endpoint == "preview":
            return route.fulfill(
                status=201,
                json={
                    "id": "b" * 32,
                    "expires_at": time.time() + 3600,
                    "summary": {
                        "iran": body["iran"],
                        "foreign": "198.51.100.20",
                        "transports": body["transports"],
                        "services": body["services"],
                        "firewall": {
                            "iran": {"tcp": [443, 24443], "udp": []},
                            "foreign": {"tcp": [9444], "udp": []},
                        },
                    },
                },
            )
        if endpoint == "start" and path.startswith("bindings/"):
            state["bindings"][0].update(
                phase="running", can_start=False, job_id="e" * 32
            )
            return route.fulfill(status=202, json=state["bindings"][0])
        if endpoint == "start":
            job = {"id": "c" * 32, "status": "running", "stage": "queued"}
            state["jobs"] = [job]
            return route.fulfill(status=202, json=job)
        if endpoint == "verify":
            check = {
                "id": "f" * 32,
                "phase": "succeeded",
                "expires": time.time() + 600,
                "inbound_ids": body["inbound_ids"],
            }
            state["bindings"][0]["checks"] = [check]
            return route.fulfill(status=201, json=check)
        if endpoint == "publication":
            binding = state["bindings"][0]
            binding["endpoint_published"] = route.request.method == "POST"
            binding["published_inbounds"] = (
                [{"inbound_id": inbound["id"], "check_id": "f" * 32}]
                if binding["endpoint_published"]
                else []
            )
            return route.fulfill(json=binding)
        if endpoint == "monitor":
            binding = state["bindings"][0]
            active = route.request.method == "PUT"
            binding["monitor"].update(
                enabled=active,
                phase="healthy" if active else "disabled",
                last_success=int(time.time()),
                next_run=int(time.time()) + 300,
            )
            if not active:
                binding.update(endpoint_published=False, published_inbounds=[])
            return route.fulfill(json=binding["monitor"])
        return route.fulfill(status=500, json={"detail": "Unexpected fixture route"})

    page.route("**/api/tunnels/**", worker)
    try:
        page.evaluate("render()")
        page.locator("#tunnel-plan [name=mode]").select_option("manual")
        page.locator("#tunnel-plan [name=iran]").fill("192.0.2.10")
        page.locator("#tunnel-plan [name=services]").fill("vpn,443,8443")
        page.locator("#tunnel-plan button[type=submit]").click()
        page.locator("#tunnel-review").wait_for(state="visible")
        assert page.locator("#tunnel-start").is_disabled()
        page.locator("#tunnel-confirm").check()
        page.locator("#tunnel-plan [name=services]").fill("vpn,444,8443")
        assert page.locator("#tunnel-review").is_hidden(), (
            "Changed spec must invalidate the reviewed plan"
        )
        page.locator("#tunnel-plan button[type=submit]").click()
        page.locator("#tunnel-review").wait_for(state="visible")
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
            "Tunnel mobile overflow"
        )
        page.locator("#tunnel-confirm").check()
        page.locator("#tunnel-start").click()
        page.locator("#tunnel-jobs").get_by_text("در حال اجرا", exact=True).wait_for()
        assert requests[-1] == ("start", {"plan_id": "b" * 32, "confirm_replace": True})
        assert requests[0][1]["services"][0]["target_port"] == 8443
        page.evaluate("render()")
        page.locator("#tunnel-plan [name=iran]").fill("192.0.2.10")
        page.locator(".tunnel-service-choice").first.check()
        page.locator("#tunnel-plan [name=port_" + inbound["id"] + "]").fill("1443")
        page.locator("#tunnel-plan button[type=submit]").click()
        page.locator("#tunnel-review").wait_for(state="visible")
        assert requests[-1][0] == "bindings"
        assert requests[-1][1]["services"] == [
            {"inbound_id": inbound["id"], "listen_port": 1443}
        ]
        assert requests[-1][1]["node_id"] == inbound["node_id"]
        page.evaluate("render()")
        page.get_by_role("button", name="مرور نقشه", exact=True).click()
        page.locator("#tunnel-review").wait_for(state="visible")
        assert page.locator("#tunnel-start").is_disabled()
        page.locator("#tunnel-confirm").check()
        page.locator("#tunnel-start").click()
        page.locator("#tunnel-jobs").get_by_text(
            "نصب در حال اجرا", exact=True
        ).wait_for()
        assert requests[-1] == ("start", {"confirm_replace": True})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
            "Bound tunnel mobile overflow"
        )
        state["bindings"][0]["phase"] = "succeeded"
        page.locator("#tunnel-reload").click()
        page.get_by_role("button", name="آزمون و انتشار", exact=True).click()
        verify_form = page.locator("#tunnel-verify-form")
        verify_form.locator("[name=device_id] option").first.wait_for(state="attached")
        verify_form.get_by_role("button", name="آزمون انتقال VPN", exact=True).click()
        page.locator("#tunnel-publish").wait_for(state="visible")
        assert page.locator("#tunnel-publish").is_disabled()
        assert requests[-1][0] == "verify"
        assert requests[-1][1]["inbound_ids"] == [inbound["id"]]
        assert set(requests[-1][1]) == {"device_id", "inbound_ids"}
        page.locator("#tunnel-publish-confirm").check()
        page.locator("#tunnel-publish").click()
        page.get_by_role("button", name="لغو انتشار", exact=True).wait_for()
        assert requests[-1] == (
            "publication",
            {"check_id": "f" * 32, "confirm_publish": True},
        )
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
            "Publication mobile overflow"
        )
        page.get_by_role("button", name="پایش و تمدید خودکار", exact=True).click()
        page.locator("#tunnel-monitor-form").wait_for()
        assert page.locator("#tunnel-monitor-form button").is_disabled()
        page.locator("#tunnel-monitor-form [name=consent]").check()
        page.locator("#tunnel-monitor-form button").click()
        page.locator("#tunnel-monitor-stop").wait_for()
        assert requests[-1] == (
            "monitor",
            {"check_id": "f" * 32, "confirm_auto_renew": True, "interval_seconds": 300},
        )
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
            "Monitor mobile overflow"
        )
        page.locator("#tunnel-monitor-stop").click()
        page.get_by_text(
            "پایش خاموش و انتشار لغو شد؛ نتیجهٔ آزمون قبلی آن را دوباره فعال نمی‌کند.",
            exact=True,
        ).wait_for()
        assert requests[-1] == ("monitor", None)
        page.get_by_role("button", name="آزمون و انتشار", exact=True).click()
        page.locator("#tunnel-acceptance").wait_for(state="visible")
        page.locator("#tunnel-verify-form [name=device_id] option").first.wait_for(
            state="attached"
        )
        page.evaluate("""() => {
            const form = document.querySelector('#tunnel-verify-form');
            form.requestSubmit();
            const input = form.querySelector('[name=inbound]');
            input.checked = false;
            input.dispatchEvent(new Event('change', {bubbles:true}));
        }""")
        page.get_by_text(
            "انتخاب‌ها هنگام آزمون تغییر کردند؛ نتیجه در تاریخچه است. برای انتشار، انتخاب‌ها را دوباره آزمون کنید.",
            exact=True,
        ).wait_for()
        assert page.locator("#tunnel-publish").count() == 0, (
            "Changed selection cannot publish an in-flight result"
        )

    finally:
        page.unroute("**/api/tunnels/**", worker)
        page.set_viewport_size({"width": 1440, "height": 1050})


def exercise_wireguard_ui(page):
    origin = page.evaluate("location.origin")
    page.locator("a[data-page=wireguard]").click()
    form = page.locator("#wg-create")
    form.wait_for()
    form.locator("[name=name]").fill("WireGuard آزمایشی")
    form.locator("[name=host]").fill("wg.example.com")
    # A background refresh must preserve typed endpoint forms.
    page.evaluate("refresh(false)")
    assert form.locator("[name=name]").input_value() == "WireGuard آزمایشی"
    form.locator("button[type=submit]").click()
    button = page.locator("[data-wg-toggle]")
    button.wait_for()
    button.click()
    page.locator('[data-wg-toggle][data-enabled="0"]').wait_for()
    page.locator("[data-wg-peers]").click()
    peer_form = page.locator(".wg-peer-create")
    peer_form.locator("[name=device_id] option").first.wait_for(state="attached")
    peer_form.locator("button[type=submit]").click()
    page.locator("[data-wg-qr]").wait_for()
    pid = page.locator("[data-wg-qr]").get_attribute("data-wg-qr")
    response = page.request.get(origin + "/api/wireguard/peers/" + pid + "/profile")
    assert response.status == 200 and "PrivateKey = " in response.text()
    assert response.headers["cache-control"] == "no-store"
    page.locator("[data-wg-qr]").click()
    page.wait_for_function(
        "() => document.querySelector('.wg-private-qr img')?.naturalWidth > 0"
    )
    # Never capture a private QR in screenshots or reports.
    page.locator(".wg-hide-qr").click()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("[data-wg-rotate]").click()
    page.wait_for_function(
        "id => fetch('/api/wireguard/peers/'+id+'/profile').then(r=>r.ok)", arg=pid
    )
    page.locator('[data-wg-peer][data-enabled="0"]').click()
    page.locator('[data-wg-peer][data-enabled="1"]').wait_for()
    assert page.request.get(origin + "/api/wireguard/peers/" + pid + "/profile").status == 409
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    page.set_viewport_size({"width": 1440, "height": 1050})


def main():
    output = Path(os.environ.get("DONINO_SCREENSHOT_DIR", "/tmp/donino-browser"))
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        os.environ["DONINO_DB"] = folder + "/test.db"
        os.environ.pop("DONINO_DATABASE_URL", None)
        os.environ["DONINO_KEY_FILE"] = folder + "/master.key"
        setup_token = secrets.token_urlsafe(40)
        os.environ["DONINO_BOOTSTRAP_TOKEN_HASH"] = digest(setup_token)
        os.environ["DONINO_BOOTSTRAP_EXPIRES"] = str(int(time.time()) + 3600)
        initialize()
        password = secrets.token_urlsafe(24)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-proxy-headers",
            ],
            env={**os.environ, "DONINO_SECURE_COOKIE": "false"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(60):
                try:
                    urllib.request.urlopen(url + "/healthz").close()
                    break
                except OSError:
                    time.sleep(0.1)
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(
                    viewport={"width": 1440, "height": 1050}, device_scale_factor=1
                )
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(url + "/#setup=" + setup_token)
                page.locator("#login-view").wait_for(state="visible")
                page.locator("#bootstrap-form").wait_for(state="visible")
                assert "#setup=" not in page.url
                page.locator("[name=owner_username]").fill("admin")
                page.locator("[name=owner_password]").fill(password)
                page.locator("[name=confirm]").fill(password)
                page.evaluate("document.fonts.ready")
                page.locator("#bootstrap-form button").click()
                page.locator("#app-view").wait_for(state="visible")
                page.get_by_role("button", name="کاربر جدید").click()
                page.locator("#edit-form [name=name]").fill("کاربر آزمایشی")
                page.locator("#edit-form [name=quota]").fill("25")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.locator("a[data-page=users]").click()
                page.get_by_role("button", name="اشتراک", exact=True).click()
                page.locator("#secret-output").wait_for()
                assert "/sub/" in page.locator("#secret-output").input_value()
                portal_url = page.locator("#open-portal").get_attribute("href")
                page.wait_for_function(
                    '() => document.querySelector(".share-qr").naturalWidth > 0'
                )
                page.locator("#close-modal").click()
                page.get_by_role("button", name="ویرایش", exact=True).click()
                page.locator("#edit-form [name=quota]").fill("35")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.locator("a[data-page=nodes]").click()
                page.get_by_role("button", name="نود جدید").click()
                page.locator("#edit-form [name=name]").fill("سرور اصلی")
                page.locator("#edit-form [name=host]").fill("vpn.example.com")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#secret-output").wait_for()
                assert len(page.locator("#secret-output").input_value()) > 40
                page.locator("#close-modal").click()
                page.locator("a[data-page=inbounds]").click()
                page.get_by_role("button", name="اتصال جدید").click()
                page.locator("#protocol").select_option("vless")
                assert page.locator("#transport option").count() == 3
                page.locator("#transport").select_option("grpc")
                assert page.locator("#service-field").is_visible()
                assert not page.locator("#path-field").is_visible()
                assert not page.locator("#reality-fields").is_visible()
                page.locator("#protocol").select_option("vmess")
                assert page.locator("#transport option").count() == 2
                page.locator("#transport").select_option("ws")
                assert page.locator("#path-field").is_visible()
                page.locator("#protocol").select_option("trojan")
                assert page.locator("#transport option").count() == 2
                page.locator("#protocol").select_option("vless")
                assert page.locator("#reality-fields").is_visible()
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role("button", name="ویرایش", exact=True).click()
                page.locator("#edit-form [name=name]").fill("اتصال اختصاصی")
                page.locator("#edit-form [name=port]").fill("8443")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.locator("a[data-page=users]").click()
                page.get_by_role("button", name="نودها", exact=True).click()
                page.locator("#edit-form [name=mode]").select_option("selected")
                page.locator("#edit-form input[type=checkbox]").check()
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role("button", name="دوره‌ها", exact=True).click()
                page.locator("#modal").wait_for(state="visible")
                assert "جاری" in page.locator("#modal").inner_text()
                page.locator("#close-modal").click()
                page.locator("a[data-page=dns]").click()
                page.get_by_role("button", name="سیاست جدید", exact=True).click()
                page.locator("#edit-form [name=name]").fill("سیاست آزمایشی DNS")
                page.locator("#edit-form [name=rules]").fill(
                    "block blocked.example\nrewrite fixture.example 1.2.3.4"
                )
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role(
                    "button", name="از کاتالوگ سرویس‌ها", exact=True
                ).click()
                page.locator("#edit-form [name=name]").fill("کاتالوگ پلی‌استیشن")
                page.locator("#edit-form [name=relay_addresses]").fill("1.2.3.4")
                page.locator("#edit-form [name=catalog_group_0]").check()
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role("button", name="مشاهدهٔ انتقال‌ها", exact=True).click()
                page.locator("#modal-title").filter(
                    has_text="انتقال‌های مرحله‌ای"
                ).wait_for()
                page.locator("#close-modal").click()
                page.get_by_role("button", name="فعال‌سازی DNS", exact=True).click()
                page.locator("#edit-form [name=user_id]").select_option(
                    label="کاربر آزمایشی"
                )
                page.locator("#edit-form [name=query_limit]").fill("500")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal-title").filter(
                    has_text="اعتبارنامهٔ خصوصی DoH"
                ).wait_for()
                page.locator("#close-modal").click()
                exercise_smart_dns_ui(page)
                exercise_tunnel_ui(page)
                exercise_wireguard_ui(page)
                page.locator("a[data-page=overview]").click()
                page.locator("#main h1").filter(has_text="شبکه، در یک نگاه").wait_for()
                page.locator("#toast").wait_for(state="hidden")
                page.screenshot(
                    path=str(output / "donino-dashboard.png"), full_page=True
                )
                page.locator("a[data-page=users]").click()
                page.get_by_role("button", name="کاربر جدید").click()
                page.locator("#edit-form [name=name]").fill("بودجه آزمایشی")
                page.locator("#edit-form [name=quota]").fill("10")
                page.locator("#edit-form [name=quota_mode]").select_option("lease")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role("button", name="بودجه", exact=True).click()
                page.locator("#modal-title").filter(
                    has_text="حجم تخصیص‌یافته"
                ).wait_for()
                page.locator("#close-modal").click()
                page.locator("a[data-page=overview]").click()
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "donino-mobile.png"), full_page=True)
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), "Mobile overview overflow"
                for view in [
                    "users",
                    "nodes",
                    "inbounds",
                    "dns",
                    "tunnels",
                    "audit",
                    "settings",
                ]:
                    page.locator("a[data-page=" + view + "]").click()
                    page.wait_for_timeout(100)
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    ), view + " overflow"
                    if view == "dns":
                        page.get_by_role(
                            "button", name="از کاتالوگ سرویس‌ها", exact=True
                        ).click()
                        page.locator("#edit-form [name=relay_addresses]").wait_for()
                        assert page.evaluate(
                            "document.documentElement.scrollWidth <= innerWidth"
                        ), "Mobile catalog form overflow"
                        page.locator("#close-modal").click()
                        page.locator('[data-action="dns-smart-route"]').first.click()
                        page.locator("#edit-form [name=domains]").wait_for()
                        assert page.evaluate(
                            "document.documentElement.scrollWidth <= innerWidth"
                        ), "Mobile Smart DNS routing form overflow"
                        page.locator("#close-modal").click()
                page.locator('[data-action="mfa-setup"]').click()
                page.locator("#edit-form [name=password]").fill(password)
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#edit-form [name=code]").wait_for()
                seed = page.locator("#edit-form textarea").input_value()
                page.locator("#edit-form [name=code]").fill(
                    hotp(seed, int(time.time()) // 30)
                )
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#secret-output").wait_for()
                assert (
                    len(page.locator("#secret-output").input_value().splitlines()) == 10
                )
                page.locator("#close-modal").click()
                page.locator("#theme").click()
                page.locator("[data-action=logout]").click()
                page.locator("#login-view").wait_for(state="visible")
                # The customer portal works in a separate context without admin cookies.
                visitor = browser.new_context(viewport={"width": 1200, "height": 1000})
                customer = visitor.new_page()
                customer.on("pageerror", lambda e: errors.append(str(e)))
                external = []
                customer.on(
                    "request",
                    lambda req: (
                        external.append(req.url)
                        if not req.url.startswith(url)
                        else None
                    ),
                )
                customer.goto(portal_url)
                customer.locator("#portal-content").wait_for(state="visible")
                customer.locator("#portal-dns").wait_for(state="visible")
                assert "۵۰۰" in customer.locator("#dns-summary").inner_text()
                customer.locator("#dns-claim").click()
                customer.locator("#dns-message").filter(
                    has_text="نشانی عمومی"
                ).wait_for()
                assert customer.locator("#portal-status").inner_text() == "فعال"
                assert (
                    customer.locator("#subscription-link")
                    .input_value()
                    .startswith(url + "/sub/")
                )
                customer.locator("#subscription-qr").wait_for(state="visible")
                customer.wait_for_function(
                    '() => document.querySelector("#subscription-qr").naturalWidth > 0'
                )
                customer.locator(".profile-item summary").click()
                customer.wait_for_function(
                    '() => document.querySelector(".profile-item img").naturalWidth > 0'
                )
                customer.evaluate("document.fonts.ready")
                customer.screenshot(
                    path=str(output / "donino-portal.png"), full_page=True
                )
                customer.set_viewport_size({"width": 390, "height": 844})
                customer.screenshot(
                    path=str(output / "donino-portal-mobile.png"), full_page=True
                )
                assert customer.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), "Portal mobile overflow"
                assert not external, external
                customer.locator("#portal-theme").click()
                customer.locator("#portal-refresh").click()
                customer.locator("#portal-content").wait_for(state="visible")
                visitor.close()
                assert not errors, errors
                browser.close()
            print(
                "Browser acceptance passed: admin flows, inbound editing, Smart DNS exits/routing/catalog/quotas, guest portal, local QR images, zero third-party requests, mobile layouts, themes and logout. No JavaScript errors."
            )
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
