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
from app.db import initialize, database, hash_password
from playwright.sync_api import sync_playwright


def main():
    output = Path(os.environ.get("DONINO_SCREENSHOT_DIR", "/tmp/donino-browser"))
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        os.environ["DONINO_DB"] = folder + "/test.db"
        initialize()
        password = secrets.token_urlsafe(24)
        with database() as db:
            db.execute(
                "INSERT INTO admins VALUES(?,?,?)",
                ("admin", hash_password(password), "owner"),
            )
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
                page.goto(url)
                page.locator("#login-view").wait_for(state="visible")
                page.evaluate("document.fonts.ready")
                page.screenshot(path=str(output / "donino-login.png"), full_page=True)
                page.locator("[name=username]").fill("admin")
                page.locator("[name=password]").fill(password)
                page.locator("#login-form button").click()
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
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.get_by_role("button", name="ویرایش", exact=True).click()
                page.locator("#edit-form [name=name]").fill("اتصال اختصاصی")
                page.locator("#edit-form [name=port]").fill("8443")
                page.locator("#edit-form button[type=submit]").click()
                page.locator("#modal").wait_for(state="hidden")
                page.locator("a[data-page=overview]").click()
                page.locator("#main h1").filter(has_text="شبکه، در یک نگاه").wait_for()
                page.locator("#toast").wait_for(state="hidden")
                page.screenshot(
                    path=str(output / "donino-dashboard.png"), full_page=True
                )
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "donino-mobile.png"), full_page=True)
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), "Mobile overview overflow"
                for view in ["users", "nodes", "inbounds", "audit", "settings"]:
                    page.locator("a[data-page=" + view + "]").click()
                    page.wait_for_timeout(100)
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    ), view + " overflow"
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
                "Browser acceptance passed: admin flows, inbound editing, guest portal, local QR images, zero third-party requests, mobile layouts, themes and logout. No JavaScript errors."
            )
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
