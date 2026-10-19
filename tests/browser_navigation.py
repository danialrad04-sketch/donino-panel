"""Real-browser mobile navigation, focus, resize and readable table acceptance."""

import secrets


def open_navigation(page):
    if (
        page.evaluate('matchMedia("(max-width: 860px)").matches')
        and not page.locator("#navigation.is-open").count()
    ):
        page.locator(".topbar [data-nav-toggle]").click()
        page.locator('#navigation[aria-modal="true"]').wait_for()


def navigate(page, target):
    bottom = page.locator(f'#mobile-navigation a[data-nav-target="{target}"]')
    if bottom.is_visible() and not page.locator("#navigation.is-open").count():
        bottom.click()
    else:
        open_navigation(page)
        link = page.locator(f'a[data-page="{target}"]')
        group = link.locator("xpath=ancestor::details")
        if group.count() and not group.evaluate("el => el.open"):
            group.locator("summary").click()
        link.click()
    page.wait_for_function(
        'target => document.querySelector("#breadcrumb").textContent === titles[target]',
        arg=target,
    )


def exercise_mobile_navigation(page, output):
    navigate(page, "overview")
    for width, height in [(320, 740), (390, 844), (430, 932), (768, 1024), (844, 390)]:
        page.set_viewport_size({"width": width, "height": height})
        assert (
            page.locator("#mobile-navigation > a, #mobile-navigation > button").count()
            == 4
        )
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
            f"Shell overflow at {width}"
        )
        page.wait_for_function('() => document.querySelector("#navigation").inert')
        assert page.locator("#mobile-navigation").bounding_box()["width"] <= width
        for item in page.locator("#mobile-navigation > *").all():
            box = item.bounding_box()
            assert box["width"] >= 44 and box["height"] >= 44, "Small touch target"
        open_navigation(page)
        assert page.locator(".workspace").evaluate("el => el.inert")
        assert page.locator("#mobile-navigation").evaluate("el => el.inert")
        page.wait_for_function(
            '() => document.querySelector("#navigation").contains(document.activeElement)'
        )
        page.locator("#navigation .brand").focus()
        page.keyboard.press("Shift+Tab")
        assert page.locator("#logout").evaluate(
            "el => el === document.activeElement"
        ), "Reverse focus cycle escaped drawer"
        page.keyboard.press("Tab")
        assert page.locator("#navigation .brand").evaluate(
            "el => el === document.activeElement"
        )
        # Native details and every visible link must remain inside the modal focus cycle.
        for _ in range(25):
            page.keyboard.press("Tab")
            assert page.locator("#navigation").evaluate(
                "el => el.contains(document.activeElement)"
            ), "Focus escaped drawer"
        page.keyboard.press("Escape")
        page.locator("#navigation").wait_for(state="hidden")
        assert not page.locator(".workspace").evaluate("el => el.inert")
        assert page.locator(".topbar [data-nav-toggle]").evaluate(
            "el => el === document.activeElement"
        )
        open_navigation(page)
        page.locator("#nav-backdrop").click(position={"x": 8, "y": 160})
        page.locator("#navigation").wait_for(state="hidden")
        for target in ("users", "nodes"):
            navigate(page, target)
            assert page.evaluate(
                "document.documentElement.scrollWidth <= innerWidth"
            ), f"{target} overflow at {width}"
        navigate(page, "overview")
    page.set_viewport_size({"width": 390, "height": 844})
    navigate(page, "inbounds")
    assert page.locator("#mobile-navigation button.active").count() == 1
    assert page.locator("a[data-page=inbounds]").get_attribute("aria-current") == "page"
    open_navigation(page)
    assert page.locator("a[data-page=inbounds]").is_visible(), (
        "Active group is not expanded"
    )
    page.screenshot(path=str(output / "donino-mobile-menu.png"))
    # Tapping the current route must still close the drawer.
    page.locator("a[data-page=inbounds]").click()
    page.locator("#navigation").wait_for(state="hidden")
    assert page.locator("#main").evaluate("el => el === document.activeElement")
    navigate(page, "users")
    page.wait_for_selector("#main .responsive-table tbody tr")
    for cell in (
        page.locator("#main .responsive-table tbody tr").first.locator("td").all()
    ):
        assert cell.get_attribute("data-label"), "Unlabelled mobile field"
    page.screenshot(path=str(output / "donino-mobile-users.png"), full_page=True)
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    assert (
        page.locator("#users-pager").bounding_box()["y"]
        + page.locator("#users-pager").bounding_box()["height"]
        <= page.locator("#mobile-navigation").bounding_box()["y"]
    ), "Bottom bar covers the last controls"
    saved_scroll = page.evaluate("window.scrollY")
    open_navigation(page)
    assert page.evaluate('getComputedStyle(document.body).position === "fixed"')
    page.keyboard.press("Escape")
    page.locator("#navigation").wait_for(state="hidden")
    assert abs(page.evaluate("window.scrollY") - saved_scroll) <= 1, (
        "Closing menu lost the page position"
    )
    # Back/forward preserve route, current indicator and a closed drawer.
    page.go_back()
    page.wait_for_function('() => location.hash === "#inbounds"')
    page.locator("#navigation").wait_for(state="hidden")
    page.go_forward()
    page.wait_for_function('() => location.hash === "#users"')
    open_navigation(page)
    page.set_viewport_size({"width": 1280, "height": 720})
    page.wait_for_function(
        '() => !document.querySelector("#navigation").inert && !document.querySelector("#navigation").hasAttribute("aria-modal")'
    )
    assert page.locator("#navigation").is_visible()
    assert not page.locator("#navigation").evaluate("el => el.inert")
    assert page.locator("#navigation").get_attribute("aria-modal") is None
    assert not page.locator(".workspace").evaluate("el => el.inert")
    assert not page.locator("#mobile-navigation").is_visible()
    page.locator("a[data-page=users]").focus()
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator("#navigation").wait_for(state="hidden")
    page.wait_for_function(
        '() => document.querySelector(".topbar [data-nav-toggle]") === document.activeElement'
    )
    # Touch context uses real authenticated API, not a static HTML mock.
    context = page.context.browser.new_context(
        viewport={"width": 390, "height": 844},
        is_mobile=True,
        has_touch=True,
        storage_state=page.context.storage_state(),
    )
    try:
        touch = context.new_page()
        touch.goto(page.url.split("#")[0] + "#settings")
        touch.locator("#app-view").wait_for(state="visible")
        touch.locator(".topbar [data-nav-toggle]").tap()
        touch.locator("#close-navigation").tap()
        touch.locator("#navigation").wait_for(state="hidden")
        touch.locator("#mobile-navigation [data-nav-target=users]").tap()
        touch.get_by_role("button", name="کاربر جدید", exact=True).tap()
        touch.locator("#edit-form [name=name]").wait_for()
        assert touch.locator("#modal").bounding_box()["width"] <= 390
        assert touch.locator("#edit-form [name=name]").evaluate(
            "el => parseFloat(getComputedStyle(el).fontSize) >= 16"
        )
        touch.locator("#edit-form [name=name]").fill("فرم لمسی آزمایشی")
        touch.locator("#close-modal").tap()
    finally:
        context.close()
    username = "mobile-viewer-" + secrets.token_hex(3)
    password = secrets.token_urlsafe(24)
    page.evaluate(
        "fields => api('/admins', {method:'POST', body:JSON.stringify(fields)})",
        {"username": username, "password": password, "role": "viewer"},
    )
    viewer_context = page.context.browser.new_context(
        viewport={"width": 390, "height": 844},
        is_mobile=True,
        has_touch=True,
        reduced_motion="reduce",
    )
    try:
        viewer = viewer_context.new_page()
        viewer.goto(page.url.split("#")[0])
        viewer.locator("#login-form [name=username]").fill(username)
        viewer.locator("#login-form [name=password]").fill(password)
        viewer.locator("#login-form button").click()
        viewer.locator("#app-view").wait_for(state="visible")
        open_navigation(viewer)
        assert viewer.locator("#navigation [data-owner]").evaluate_all(
            "items => items.every(el => el.hidden)"
        ), "Owner-only navigation leaked"
        assert (
            viewer_context.request.get(page.url.split("#")[0] + "api/admins").status
            == 403
        )
        viewer.keyboard.press("Escape")
        viewer.locator("#navigation").wait_for(state="hidden")
        navigate(viewer, "settings")
        assert viewer.locator("#mobile-navigation button.active").count() == 1
    finally:
        viewer_context.close()
    navigate(page, "overview")
    print(
        "Mobile navigation passed: 320/390/430/768/844 widths, modal focus/escape/backdrop, hierarchy, history, resize, touch form and labelled table cards.",
        flush=True,
    )
