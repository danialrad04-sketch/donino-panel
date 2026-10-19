/* Responsive navigation only; API authorization stays on the server. */
"use strict";
window.DoninoNavigation = (() => {
  const mobile = matchMedia("(max-width: 860px)");
  let opened = false,
    trigger,
    scrollY = 0,
    currentPage;
  const drawer = () => document.querySelector("#navigation");
  const toggles = () => document.querySelectorAll("[data-nav-toggle]");

  function close(restore = true) {
    setOpen(false, restore);
  }
  function setOpen(value, restore = true) {
    const nav = drawer();
    const next = value && mobile.matches;
    if (next === opened) return;
    opened = next;
    if (next) {
      trigger = document.activeElement;
      scrollY = window.scrollY;
      document.body.style.setProperty("--nav-scroll-top", `-${scrollY}px`);
    }
    document.body.classList.toggle("nav-open", next);
    nav.classList.toggle("is-open", next);
    nav.inert = mobile.matches && !next;
    document.querySelector("#nav-backdrop").hidden = !next;
    document.querySelector(".workspace").inert = next;
    document.querySelector("#mobile-navigation").inert = next;
    toggles().forEach((el) => el.setAttribute("aria-expanded", String(next)));
    if (next) {
      nav.setAttribute("role", "dialog");
      nav.setAttribute("aria-modal", "true");
      requestAnimationFrame(() => {
        if (opened)
          document
            .querySelector("#close-navigation")
            .focus({ preventScroll: true });
      });
    } else {
      nav.removeAttribute("role");
      nav.removeAttribute("aria-modal");
      document.body.style.removeProperty("--nav-scroll-top");
      window.scrollTo(0, scrollY);
      if (restore && trigger?.isConnected && trigger.getClientRects().length)
        trigger.focus({ preventScroll: true });
    }
  }
  function routeChanged() {
    close(false);
    document.querySelector("#main").focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
  function sync(page) {
    document
      .querySelectorAll("[data-page], [data-nav-target]")
      .forEach((el) => {
        const active = (el.dataset.page || el.dataset.navTarget) === page;
        el.classList.toggle("active", active);
        if (active) el.setAttribute("aria-current", "page");
        else el.removeAttribute("aria-current");
      });
    document.querySelectorAll(".nav-group").forEach((group) => {
      group.hidden = ![...group.querySelectorAll("[data-page]")].some(
        (el) => !el.hidden,
      );
      const active = Boolean(group.querySelector("a.active:not([hidden])"));
      group.classList.toggle("has-active", active);
      if (currentPage !== page && active) group.open = true;
    });
    document
      .querySelector("#mobile-navigation button")
      .classList.toggle(
        "active",
        !["overview", "users", "nodes"].includes(page),
      );
    currentPage = page;
  }
  function labelTables() {
    document.querySelectorAll("#main table").forEach((table) => {
      const headers = [...table.querySelectorAll("thead th")].map((el) =>
        el.textContent.trim(),
      );
      if (!headers.length) return;
      table.classList.add("responsive-table");
      table.setAttribute("role", "table");
      table.querySelectorAll("thead th").forEach((th) => {
        th.scope = "col";
      });
      table.querySelectorAll("tbody tr").forEach((row) => {
        [...row.cells].forEach((cell, index) => {
          cell.dataset.label = cell.colSpan > 1 ? "" : headers[index] || "";
        });
      });
    });
  }
  function init() {
    drawer().inert = mobile.matches;
    // Start with a compact hierarchy; sync opens the group containing a deep link.
    if (mobile.matches)
      document.querySelectorAll(".nav-group").forEach((el) => {
        el.open = false;
      });
    toggles().forEach((el) =>
      el.addEventListener("click", () => setOpen(!opened)),
    );
    document
      .querySelector("#close-navigation")
      .addEventListener("click", () => close());
    document
      .querySelector("#nav-backdrop")
      .addEventListener("click", () => close());
    document
      .querySelectorAll("#navigation a[href], #mobile-navigation a[href]")
      .forEach((el) => {
        el.addEventListener("click", (event) => {
          if (
            !event.ctrlKey &&
            !event.metaKey &&
            !event.shiftKey &&
            !event.altKey &&
            event.button === 0
          )
            routeChanged();
        });
      });
    mobile.addEventListener("change", () => {
      const focusWasInside = drawer().contains(document.activeElement);
      close(false);
      drawer().inert = mobile.matches;
      if (mobile.matches)
        document.querySelectorAll(".nav-group").forEach((group) => {
          group.open = group.classList.contains("has-active");
        });
      // CSS may hide a focused desktop link before matchMedia dispatches.
      if (
        mobile.matches &&
        !document.querySelector("#app-view").hidden &&
        (focusWasInside || document.activeElement === document.body)
      )
        document
          .querySelector("[data-nav-toggle]")
          .focus({ preventScroll: true });
    });
    document.addEventListener("keydown", (event) => {
      if (!opened) return;
      if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
      if (event.key !== "Tab") return;
      const items = [
        ...drawer().querySelectorAll("a[href], button, summary"),
      ].filter((el) => el.getClientRects().length && !el.disabled);
      const first = items[0],
        last = items.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
    new MutationObserver(labelTables).observe(document.querySelector("#main"), {
      childList: true,
      subtree: true,
    });
    labelTables();
  }
  return { init, sync, close, routeChanged };
})();
