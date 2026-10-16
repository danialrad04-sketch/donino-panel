"use strict";
const $ = (s) => document.querySelector(s);
const token = location.pathname.split("/").filter(Boolean)[1];
const number = (n) => new Intl.NumberFormat("fa-IR").format(n);
const bytes = (n) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : n >= 1048576
      ? (n / 1048576).toFixed(1) + " MB"
      : number(n) + " B";
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const states = {
  active: "فعال",
  disabled: "غیرفعال",
  expired: "منقضی",
  limited: "اتمام حجم",
};
let info, timer;
document.documentElement.dataset.theme =
  localStorage.getItem("donino-theme") || "dark";

async function load() {
  $("#portal-refresh").disabled = true;
  try {
    const response = await fetch("/api/portal/" + encodeURIComponent(token));
    if (!response.ok)
      throw new Error(
        response.status === 404
          ? "اشتراک پیدا نشد یا لینک آن تغییر کرده است."
          : "دریافت اطلاعات ممکن نشد. دوباره امتحان کنید.",
      );
    info = await response.json();
    $("#portal-error").hidden = true;
    $("#portal-content").hidden = false;
    $("#portal-greeting").textContent =
      info.name + "، به فضای اختصاصی خود خوش آمدید.";
    $("#portal-status").textContent = states[info.status];
    $("#portal-status").className = "badge " + info.status;
    $("#remaining").textContent =
      info.remaining === null ? "نامحدود" : bytes(info.remaining);
    $("#quota").textContent = info.quota
      ? "از " + bytes(info.quota) + " سهمیه"
      : "بدون محدودیت حجم";
    if (info.quota_mode === "lease") {
      $("#quota").textContent +=
        "؛ " + bytes(info.budget_reserved || 0) + " تخصیص‌یافته به نودها";
      if (info.budget_unreconciled)
        $("#quota").textContent +=
          "، " + bytes(info.budget_unreconciled) + " در انتظار تسویه";
    }
    $("#used").textContent = bytes(info.used);
    $("#traffic-detail").textContent =
      "ارسال " + bytes(info.uploaded) + "، دریافت " + bytes(info.downloaded);
    $("#expiry").textContent = info.expires
      ? new Date(info.expires * 1000).toLocaleDateString("fa-IR")
      : "بدون انقضا";
    $("#days-left").textContent = info.expires
      ? number(
          Math.max(0, Math.ceil((info.expires * 1000 - Date.now()) / 86400000)),
        ) + " روز باقی‌مانده"
      : "اعتبار زمانی نامحدود";
    $("#legacy-note").hidden = !info.legacy_used;
    const active = info.status === "active";
    $(".portal-connect").hidden = !active;
    $("#inactive-notice").hidden = active;
    $("#subscription-link").value = info.subscription_url || "";
    if (active) {
      $("#subscription-qr").src = info.qr_url;
      $("#download-profile").href = info.subscription_url;
    } else {
      $("#subscription-qr").removeAttribute("src");
      $("#download-profile").removeAttribute("href");
    }
    $("#profile-count").textContent =
      number(info.profiles.length) + " مسیر اتصال";
    $("#profile-list").innerHTML =
      info.profiles
        .map(
          (p, i) =>
            `<details class="card profile-item"><summary><span>${esc(p.name)}</span><span class="badge active mono">${esc(p.protocol.toUpperCase())}</span></summary><div class="profile-detail"><div><label>لینک اتصال<textarea readonly dir="ltr">${esc(p.uri)}</textarea></label><button class="secondary" data-profile="${i}">کپی اتصال</button></div><figure class="portal-qr"><img src="${esc(p.qr_url)}" loading="lazy" alt="QR اتصال ${esc(p.name)}"></figure></div></details>`,
        )
        .join("") ||
      '<div class="card empty">اتصال فعالی برای این اشتراک در دسترس نیست.</div>';
  } catch (error) {
    // Clear old secrets after token rotation or failed refresh.
    info = null;
    $("#portal-content").hidden = true;
    $("#subscription-link").value = "";
    $("#subscription-qr").removeAttribute("src");
    $("#profile-list").replaceChildren();
    $("#portal-error").textContent = error.message;
    $("#portal-error").hidden = false;
  } finally {
    $("#portal-refresh").disabled = false;
  }
}
async function copy(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    $("#toast").textContent = "کپی شد";
  } catch {
    $("#toast").textContent =
      "متن را انتخاب و با گزینهٔ کپی دستگاه خود کپی کنید.";
  }
  $("#toast").hidden = false;
  clearTimeout(timer);
  timer = setTimeout(() => ($("#toast").hidden = true), 4000);
}
$("#portal-theme").onclick = () => {
  const t =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  localStorage.setItem("donino-theme", t);
};
$("#portal-refresh").onclick = load;
$("#copy-subscription").onclick = () => copy(info?.subscription_url);
$("#copy-clash").onclick = () =>
  copy(info?.subscription_url ? info.subscription_url + "?format=clash" : null);
document.addEventListener("click", (e) => {
  const button = e.target.closest("[data-profile]");
  if (button) copy(info?.profiles[Number(button.dataset.profile)]?.uri);
});
load();
