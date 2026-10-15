"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const number = (n) => new Intl.NumberFormat("fa-IR").format(n);
const bytes = (n) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : n >= 1048576
      ? (n / 1048576).toFixed(1) + " MB"
      : number(n) + " B";
const date = (n) =>
  n ? new Date(n * 1000).toLocaleDateString("fa-IR") : "بدون انقضا";
const states = {
  active: "فعال",
  disabled: "غیرفعال",
  expired: "منقضی",
  limited: "اتمام حجم",
};
const roles = {
  owner: "مالک شبکه",
  operator: "مدیر کاربران",
  viewer: "مشاهده‌گر",
};
const titles = {
  overview: "نمای کلی",
  users: "کاربران",
  nodes: "نودهای شبکه",
  inbounds: "اتصال‌ها",
  audit: "رویدادها",
  settings: "تنظیمات",
};
let account,
  data = { users: [], nodes: [], inbounds: [], overview: {} },
  page = "overview",
  timer,
  toastTimer,
  loading = false;
let bootstrapToken = location.hash.startsWith("#setup=")
  ? location.hash.slice(7)
  : "";
if (bootstrapToken) history.replaceState(null, "", location.pathname);
document.documentElement.dataset.theme =
  localStorage.getItem("donino-theme") || "dark";

async function api(path, options = {}) {
  const response = await fetch("/api" + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Donino": "1",
      ...options.headers,
    },
  });
  if (!response.ok) {
    if (response.status === 401 && path !== "/login") showLogin();
    const result = await response.json().catch(() => ({}));
    const detail = Array.isArray(result.detail)
      ? result.detail.map((e) => e.msg).join(" · ")
      : result.detail;
    throw new Error(detail || "ارتباط با سرور برقرار نشد");
  }
  return response.json();
}
function toast(message, error = false) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  $("#toast").className = "toast" + (error ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 5000);
}
function showLogin() {
  clearInterval(timer);
  account = null;
  $("#app-view").hidden = true;
  $("#login-view").hidden = false;
  $("#login-form").hidden = Boolean(bootstrapToken);
  $("#bootstrap-form").hidden = !bootstrapToken;
}
function writable() {
  return account && account.role !== "viewer";
}
function owner() {
  return account && account.role === "owner";
}
function badge(state, text) {
  return `<span class="badge ${esc(state)}">● ${esc(text || states[state])}</span>`;
}
function empty(title, text, icon = "◇") {
  return `<div class="empty"><span class="empty-icon">${icon}</span><b>${esc(title)}</b><span>${esc(text)}</span></div>`;
}
function heading(title, description, action = "") {
  return `<div class="page-heading"><div><span class="eyebrow">DONINO / ${esc(page.toUpperCase())}</span><h1>${title}</h1><p>${description}</p></div>${action}</div>`;
}
function addButton(kind, text) {
  return `<button class="primary" data-action="add-${kind}"><span>＋</span>${text}</button>`;
}
function nodeRows() {
  return (
    data.nodes
      .slice(0, 4)
      .map(
        (n) =>
          `<div class="node-row"><span class="node-symbol">⌘</span><div><b>${esc(n.name)}</b><small>${esc(n.host)}</small></div>${badge(n.online ? "active" : "disabled", n.online ? "متصل" : "قطع")}</div>`,
      )
      .join("") ||
    empty(
      "اولین نود را اضافه کنید",
      "سرورهای شبکه را از بخش نودها متصل کنید.",
      "⌘",
    )
  );
}
function usersTable(users, compact = false) {
  if (!users.length)
    return empty(
      "هنوز کاربری وجود ندارد",
      "با ساخت اولین کاربر، مدیریت دسترسی را شروع کنید.",
      "♧",
    );
  return `<div class="table-scroll"><table><thead><tr><th>نام کاربر</th><th>وضعیت</th><th>مصرف / سهمیه</th><th>تاریخ انقضا</th>${!compact && writable() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${users.map((u) => `<tr><td><b>${esc(u.name)}</b><span class="subline">${esc(u.id.slice(0, 8))}</span></td><td>${badge(u.status)}</td><td><span class="mono">${bytes(u.used)} / ${u.quota ? bytes(u.quota) : "∞"}</span></td><td>${date(u.expires)}</td>${!compact && writable() ? `<td class="actions"><button data-action="share" data-id="${u.id}">اشتراک</button><button data-action="devices" data-id="${u.id}">دستگاه‌ها</button><button data-action="edit-user" data-id="${u.id}">ویرایش</button><button data-action="delete-user" data-id="${u.id}" class="danger">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>`;
}
function renderOverview() {
  const s = data.overview;
  const topUsers = [...data.users]
    .sort((a, b) => b.used - a.used)
    .filter((u) => u.used)
    .slice(0, 4);
  const max = Math.max(...topUsers.map((u) => u.used), 1);
  return (
    heading(
      "شبکه، در یک نگاه",
      `خوش آمدی، ${esc(account.username)}. وضعیت دسترسی‌ها و زیرساخت را اینجا ببین.`,
      writable() ? addButton("user", "کاربر جدید") : "",
    ) +
    `<section class="stats" aria-label="آمار شبکه"><div class="stat featured"><span>کاربران فعال</span><i class="stat-icon">♧</i><strong>${number(s.active || 0)}</strong><small>از ${number(s.users || 0)} کاربر شبکه</small></div><div class="stat"><span>مصرف ثبت‌شده</span><i class="stat-icon">↗︎</i><strong dir="ltr">${bytes(s.used || 0)}</strong><small>مجموع ترافیک کاربران</small></div><div class="stat"><span>نودهای متصل</span><i class="stat-icon">⌘</i><strong>${number(s.online_nodes || 0)} <small>/ ${number(s.nodes || 0)}</small></strong><small>وضعیت آخرین ارتباط با نودها</small></div><div class="stat"><span>اتصال‌های تعریف‌شده</span><i class="stat-icon">⇄</i><strong>${number(s.inbounds || 0)}</strong><small>VLESS · VMess · Trojan</small></div></section>
  <section class="overview-grid"><div class="card"><div class="card-head"><h2>مصرف کاربران</h2><small>بر اساس ترافیک ثبت‌شده</small></div>${topUsers.length ? topUsers.map((u) => `<div class="usage-row"><div><span>${esc(u.name)}</span><b>${bytes(u.used)}</b></div><progress value="${u.used}" max="${max}" aria-label="مصرف ${esc(u.name)}"></progress></div>`).join("") : empty("شبکه آمادهٔ شروع است", "پس از اتصال نود و شروع مصرف، آمار اینجا نمایش داده می‌شود.", "↗︎")}</div><div class="card"><div class="card-head"><h2>نبض زیرساخت</h2><a href="#nodes">همهٔ نودها ←</a></div>${nodeRows()}</div></section>
  <section class="card table-card"><div class="table-toolbar"><h2>آخرین کاربران</h2><a class="subtle-link" href="#users">مدیریت کاربران ←</a></div>${usersTable(data.users.slice(0, 5), true)}<div class="table-bottom">هر کاربر، یک اشتراک برای تمام اتصال‌های شبکه.</div></section>`
  );
}
function renderUsers() {
  return (
    heading(
      "کاربران شبکه",
      "دسترسی، حجم مصرفی و زمان اعتبار کاربران را مدیریت کن.",
      writable() ? addButton("user", "کاربر جدید") : "",
    ) +
    `<section class="card table-card"><div class="table-toolbar"><h2>${number(data.users.length)} کاربر <small class="muted">· حداکثر ۱۰۰۰ رکورد اخیر</small></h2><input id="search-users" class="search" type="search" placeholder="جست‌وجوی کاربر…" aria-label="جست‌وجوی کاربر"></div><div id="users-table">${usersTable(data.users)}</div></section>`
  );
}
function renderNodes() {
  return (
    heading(
      "نودهای شبکه",
      "سرورهای مستقل، یک نقطهٔ کنترل.",
      owner() ? addButton("node", "نود جدید") : "",
    ) +
    `<div class="node-grid">${data.nodes.map((n) => `<article class="card"><div class="node-row"><span class="node-symbol">⌘</span><div><b>${esc(n.name)}</b><small>${esc(n.host)}</small></div>${badge(n.online ? "active" : "disabled", n.online ? "متصل" : "قطع")}</div><div class="node-meta"><span>${number(data.inbounds.filter((i) => i.node_id === n.id).length)} اتصال</span><span>آخرین ارتباط: ${n.last_seen ? new Date(n.last_seen * 1000).toLocaleTimeString("fa-IR") : "هنوز متصل نشده"}</span></div><div class="node-meta"><span>عامل: <span class="mono">${esc(n.agent_version || "0.1 / نامشخص")}</span></span><span>${{ hot: "به‌روزرسانی زنده", restart: "اجرای کامل", rollback: "بازیابی تنظیمات" }[n.apply_mode] || "در انتظار همگام‌سازی"} · ${number(n.pending_usage || 0)} گزارش معوق</span></div>${n.error ? `<p class="node-error">${esc(n.error)}</p>` : ""}${owner() ? `<div class="compact-actions"><button class="secondary" data-action="assignments" data-id="${n.id}">تخصیص کاربران</button><button class="secondary" data-action="rotate-node" data-id="${n.id}">تعویض کلید اتصال</button><button class="outline-button danger" data-action="delete-node" data-id="${n.id}">حذف نود</button></div>` : ""}</article>`).join("")}</div>${!data.nodes.length ? `<div class="card">${empty("زیرساختت را بساز", "نود جدید اضافه کن و عامل Donino را روی سرور اجرا کن.", "⌘")}</div>` : ""}`
  );
}
function renderInbounds() {
  return (
    heading(
      "اتصال‌های شبکه",
      "مسیرهای امن اتصال برای تمام کاربران فعال.",
      owner() ? addButton("inbound", "اتصال جدید") : "",
    ) +
    `<div class="notice">VLESS با REALITY · VMess با WebSocket و TLS · Trojan با TLS. گواهی‌های TLS باید روی سرور نود قرار داشته باشند.</div><section class="card table-card">${data.inbounds.length ? `<div class="table-scroll"><table><thead><tr><th>نام اتصال</th><th>پروتکل</th><th>نود</th><th>پورت</th><th>دامنه</th>${owner() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${data.inbounds.map((i) => `<tr><td>${esc(i.name)}</td><td><span class="badge ${i.enabled ? "active" : "disabled"} mono">${esc(i.protocol.toUpperCase())} · ${i.enabled ? "فعال" : "خاموش"}</span></td><td>${esc(i.node_name)}</td><td class="mono">${i.port}</td><td><span class="mono">${esc(i.settings.sni)}</span></td>${owner() ? `<td><button data-action="edit-inbound" data-id="${i.id}">ویرایش</button> <button class="danger" data-action="delete-inbound" data-id="${i.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : empty("یک مسیر تازه بساز", "ابتدا نود را اضافه کن، سپس اولین اتصال را بساز.", "⇄")}</section>`
  );
}
function renderSettings() {
  return (
    heading("تنظیمات و نگهداری", "همه‌چیز برای مدیریت یک شبکهٔ مستقل.") +
    `<div class="settings-grid"><article class="card"><h2>پشتیبان‌گیری</h2><p>یک نسخهٔ کامل از پایگاه داده، تنظیمات و حساب‌ها دریافت کن. فایل پشتیبان حاوی اطلاعات محرمانه است؛ آن را امن نگه دار. برای بازیابی ورود دومرحله‌ای، کلید اصلی سرور (master.key) نیز باید جداگانه پشتیبان داشته باشد.</p>${owner() ? '<a class="primary" href="/api/backup" download>دریافت نسخهٔ پشتیبان ↓</a>' : "<p>دریافت پشتیبان فقط برای مالک شبکه فعال است.</p>"}</article><article class="card"><h2>ظاهر پنل</h2><p>پوستهٔ روشن یا تیره را انتخاب کن. انتخاب روی همین دستگاه ذخیره می‌شود.</p><button class="secondary" data-action="theme">تغییر پوسته ◐</button></article><article class="card"><h2>امنیت و دسترسی API</h2><p>ورود دومرحله‌ای، کدهای بازیابی و کلیدهای محدودِ اتوماسیون را مدیریت کن.</p><button class="secondary" data-action="security">مدیریت امنیت</button></article><article class="card"><h2>حساب مدیریت</h2><p>نام کاربری: ${esc(account.username)}<br>سطح دسترسی: ${roles[account.role]}<br>برای ساخت مدیر یا تغییر رمز، از دستور <span class="mono">python -m app.cli admin USERNAME</span> روی سرور استفاده کن.</p></article><article class="card"><h2>Donino Panel <span class="mono">1.0 alpha 2</span></h2><p>نسخهٔ اولیهٔ مستقل، با رابط فارسی و مدیریت چند نود. امکانات در حال توسعه‌اند. راه‌اندازی واقعی به سرور نود، Xray و دامنهٔ مناسب نیاز دارد.</p><a class="subtle-link" href="https://github.com/danialrad04-sketch/donino-panel" target="_blank" rel="noopener">مستندات و کد منبع ↗︎</a></article></div>`
  );
}
function render() {
  if (!account) return;
  document
    .querySelectorAll("[data-owner]")
    .forEach((e) => (e.hidden = !owner()));
  document
    .querySelectorAll("[data-page]")
    .forEach((e) => e.classList.toggle("active", e.dataset.page === page));
  $("#breadcrumb").textContent = titles[page];
  const views = {
    overview: renderOverview,
    users: renderUsers,
    nodes: renderNodes,
    inbounds: renderInbounds,
    settings: renderSettings,
  };
  if (page === "audit") {
    $("#main").innerHTML =
      heading(
        "رویدادهای مدیریت",
        "تاریخچهٔ فعالیت مدیران، برای شفافیت بیشتر.",
      ) + '<div class="card" id="audit-list">در حال دریافت…</div>';
    if (owner())
      api("/audit")
        .then((events) => {
          if (page !== "audit") return;
          $("#audit-list").innerHTML = events.length
            ? `<div class="table-scroll"><table><thead><tr><th>زمان</th><th>مدیر</th><th>عملیات</th><th>شناسه</th></tr></thead><tbody>${events.map((e) => `<tr><td>${new Date(e.at * 1000).toLocaleString("fa-IR")}</td><td>${esc(e.actor)}</td><td><span class="mono">${esc(e.action)}</span></td><td><span class="mono">${esc(e.target.slice(0, 12))}</span></td></tr>`).join("")}</tbody></table></div>`
            : empty("رویدادی ثبت نشده", "فعالیت‌های مدیران اینجا ثبت می‌شود.");
        })
        .catch((e) => toast(e.message, true));
    else $("#audit-list").textContent = "دسترسی مالک لازم است.";
  } else $("#main").innerHTML = (views[page] || renderOverview)();
}
async function refresh(redraw = true) {
  if (loading || !account) return;
  loading = true;
  try {
    const [users, nodes, inbounds, overview] = await Promise.all(
      ["/users", "/nodes", "/inbounds", "/overview"].map((p) => api(p)),
    );
    data = { users, nodes, inbounds, overview };
    $("#sync-status").textContent =
      "به‌روز شد · " +
      new Date().toLocaleTimeString("fa-IR", {
        hour: "2-digit",
        minute: "2-digit",
      });
    if (redraw) render();
  } catch (error) {
    $("#sync-status").textContent = "خطا در به‌روزرسانی";
    toast(error.message, true);
  } finally {
    loading = false;
  }
}
async function enter(user) {
  account = user;
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#account-name").textContent = user.username;
  $("#account-role").textContent = roles[user.role];
  page = titles[location.hash.slice(1)] ? location.hash.slice(1) : "overview";
  await refresh();
  clearInterval(timer);
  timer = setInterval(() => {
    if (!$("#modal").open && !$("#search-users")?.value) refresh();
  }, 15000);
}
function modal(title, html) {
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = html;
  $("#modal").showModal();
}
function input(label, name, options = {}) {
  const {
    value = "",
    type = "text",
    extra = "",
    hint = "",
    required = true,
    full = false,
  } = options;
  return `<label class="${full ? "full" : ""}">${label}<input name="${name}" type="${type}" value="${esc(value)}" ${required ? "required" : ""} ${extra}>${hint ? `<small>${hint}</small>` : ""}</label>`;
}
function form(title, fields, save) {
  modal(
    title,
    `<form id="edit-form"><div class="form-grid">${fields}</div><p id="form-error" class="error"></p><div class="form-actions"><button type="button" class="secondary" data-action="close-modal">انصراف</button><button class="primary" type="submit">ذخیره ←</button></div></form>`,
  );
  $("#edit-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = e.target.querySelector("[type=submit]");
    button.disabled = true;
    try {
      await save(Object.fromEntries(new FormData(e.target)));
    } catch (error) {
      $("#form-error").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
}
async function saved() {
  $("#modal").close();
  await refresh();
  toast("تغییرات ذخیره شد");
}
function editUser(user) {
  form(
    user ? "ویرایش کاربر" : "کاربر جدید",
    input("نام کاربر", "name", {
      value: user?.name || "",
      full: true,
      extra: 'maxlength="80"',
    }) +
      input("سهمیه (گیگابایت)", "quota", {
        type: "number",
        value: user?.quota ? user.quota / 1073741824 : 0,
        extra: 'min="0" max="8000000" step="0.01" dir="ltr"',
        hint: "صفر = نامحدود",
      }) +
      input("انقضا", "expires", {
        type: "datetime-local",
        value: user?.expires
          ? new Date(
              user.expires * 1000 -
                new Date(user.expires * 1000).getTimezoneOffset() * 60000,
            )
              .toISOString()
              .slice(0, 16)
          : "",
        required: false,
        hint: "خالی = بدون انقضا",
      }) +
      `<label class="check full"><input name="enabled" type="checkbox" ${!user || user.enabled ? "checked" : ""}>دسترسی کاربر فعال باشد</label>` +
      (user
        ? `<div class="full compact-actions"><button type="button" class="secondary" data-action="reset-traffic" data-id="${user.id}">صفر کردن مصرف</button><button type="button" class="secondary" data-action="rotate-subscription" data-id="${user.id}">تعویض لینک</button><button type="button" class="secondary" data-action="rotate-credentials" data-id="${user.id}">تعویض کلید کاربر</button></div>`
        : ""),
    async (f) => {
      await api("/users" + (user ? "/" + user.id : ""), {
        method: user ? "PUT" : "POST",
        body: JSON.stringify({
          name: f.name,
          quota: Math.round(Number(f.quota) * 1073741824),
          expires: f.expires
            ? Math.floor(new Date(f.expires).getTime() / 1000)
            : null,
          enabled: f.enabled === "on",
        }),
      });
      await saved();
    },
  );
}
function showNodeToken(token) {
  modal(
    "کلید اتصال نود",
    `<p class="note">این کلید فقط همین یک بار نمایش داده می‌شود. آن را به‌عنوان متغیر <span class="mono">DONINO_NODE_TOKEN</span> در فایل تنظیمات عامل نود ذخیره کن. راهنمای نصب در مخزن پروژه قرار دارد.</p><label class="full">کلید محرمانه<textarea id="secret-output" readonly dir="ltr">${esc(token)}</textarea></label><div class="form-actions"><button class="primary" data-action="copy-secret">کپی کلید</button></div>`,
  );
}
function editInbound(inbound) {
  if (!data.nodes.length) return toast("ابتدا یک نود اضافه کن.", true);
  const settings = inbound?.settings || {};
  form(
    inbound ? "ویرایش اتصال" : "اتصال جدید",
    `<label>نود<select name="node_id">${data.nodes.map((n) => `<option value="${n.id}" ${inbound?.node_id === n.id ? "selected" : ""}>${esc(n.name)}</option>`).join("")}</select></label><label>پروتکل<select name="protocol" id="protocol">${[
      ["vless", "VLESS + REALITY"],
      ["vmess", "VMess + WS/TLS"],
      ["trojan", "Trojan + TLS"],
    ]
      .map(
        ([value, label]) =>
          `<option value="${value}" ${inbound?.protocol === value ? "selected" : ""}>${label}</option>`,
      )
      .join("")}</select></label>` +
      input("نام اتصال", "name", { value: inbound?.name || "اتصال اصلی" }) +
      input("پورت", "port", {
        type: "number",
        value: inbound?.port || 443,
        extra: 'min="1" max="65535" dir="ltr"',
      }) +
      input("دامنهٔ SNI", "sni", {
        value: settings.sni || "www.microsoft.com",
        full: true,
        extra: 'dir="ltr"',
      }) +
      `<div id="reality-fields" class="full">${input("مقصد REALITY", "target", { value: settings.target || "www.microsoft.com:443", extra: 'dir="ltr"' })}</div><div id="tls-fields" class="full"><div class="form-grid">${input("مسیر گواهی روی نود", "cert_file", { value: settings.cert_file || "", required: false, extra: 'dir="ltr"', hint: "مثال: /etc/donino/tls/fullchain.pem" })}${input("مسیر کلید روی نود", "key_file", { value: settings.key_file || "", required: false, extra: 'dir="ltr"', hint: "مثال: /etc/donino/tls/privkey.pem" })}${input("مسیر WebSocket", "path", { value: settings.path || "/donino", extra: 'dir="ltr"', required: false, full: true })}</div></div><label class="check full"><input type="checkbox" name="enabled" ${!inbound || inbound.enabled ? "checked" : ""}>اتصال فعال باشد</label>` +
      (inbound
        ? '<p class="note full">تغییر پورت یا تنظیمات انتقال باعث راه‌اندازی مجدد هستهٔ نود می‌شود. کلید REALITY هنگام ویرایش همین پروتکل حفظ می‌شود.</p>'
        : ""),
    async (f) => {
      await api("/inbounds" + (inbound ? "/" + inbound.id : ""), {
        method: inbound ? "PUT" : "POST",
        body: JSON.stringify({
          ...f,
          port: Number(f.port),
          enabled: f.enabled === "on",
          target: f.target || "www.microsoft.com:443",
          path: f.path || "/donino",
        }),
      });
      await saved();
    },
  );
  const updateFields = () => {
    const protocol = $("#protocol").value;
    $("#reality-fields").hidden = protocol !== "vless";
    $("#tls-fields").hidden = protocol === "vless";
    document
      .querySelectorAll(
        "#tls-fields [name=cert_file],#tls-fields [name=key_file]",
      )
      .forEach((e) => (e.required = protocol !== "vless"));
  };
  $("#protocol").addEventListener("change", updateFields);
  updateFields();
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("کپی شد");
  } catch {
    toast("کپی خودکار در دسترس نیست؛ متن را انتخاب و کپی کن.", true);
  }
}
async function confirmAction(title, description, action) {
  form(title, `<p class="note full">${esc(description)}</p>`, async () => {
    await action();
    await saved();
  });
}
async function handleAction(action, id) {
  if (
    [
      "devices",
      "device-add",
      "device-toggle",
      "device-rotate",
      "assignments",
      "security",
      "mfa-setup",
      "mfa-disable",
      "token-add",
      "token-delete",
    ].includes(action)
  )
    return foundationAction(action, id);
  const user = data.users.find((u) => u.id === id);
  if (action === "add-user") return editUser();
  if (action === "edit-user") return editUser(user);
  if (action === "close-modal") return $("#modal").close();
  if (action === "logout") {
    await api("/logout", { method: "POST" });
    showLogin();
    return;
  }
  if (action === "theme") {
    const t =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    localStorage.setItem("donino-theme", t);
    return;
  }
  if (action === "add-node")
    return form(
      "نود جدید",
      input("نام نود", "name", { value: "نود اصلی" }) +
        input("دامنه یا IP سرور", "host", {
          extra: 'dir="ltr"',
          hint: "بدون https و بدون پورت",
        }),
      async (f) => {
        const node = await api("/nodes", {
          method: "POST",
          body: JSON.stringify(f),
        });
        await saved();
        showNodeToken(node.token);
      },
    );
  if (action === "rotate-node")
    return form(
      "تعویض کلید نود",
      '<p class="note full">کلید قبلی باطل می‌شود. کلید جدید را روی عامل نود جایگزین کن تا دوباره متصل شود.</p>',
      async () => {
        const result = await api(`/nodes/${id}/rotate-token`, {
          method: "POST",
        });
        await saved();
        showNodeToken(result.token);
      },
    );
  if (action === "copy-portal")
    return copyText($("[data-action=copy-portal]").dataset.url);
  if (action === "copy-secret") return copyText($("#secret-output").value);
  if (action === "add-inbound") return editInbound();
  if (action === "edit-inbound")
    return editInbound(data.inbounds.find((i) => i.id === id));
  if (action === "share") {
    const result = await api(`/users/${id}/subscription`);
    modal(
      "اشتراک " + user.name,
      `<p class="note">لینک خصوصی کاربر را کپی کن یا صفحهٔ اختصاصی او را باز کن. QR روی همین سرور تولید می‌شود.</p><img class="share-qr" src="${esc(result.qr_url)}" alt="QR اشتراک"><label>لینک اشتراک<textarea id="secret-output" dir="ltr" readonly>${esc(result.url)}</textarea></label><div class="form-actions"><a class="outline-button" id="open-portal" href="${esc(result.portal_url)}" target="_blank" rel="noopener">صفحهٔ کاربر ↗︎</a><button class="secondary" data-action="copy-portal" data-url="${esc(result.portal_url)}">کپی صفحه</button><button class="secondary" data-action="copy-clash">Clash</button><button class="primary" data-action="copy-secret">کپی اشتراک</button></div>`,
    );
    return;
  }
  if (action === "copy-clash")
    return copyText($("#secret-output").value + "?format=clash");
  if (action === "delete-user")
    return confirmAction(
      "حذف کاربر",
      "کاربر و اشتراک او حذف می‌شوند. این عملیات قابل بازگشت نیست.",
      () => api("/users/" + id, { method: "DELETE" }),
    );
  if (action === "delete-node")
    return confirmAction(
      "حذف نود",
      "نود و تمام اتصال‌های آن حذف می‌شوند. عامل نود پس از تشخیص باطل شدن کلید، Xray را متوقف می‌کند.",
      () => api("/nodes/" + id, { method: "DELETE" }),
    );
  if (action === "delete-inbound")
    return confirmAction(
      "حذف اتصال",
      "این مسیر اتصال از تنظیمات نود و اشتراک کاربران حذف می‌شود.",
      () => api("/inbounds/" + id, { method: "DELETE" }),
    );
  if (action === "reset-traffic")
    return confirmAction(
      "صفر کردن مصرف",
      "مصرف ثبت‌شدهٔ این کاربر صفر می‌شود.",
      () => api(`/users/${id}/reset-traffic`, { method: "POST" }),
    );
  if (action === "rotate-subscription")
    return confirmAction(
      "تعویض لینک اشتراک",
      "لینک قبلی اشتراک باطل می‌شود. تنظیماتی که قبلاً دریافت شده‌اند همچنان همان شناسهٔ اتصال را دارند.",
      () => api(`/users/${id}/rotate-subscription`, { method: "POST" }),
    );
  if (action === "rotate-credentials")
    return confirmAction(
      "تعویض کلید کاربر",
      "شناسهٔ اتصال و لینک اشتراک عوض می‌شود. تنظیمات قبلی پس از همگام‌سازی نود دیگر کار نمی‌کنند؛ لینک جدید را به کاربر بده.",
      () => api(`/users/${id}/rotate-credentials`, { method: "POST" }),
    );
}
document.addEventListener("click", (e) => {
  const target = e.target.closest("[data-action]");
  if (target)
    handleAction(target.dataset.action, target.dataset.id).catch((error) =>
      toast(error.message, true),
    );
});
document.addEventListener("input", (e) => {
  if (e.target.id === "search-users")
    $("#users-table").innerHTML = usersTable(
      data.users.filter((u) =>
        u.name.toLocaleLowerCase().includes(e.target.value.toLocaleLowerCase()),
      ),
    );
});
$("#close-modal").onclick = () => $("#modal").close();
$("#theme").onclick = () => handleAction("theme");
$("#refresh").onclick = () => refresh();
$("#logout").onclick = async () => {
  try {
    await api("/logout", { method: "POST" });
    showLogin();
  } catch (e) {
    toast(e.message, true);
  }
};
window.addEventListener("hashchange", () => {
  page = titles[location.hash.slice(1)] ? location.hash.slice(1) : "overview";
  render();
});
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.disabled = true;
  $("#login-error").textContent = "";
  try {
    const user = await api("/login", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(e.target))),
    });
    e.target.reset();
    await enter(user);
  } catch (error) {
    $("#login-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
api("/me")
  .then(enter)
  .catch(() => showLogin());
