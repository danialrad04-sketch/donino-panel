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
const ICONS = {
  overview:
    '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  users: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  nodes:
    '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  inbounds: '<path d="M4 8h13l-3-3M20 16H7l3 3"/>',
  events:
    '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4 6h.01M4 12h.01M4 18h.01"/>',
  settings:
    '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
  theme: '<path d="M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z"/>',
  logout:
    '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  empty: '<circle cx="12" cy="12" r="8"/>',
};
function icon(name) {
  return `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.empty}</svg>`;
}
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
  const total = response.headers.get("X-Total-Count");
  if (total !== null) lastTotal = Number(total);
  if (!response.ok) {
    if (response.status === 401 && path !== "/login") showLogin();
    const result = await response.json().catch(() => ({}));
    const detail = Array.isArray(result.detail)
      ? result.detail.map((e) => e.msg).join("، ")
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
  return `<span class="badge ${esc(state)}">${esc(text || states[state])}</span>`;
}
function empty(title, text, name = "empty") {
  return `<div class="empty"><span class="empty-icon">${icon(name)}</span><b>${esc(title)}</b><span>${esc(text)}</span></div>`;
}
function heading(title, description, action = "") {
  return `<div class="page-heading"><div><h1>${title}</h1><p>${description}</p></div>${action}</div>`;
}
function addButton(kind, text) {
  return `<button class="primary" data-action="add-${kind}">${icon("plus")}${text}</button>`;
}
function nodeRows() {
  return (
    data.nodes
      .slice(0, 4)
      .map(
        (n) =>
          `<div class="node-row"><span class="node-symbol">${icon("nodes")}</span><div><b>${esc(n.name)}</b><small>${esc(n.host)}</small></div>${badge(n.online ? "active" : "disabled", n.online ? "متصل" : "قطع")}</div>`,
      )
      .join("") ||
    empty(
      "اولین نود را اضافه کنید",
      "سرورهای شبکه را از بخش نودها متصل کنید.",
      "nodes",
    )
  );
}
function usersTable(users, compact = false) {
  if (!users.length)
    return empty(
      "هنوز کاربری وجود ندارد",
      "با ساخت اولین کاربر، مدیریت دسترسی را شروع کنید.",
      "users",
    );
  return `<div class="table-scroll"><table><thead><tr><th>نام کاربر</th><th>وضعیت</th><th>مصرف / سهمیه</th><th>تاریخ انقضا</th>${!compact && writable() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${users.map((u) => `<tr><td><b>${esc(u.name)}</b><span class="subline">${esc(u.id.slice(0, 8))}</span></td><td>${badge(u.status)}</td><td><span class="mono">${bytes(u.used)} / ${u.quota ? bytes(u.quota) : "نامحدود"}</span></td><td>${date(u.expires)}</td>${!compact && writable() ? `<td class="actions"><button data-action="share" data-id="${u.id}">اشتراک</button><button data-action="edit-user" data-id="${u.id}">ویرایش</button><button data-action="user-nodes" data-id="${u.id}">نودها</button><button data-action="user-periods" data-id="${u.id}">دوره‌ها</button><button data-action="delete-user" data-id="${u.id}" class="danger">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>`;
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
    `<section class="stats" aria-label="آمار شبکه"><div class="stat"><span>کاربران فعال</span><strong>${number(s.active || 0)}</strong><small>از ${number(s.users || 0)} کاربر شبکه</small></div><div class="stat"><span>مصرف ثبت‌شده</span><strong dir="ltr">${bytes(s.used || 0)}</strong><small>مجموع ترافیک کاربران</small></div><div class="stat"><span>نودهای متصل</span><strong>${number(s.online_nodes || 0)} <small>/ ${number(s.nodes || 0)}</small></strong><small>وضعیت آخرین ارتباط با نودها</small></div><div class="stat"><span>اتصال‌های تعریف‌شده</span><strong>${number(s.inbounds || 0)}</strong><small>VLESS، VMess و Trojan</small></div></section>
  <section class="overview-grid"><div class="card"><div class="card-head"><h2>مصرف کاربران</h2><small>بر اساس ترافیک ثبت‌شده</small></div>${topUsers.length ? topUsers.map((u) => `<div class="usage-row"><div><span>${esc(u.name)}</span><b>${bytes(u.used)}</b></div><progress value="${u.used}" max="${max}" aria-label="مصرف ${esc(u.name)}"></progress></div>`).join("") : empty("شبکه آمادهٔ شروع است", "پس از اتصال نود و شروع مصرف، آمار اینجا نمایش داده می‌شود.", "chart")}</div><div class="card"><div class="card-head"><h2>وضعیت نودها</h2><a class="subtle-link" href="#nodes">همهٔ نودها</a></div>${nodeRows()}</div></section>
  <section class="card table-card"><div class="table-toolbar"><h2>آخرین کاربران</h2><a class="subtle-link" href="#users">مدیریت کاربران</a></div>${usersTable(data.users.slice(0, 5), true)}<div class="table-bottom">هر کاربر، یک اشتراک برای تمام اتصال‌های شبکه.</div></section>`
  );
}
let usersView = { q: "", state: "", offset: 0, limit: 25, total: 0, rows: [] };
let usersTimer;
let lastTotal = 0;
async function loadUsersPage() {
  if (page !== "users") return;
  const params = new URLSearchParams({
    limit: usersView.limit,
    offset: usersView.offset,
  });
  if (usersView.q) params.set("q", usersView.q);
  if (usersView.state) params.set("state", usersView.state);
  try {
    usersView.rows = await api("/users?" + params);
    usersView.total = lastTotal;
  } catch (error) {
    toast(error.message, true);
    return;
  }
  paintUsers();
}
function paintUsers() {
  if (page !== "users" || !$("#users-table")) return;
  $("#users-count").textContent = number(usersView.total) + " کاربر";
  $("#users-table").innerHTML = usersTable(usersView.rows);
  $("#users-pager").innerHTML = pagerHtml();
}
function pagerHtml() {
  if (!usersView.total) return "";
  const from = usersView.offset + 1;
  const to = Math.min(usersView.offset + usersView.limit, usersView.total);
  return `<div class="pager"><button type="button" class="secondary" data-action="users-prev" ${usersView.offset <= 0 ? "disabled" : ""}>قبلی</button><span class="muted">${number(from)}–${number(to)} از ${number(usersView.total)}</span><button type="button" class="secondary" data-action="users-next" ${to >= usersView.total ? "disabled" : ""}>بعدی</button></div>`;
}
function renderUsers() {
  return (
    heading(
      "کاربران شبکه",
      "دسترسی، حجم مصرفی و زمان اعتبار کاربران را مدیریت کن.",
      writable() ? addButton("user", "کاربر جدید") : "",
    ) +
    `<section class="card table-card"><div class="table-toolbar"><h2 id="users-count">${number(usersView.total)} کاربر</h2><div class="filters"><input id="search-users" class="search" type="search" value="${esc(usersView.q)}" placeholder="جست‌وجوی کاربر…" aria-label="جست‌وجوی کاربر"><select id="filter-state" aria-label="فیلتر وضعیت"><option value="">همه</option>${Object.entries(
      states,
    )
      .map(
        ([k, v]) =>
          `<option value="${k}" ${usersView.state === k ? "selected" : ""}>${v}</option>`,
      )
      .join(
        "",
      )}</select></div></div><div id="users-table">${usersTable(usersView.rows)}</div><div id="users-pager">${pagerHtml()}</div></section>`
  );
}
function renderNodes() {
  return (
    heading(
      "نودهای شبکه",
      "سرورهای مستقل، یک نقطهٔ کنترل.",
      owner() ? addButton("node", "نود جدید") : "",
    ) +
    `<div class="node-grid">${data.nodes.map((n) => `<article class="card"><div class="node-row"><span class="node-symbol">${icon("nodes")}</span><div><b>${esc(n.name)}</b><small>${esc(n.host)}</small></div>${badge(n.online ? "active" : "disabled", n.online ? "متصل" : "قطع")}</div><div class="node-meta"><span>${number(data.inbounds.filter((i) => i.node_id === n.id).length)} اتصال</span><span>آخرین ارتباط: ${n.last_seen ? new Date(n.last_seen * 1000).toLocaleTimeString("fa-IR") : "هنوز متصل نشده"}</span></div><div class="node-meta"><span>عامل: <span class="mono">${esc(n.agent_version || "0.1 / نامشخص")}</span></span><span>${{ hot: "به‌روزرسانی زنده", restart: "اجرای کامل", rollback: "بازیابی تنظیمات" }[n.apply_mode] || "در انتظار همگام‌سازی"}، ${number(n.pending_usage || 0)} گزارش معوق</span></div>${n.error ? `<p class="node-error">${esc(n.error)}</p>` : ""}${owner() ? `<div class="compact-actions"><button class="secondary" data-action="rotate-node" data-id="${n.id}">تعویض کلید اتصال</button><button class="outline-button danger" data-action="delete-node" data-id="${n.id}">حذف نود</button></div>` : ""}</article>`).join("")}</div>${!data.nodes.length ? `<div class="card">${empty("زیرساختت را بساز", "نود جدید اضافه کن و عامل Donino را روی سرور اجرا کن.", "nodes")}</div>` : ""}`
  );
}
function renderInbounds() {
  return (
    heading(
      "اتصال‌های شبکه",
      "مسیرهای امن اتصال برای تمام کاربران فعال.",
      owner() ? addButton("inbound", "اتصال جدید") : "",
    ) +
    `<div class="notice">VLESS با REALITY، VMess با WebSocket و TLS، و Trojan با TLS. گواهی‌های TLS باید روی سرور نود قرار داشته باشند.</div><section class="card table-card">${data.inbounds.length ? `<div class="table-scroll"><table><thead><tr><th>نام اتصال</th><th>پروتکل</th><th>نود</th><th>پورت</th><th>دامنه</th>${owner() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${data.inbounds.map((i) => `<tr><td>${esc(i.name)}</td><td><span class="mono">${esc(i.protocol.toUpperCase())}</span> ${badge(i.enabled ? "active" : "disabled", i.enabled ? "فعال" : "خاموش")}</td><td>${esc(i.node_name)}</td><td class="mono">${i.port}</td><td><span class="mono">${esc(i.settings.sni)}</span></td>${owner() ? `<td><button data-action="edit-inbound" data-id="${i.id}">ویرایش</button> <button class="danger" data-action="delete-inbound" data-id="${i.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : empty("یک مسیر تازه بساز", "ابتدا نود را اضافه کن، سپس اولین اتصال را بساز.", "inbounds")}</section>`
  );
}
function renderSettings() {
  return (
    heading("تنظیمات و نگهداری", "همه‌چیز برای مدیریت یک شبکهٔ مستقل.") +
    `<div class="settings-grid"><article class="card"><h2>پشتیبان‌گیری</h2><p>نسخهٔ پایگاه داده و حساب‌ها را دریافت کن. این فایل محرمانه است. برای بازیابی ورود دومرحله‌ای، کلید مستقل سرور نیز لازم است؛ پشتیبان کامل رمزگذاری‌شده در راهنمای نگهداری توضیح داده شده است.</p>${owner() ? `<a class="primary" href="/api/backup" download>${icon("download")}دریافت نسخهٔ پایگاه داده</a>` : "<p>دریافت پشتیبان فقط برای مالک شبکه فعال است.</p>"}</article><article class="card"><h2>ظاهر پنل</h2><p>پوستهٔ روشن یا تیره را انتخاب کن. انتخاب روی همین دستگاه ذخیره می‌شود.</p><button class="secondary" data-action="theme">${icon("theme")}تغییر حالت نمایش</button></article><article class="card"><h2>حساب مدیریت</h2><p>نام کاربری: ${esc(account.username)}<br>سطح دسترسی: ${roles[account.role]}<br>رمز، ورود دومرحله‌ای، نشست‌ها و توکن‌ها را از بخش امنیت حساب مدیریت کن. مالک می‌تواند مدیرهای دیگر را نیز همین‌جا مدیریت کند.</p></article><article class="card"><h2>Donino Panel <span class="mono">1.0.0-alpha.3</span></h2><p>نسخهٔ اولیهٔ مستقل، با رابط فارسی و مدیریت چند نود. امکانات در حال توسعه‌اند. راه‌اندازی واقعی به سرور نود، Xray و دامنهٔ مناسب نیاز دارد.</p><a class="subtle-link" href="https://github.com/danialrad04-sketch/donino-panel" target="_blank" rel="noopener">مستندات و کد منبع</a></article></div><section id="account-security" class="settings-grid"></section>`
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
  } else {
    $("#main").innerHTML = (views[page] || renderOverview)();
    if (page === "settings") loadSecurity();
    if (page === "users") loadUsersPage();
    if (page === "nodes" && owner()) {
      $("#main").insertAdjacentHTML(
        "beforeend",
        '<section class="card" id="deployment-status">در حال دریافت وضعیت تنظیمات…</section>',
      );
      api("/deployments")
        .then((jobs) => {
          if (page !== "nodes" || !$("#deployment-status")) return;
          const labels = {
            pending: "در انتظار اعمال",
            applied: "اعمال شد",
            failed: "ناموفق؛ در انتظار تلاش مجدد",
            superseded: "با تنظیمات تازه جایگزین شد",
          };
          $("#deployment-status").innerHTML =
            "<h2>اعمال تنظیمات نودها</h2>" +
            (jobs.length
              ? `<div class="table-scroll"><table><thead><tr><th>نود</th><th>وضعیت</th><th>زمان</th></tr></thead><tbody>${jobs
                  .slice(0, 10)
                  .map(
                    (j) =>
                      `<tr><td>${esc(data.nodes.find((n) => n.id === j.node_id)?.name || j.node_id.slice(0, 8))}</td><td>${esc(labels[j.state])}</td><td>${new Date(j.updated * 1000).toLocaleString("fa-IR")}</td></tr>`,
                  )
                  .join("")}</tbody></table></div>`
              : '<p class="muted">پس از اولین همگام‌سازی نود، نتیجهٔ اعمال تنظیمات نمایش داده می‌شود.</p>');
        })
        .catch((e) => toast(e.message, true));
    }
  }
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
      "به‌روز شد " +
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
  $("#account-initial").textContent = user.username.charAt(0).toUpperCase();
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
    `<form id="edit-form"><div class="form-grid">${fields}</div><p id="form-error" class="error"></p><div class="form-actions"><button type="button" class="secondary" data-action="close-modal">انصراف</button><button class="primary" type="submit">ذخیره</button></div></form>`,
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
      `<label class="full">دورهٔ مصرف<select name="period"><option value="none" ${!user || user.period !== "monthly" ? "selected" : ""}>بدون دوره (حجم یک‌باره)</option><option value="monthly" ${user?.period === "monthly" ? "selected" : ""}>ماهانه</option></select></label>` +
      input("طول دوره (روز)", "period_days", {
        type: "number",
        value: user?.period_days || 30,
        required: false,
        extra: 'min="1" max="366" dir="ltr"',
        hint: "فقط برای دورهٔ ماهانه. دوره از اولین مصرف شروع و حجم مصرف آن صفر می‌شود.",
      }) +
      `<label class="check full"><input name="enabled" type="checkbox" ${!user || user.enabled ? "checked" : ""}>دسترسی کاربر فعال باشد</label>` +
      (user
        ? `<div class="full" id="device-box"></div><div class="full compact-actions"><button type="button" class="secondary" data-action="reset-traffic" data-id="${user.id}">صفر کردن مصرف</button><button type="button" class="secondary" data-action="rotate-subscription" data-id="${user.id}">تعویض لینک</button><button type="button" class="secondary" data-action="rotate-credentials" data-id="${user.id}">تعویض کلید کاربر</button></div>`
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
          period: f.period || "none",
          period_days: Number(f.period_days) || 30,
        }),
      });
      await saved();
    },
  );
  if (user) loadDevices(user.id);
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
async function loadDevices(uid) {
  const box = $("#device-box");
  if (!box) return;
  try {
    const devices = await api(`/users/${uid}/devices`);
    box.innerHTML =
      `<h3>دستگاه‌ها و کلیدها</h3><p class="note">هر دستگاه کلید جدا دارد و فقط همان را می‌توان باطل کرد. فعال/غیرفعال کردن یا چرخش کلید، هستهٔ نود را دوباره راه‌اندازی می‌کند.</p>` +
      devices
        .map(
          (d) =>
            `<div class="node-row"><div><b>${esc(d.name)}${d.is_default ? " (پیش‌فرض)" : ""}</b><small>ارسال ${bytes(d.uploaded)}، دریافت ${bytes(d.downloaded)}</small></div>${badge(d.enabled ? "active" : "disabled")}<div class="compact-actions">${d.enabled ? `<button type="button" class="secondary" data-action="disable-device" data-id="${d.id}" data-user="${uid}">غیرفعال</button>` : `<button type="button" class="secondary" data-action="enable-device" data-id="${d.id}" data-user="${uid}">فعال</button>`}<button type="button" class="secondary" data-action="rotate-device" data-id="${d.id}" data-user="${uid}">چرخش کلید</button>${d.is_default ? "" : `<button type="button" class="danger" data-action="delete-device" data-id="${d.id}" data-user="${uid}">حذف</button>`}</div></div>`,
        )
        .join("") +
      `<div class="form-grid"><label class="full">نام دستگاه جدید<input id="new-device-name" maxlength="40"></label><div class="full compact-actions"><button type="button" class="primary" data-action="add-device" data-user="${uid}">افزودن دستگاه</button></div></div>`;
  } catch (error) {
    box.textContent = error.message;
  }
}
async function loadAdmins(box) {
  try {
    const admins = await api("/admins");
    box.insertAdjacentHTML(
      "beforeend",
      `<article class="card"><h2>مدیران پنل</h2><p>فقط مالک می‌تواند مدیران را مدیریت کند. تغییر نقش یا رمز، نشست‌ها و توکن‌های آن مدیر را باطل می‌کند.</p>` +
        admins
          .map(
            (a) =>
              `<div class="node-row"><div><b>${esc(a.username)}${a.username === account.username ? " (شما)" : ""}</b><small>${esc(roles[a.role])} · ورود دو مرحله‌ای: ${a.mfa_enabled ? "فعال" : "غیرفعال"}</small></div><div class="compact-actions"><button type="button" class="secondary" data-action="admin-role" data-id="${esc(a.username)}">نقش</button><button type="button" class="secondary" data-action="admin-password" data-id="${esc(a.username)}">رمز</button>${a.username === account.username ? "" : `<button type="button" class="danger" data-action="admin-delete" data-id="${esc(a.username)}">حذف</button>`}</div></div>`,
          )
          .join("") +
        `<div class="compact-actions"><button type="button" class="primary" data-action="admin-create">مدیر جدید</button></div></article>`,
    );
  } catch (error) {
    box.insertAdjacentHTML(
      "beforeend",
      `<article class="card"><p class="error">${esc(error.message)}</p></article>`,
    );
  }
}
async function loadSecurity() {
  const box = $("#account-security");
  if (!box) return;
  try {
    const info = await api("/account");
    const sessions =
      info.sessions
        .map(
          (s) =>
            `<div class="node-row"><div><b>${esc(s.address || "نامشخص")}</b><small>${new Date(s.created * 1000).toLocaleString("fa-IR")}، ${esc((s.agent || "").slice(0, 60))}</small></div>${s.current ? badge("active", "این نشست") : `<button type="button" class="secondary" data-action="revoke-session" data-id="${esc(s.sid)}">خروج</button>`}</div>`,
        )
        .join("") || "<p class='muted'>نشست دیگری فعال نیست.</p>";
    const tokens =
      info.tokens
        .map(
          (t) =>
            `<div class="node-row"><div><b>${esc(t.name)}</b><small>دامنه: ${esc(t.scope)}، انقضا: ${date(t.expires)}، آخرین استفاده: ${t.last_used ? new Date(t.last_used * 1000).toLocaleString("fa-IR") : "هرگز"}</small></div><button type="button" class="secondary" data-action="revoke-token" data-id="${esc(t.id)}">ابطال</button></div>`,
        )
        .join("") || "<p class='muted'>توکنی ساخته نشده است.</p>";
    box.innerHTML =
      `<article class="card"><h2>ورود دو مرحله‌ای</h2><p>${info.mfa_enabled ? "فعال است؛ ورود به پنل کد برنامهٔ احراز هویت می‌خواهد." : "غیرفعال است. فعال‌سازی آن امنیت حساب مدیریت را بالا می‌برد."}</p>${info.mfa_enabled ? '<button type="button" class="secondary" data-action="mfa-disable">غیرفعال‌سازی</button>' : '<button type="button" class="primary" data-action="mfa-setup">فعال‌سازی</button>'}</article>` +
      `<article class="card"><h2>رمز عبور</h2><p>با تغییر رمز، نشست‌های دیگر و همهٔ توکن‌های API این حساب باطل می‌شوند.</p><button type="button" class="secondary" data-action="change-password">تغییر رمز</button></article>` +
      `<article class="card"><h2>نشست‌های ورود</h2>${sessions}${info.sessions.length > 1 ? '<div class="compact-actions"><button type="button" class="outline-button danger" data-action="revoke-others">خروج از سایر نشست‌ها</button></div>' : ""}</article>` +
      `<article class="card"><h2>توکن‌های API</h2><p>برای اتوماسیون. هر توکن فقط یک‌بار نمایش داده می‌شود و دامنهٔ آن محدود است.</p>${tokens}<div class="compact-actions"><button type="button" class="primary" data-action="token-create">ساخت توکن</button></div></article>`;
    if (owner()) await loadAdmins(box);
  } catch (error) {
    box.innerHTML = `<article class="card"><p class="error">${esc(error.message)}</p></article>`;
  }
}
async function handleAction(action, id, element) {
  const user = data.users.find((u) => u.id === id);
  if (action === "user-periods") {
    const periods = await api(`/users/${id}/periods`);
    return modal(
      "تاریخچهٔ دوره‌های مصرف",
      `<div class="table-scroll"><table><thead><tr><th>دوره</th><th>شروع</th><th>پایان</th><th>ارسال</th><th>دریافت</th></tr></thead><tbody>${periods.map((p) => `<tr><td>${number(p.period_no + 1)}</td><td>${date(p.started)}</td><td>${p.ended ? date(p.ended) : "جاری"}</td><td>${bytes(p.uploaded)}</td><td>${bytes(p.downloaded)}</td></tr>`).join("")}</tbody></table></div>`,
    );
  }
  if (action === "user-nodes") {
    const [assignment, nodes] = await Promise.all([
      api(`/users/${id}/nodes`),
      api("/nodes"),
    ]);
    return form(
      "نودهای مجاز کاربر",
      `<label class="full">دسترسی<select name="mode"><option value="all" ${assignment.mode === "all" ? "selected" : ""}>تمام نودها</option><option value="selected" ${assignment.mode === "selected" ? "selected" : ""}>فقط نودهای انتخاب‌شده</option></select></label><p class="note full">در حالت انتخابی، انتخاب نکردن هیچ نودی دسترسی اتصال را می‌بندد. تغییر پس از همگام‌سازی نود اعمال می‌شود.</p>${nodes.map((n) => `<label class="full"><input type="checkbox" name="node_${esc(n.id)}" ${assignment.node_ids.includes(n.id) ? "checked" : ""}> ${esc(n.name)}</label>`).join("")}`,
      async (f) => {
        await api(`/users/${id}/nodes`, {
          method: "PUT",
          body: JSON.stringify({
            mode: f.mode,
            node_ids: Object.keys(f)
              .filter((k) => k.startsWith("node_"))
              .map((k) => k.slice(5)),
          }),
        });
        await saved();
      },
    );
  }
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
  if (action === "users-prev") {
    usersView.offset = Math.max(0, usersView.offset - usersView.limit);
    return loadUsersPage();
  }
  if (action === "users-next") {
    usersView.offset += usersView.limit;
    return loadUsersPage();
  }
  if (action === "admin-create")
    return form(
      "مدیر جدید",
      input("نام کاربری", "username", { extra: 'dir="ltr" maxlength="64"' }) +
        input("رمز عبور (حداقل ۱۲ نویسه)", "password", {
          type: "password",
          extra: 'autocomplete="new-password" minlength="12" dir="ltr"',
        }) +
        `<label>نقش<select name="role"><option value="viewer">مشاهده‌گر</option><option value="operator">مدیر کاربران</option><option value="owner">مالک</option></select></label>`,
      async (f) => {
        await api("/admins", { method: "POST", body: JSON.stringify(f) });
        $("#modal").close();
        toast("مدیر ساخته شد");
        await loadSecurity();
      },
    );
  if (action === "admin-role")
    return form(
      "تغییر نقش مدیر",
      `<label class="full">نقش<select name="role"><option value="viewer">مشاهده‌گر</option><option value="operator">مدیر کاربران</option><option value="owner">مالک</option></select></label>`,
      async (f) => {
        await api(`/admins/${encodeURIComponent(id)}`, {
          method: "PUT",
          body: JSON.stringify({ role: f.role }),
        });
        $("#modal").close();
        toast("نقش تغییر کرد");
        await loadSecurity();
      },
    );
  if (action === "admin-password")
    return form(
      "تغییر رمز مدیر",
      input("رمز جدید (حداقل ۱۲ نویسه)", "password", {
        type: "password",
        extra: 'autocomplete="new-password" minlength="12" dir="ltr"',
      }),
      async (f) => {
        await api(`/admins/${encodeURIComponent(id)}/password`, {
          method: "POST",
          body: JSON.stringify({ password: f.password }),
        });
        $("#modal").close();
        toast("رمز مدیر تغییر کرد و نشست‌هایش باطل شدند");
        await loadSecurity();
      },
    );
  if (action === "admin-delete")
    return confirmAction(
      "حذف مدیر",
      "این مدیر و نشست‌ها و توکن‌هایش حذف می‌شوند.",
      () => api(`/admins/${encodeURIComponent(id)}`, { method: "DELETE" }),
    );
  if (action === "mfa-setup") {
    return form(
      "تأیید رمز عبور",
      input("رمز عبور", "password", {
        type: "password",
        extra: 'autocomplete="current-password" dir="ltr"',
      }),
      async (credentials) => {
        const setup = await api("/account/mfa/setup", {
          method: "POST",
          body: JSON.stringify(credentials),
        });
        return form(
          "فعال‌سازی ورود دو مرحله‌ای",
          `<p class="note full">کلید زیر را در برنامهٔ احراز هویت (مثل Google Authenticator یا Aegis) به‌صورت دستی وارد کنید.</p><label class="full">کلید محرمانه<textarea readonly dir="ltr">${esc(setup.secret)}</textarea></label>` +
            input("کد ۶ رقمی برنامه", "code", {
              type: "text",
              full: true,
              extra:
                'inputmode="numeric" autocomplete="one-time-code" dir="ltr" maxlength="6"',
            }),
          async (f) => {
            const result = await api("/account/mfa/enable", {
              method: "POST",
              body: JSON.stringify({ code: f.code }),
            });
            modal(
              "رمزهای بازیابی",
              `<p class="note">این رمزها فقط همین یک بار نشان داده می‌شوند. هر کدام یک‌بار مصرف است و اگر دستگاه احراز هویت را از دست دادید، به‌جای کد ۶ رقمی وارد می‌شود.</p><label class="full">رمزهای بازیابی<textarea id="secret-output" readonly dir="ltr" rows="10">${esc(result.recovery_codes.join("\n"))}</textarea></label><div class="form-actions"><button type="button" class="primary" data-action="copy-secret">کپی رمزها</button></div>`,
            );
            await loadSecurity();
          },
        );
      },
    );
  }
  if (action === "mfa-disable")
    return form(
      "غیرفعال‌سازی ورود دو مرحله‌ای",
      input("رمز عبور", "password", {
        type: "password",
        extra: 'autocomplete="current-password" dir="ltr"',
      }) +
        input("کد دو مرحله‌ای یا بازیابی", "code", {
          extra: 'autocomplete="one-time-code" dir="ltr"',
        }),
      async (f) => {
        await api("/account/mfa/disable", {
          method: "POST",
          body: JSON.stringify(f),
        });
        $("#modal").close();
        toast("ورود دو مرحله‌ای غیرفعال شد");
        await loadSecurity();
      },
    );
  if (action === "change-password")
    return form(
      "تغییر رمز عبور",
      input("رمز فعلی", "current", {
        type: "password",
        extra: 'autocomplete="current-password" dir="ltr"',
      }) +
        input("رمز جدید (حداقل ۱۲ نویسه)", "new", {
          type: "password",
          extra: 'autocomplete="new-password" minlength="12" dir="ltr"',
        }),
      async (f) => {
        await api("/account/password", {
          method: "POST",
          body: JSON.stringify(f),
        });
        $("#modal").close();
        toast("رمز تغییر کرد؛ نشست‌ها و توکن‌های دیگر باطل شدند");
        await loadSecurity();
      },
    );
  if (action === "revoke-session") {
    await api(`/account/sessions/${id}`, { method: "DELETE" });
    toast("نشست بسته شد");
    return loadSecurity();
  }
  if (action === "revoke-others") {
    await api("/account/sessions/revoke-others", { method: "POST" });
    toast("سایر نشست‌ها بسته شدند");
    return loadSecurity();
  }
  if (action === "revoke-token") {
    await api(`/account/tokens/${id}`, { method: "DELETE" });
    toast("توکن باطل شد");
    return loadSecurity();
  }
  if (action === "token-create")
    return form(
      "توکن API جدید",
      input("نام توکن", "name", { value: "automation" }) +
        `<label>دامنه<select name="scope"><option value="read">فقط خواندن</option><option value="users">مدیریت کاربران</option><option value="full">کامل (فقط مالک)</option></select></label>` +
        input("مدت (روز)", "days", {
          type: "number",
          value: 30,
          extra: 'min="1" max="365" dir="ltr"',
        }),
      async (f) => {
        const result = await api("/account/tokens", {
          method: "POST",
          body: JSON.stringify({
            name: f.name,
            scope: f.scope,
            days: Number(f.days),
          }),
        });
        modal(
          "توکن API",
          `<p class="note">این توکن فقط همین یک بار نمایش داده می‌شود. آن را در جای امنی ذخیره کنید.</p><label class="full">توکن<textarea id="secret-output" readonly dir="ltr">${esc(result.token)}</textarea></label><div class="form-actions"><button type="button" class="primary" data-action="copy-secret">کپی توکن</button></div>`,
        );
        await loadSecurity();
      },
    );
  if (action === "add-device") {
    const uid = element.dataset.user;
    const name = $("#new-device-name").value.trim();
    await api(`/users/${uid}/devices`, {
      method: "POST",
      body: JSON.stringify({ name, enabled: true }),
    });
    toast("دستگاه اضافه شد؛ کلید آن در لینک اشتراک همین کاربر است");
    await loadDevices(uid);
    return refresh(false);
  }
  if (action === "delete-device") {
    await api(`/devices/${id}`, { method: "DELETE" });
    toast("دستگاه حذف شد");
    await loadDevices(element.dataset.user);
    return refresh(false);
  }
  if (action === "rotate-device") {
    await api(`/devices/${id}/rotate-secret`, { method: "POST" });
    toast("کلید این دستگاه عوض شد؛ کلید قبلی باطل است و نود همگام می‌شود");
    await loadDevices(element.dataset.user);
    return refresh(false);
  }
  if (action === "enable-device" || action === "disable-device") {
    const uid = element.dataset.user;
    const current = (await api(`/users/${uid}/devices`)).find(
      (d) => d.id === id,
    );
    await api(`/devices/${id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: current.name,
        enabled: action === "enable-device",
      }),
    });
    await loadDevices(uid);
    return refresh(false);
  }
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
      `<p class="note">لینک خصوصی کاربر را کپی کن یا صفحهٔ اختصاصی او را باز کن. QR روی همین سرور تولید می‌شود.</p><img class="share-qr" src="${esc(result.qr_url)}" alt="QR اشتراک"><label>لینک اشتراک<textarea id="secret-output" dir="ltr" readonly>${esc(result.url)}</textarea></label><div class="form-actions"><a class="outline-button" id="open-portal" href="${esc(result.portal_url)}" target="_blank" rel="noopener">صفحهٔ کاربر</a><button class="secondary" data-action="copy-portal" data-url="${esc(result.portal_url)}">کپی صفحه</button><button class="secondary" data-action="copy-clash">Clash</button><button class="primary" data-action="copy-secret">کپی اشتراک</button></div>`,
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
    handleAction(target.dataset.action, target.dataset.id, target).catch(
      (error) => toast(error.message, true),
    );
});
document.addEventListener("input", (e) => {
  if (e.target.id !== "search-users") return;
  usersView.q = e.target.value.trim();
  usersView.offset = 0;
  clearTimeout(usersTimer);
  usersTimer = setTimeout(loadUsersPage, 250);
});
document.addEventListener("change", (e) => {
  if (e.target.id !== "filter-state") return;
  usersView.state = e.target.value;
  usersView.offset = 0;
  loadUsersPage();
});
document
  .querySelectorAll("[data-icon]")
  .forEach((el) => (el.innerHTML = icon(el.dataset.icon)));
$("#close-modal").onclick = () => $("#modal").close();
$("#theme").onclick = () => handleAction("theme");
$("#refresh").onclick = () => refresh();
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
    if (user.mfa_required) {
      $("#code-field").hidden = false;
      $("#login-error").textContent =
        "کد برنامهٔ احراز هویت یا یکی از رمزهای بازیابی را وارد کنید.";
      $("#login-form [name=code]").focus();
      return;
    }
    e.target.reset();
    $("#code-field").hidden = true;
    await enter(user);
  } catch (error) {
    $("#login-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
$("#bootstrap-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = Object.fromEntries(new FormData(event.target));
  const button = event.target.querySelector("button");
  $("#bootstrap-error").textContent = "";
  if (fields.owner_password !== fields.confirm) {
    $("#bootstrap-error").textContent = "رمز و تکرار آن یکسان نیستند.";
    return;
  }
  button.disabled = true;
  try {
    await api("/bootstrap", {
      method: "POST",
      body: JSON.stringify({
        token: bootstrapToken,
        username: fields.owner_username,
        password: fields.owner_password,
      }),
    });
    bootstrapToken = "";
    event.target.reset();
    showLogin();
    const account = await api("/login", {
      method: "POST",
      body: JSON.stringify({
        username: fields.owner_username,
        password: fields.owner_password,
      }),
    });
    await enter(account);
  } catch (error) {
    $("#bootstrap-error").textContent = error.message;
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});

api("/me")
  .then(enter)
  .catch(() => showLogin());
