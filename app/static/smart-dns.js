"use strict";
let smartData = { exits: [], status: {}, sessions: [] };
const smartModes = {
  active: "فعال",
  drain: "تخلیهٔ اتصال‌ها",
  disabled: "غیرفعال",
};
async function loadSmartDNS() {
  const box = $("#smart-dns-content");
  if (!box) return;
  try {
    const [status, exits, sessions] = await Promise.all([
      api("/dns/smart/status"),
      api("/dns/smart/exits"),
      api("/dns/smart/sessions"),
    ]);
    if (!box.isConnected || page !== "dns") return;
    smartData = { status, exits, sessions };
    box.innerHTML = `<div class="card-head"><h2>Smart DNS و نودهای خروجی</h2>${owner() ? '<button class="primary" data-action="dns-smart-add">نود خروجی جدید</button><button data-action="dns-smart-catalog">مسیریابی از کاتالوگ</button>' : ""}</div><p>${status.enabled && status.gateway_ready ? "gateway فعال است" : "gateway هنوز فعال و آماده نیست"} · HTTPS با SNI؛ نتیجهٔ بازی‌ها و اینترنت شما نیازمند آزمون است.</p><p>مسیر اصلی و جایگزین برای هر دامنه تعیین می‌شوند. ارتباط جاری در زمان تغییر سیاست ممکن است قطع شود. برای relay، کاربر باید IP همین اتصال را در پورتال ثبت کرده باشد.</p>${exits.length ? `<div class="table-scroll"><table><thead><tr><th>نود خروجی</th><th>حالت</th><th>TLS و احراز هویت</th>${owner() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${exits.map((n) => `<tr><td><b>${esc(n.name)}</b><span class="subline mono">${esc(n.host)}:${n.port}</span></td><td>${esc(smartModes[n.mode])}</td><td>${n.healthy === null ? "آزمون نشده" : n.healthy ? "موفق" : "ناموفق"}${n.checked ? `<span class="subline">${new Date(n.checked * 1000).toLocaleString("fa-IR")}</span>` : ""}</td>${owner() ? `<td class="actions"><button data-action="dns-smart-probe" data-id="${n.id}">آزمون اتصال خروجی</button><button data-action="dns-smart-edit" data-id="${n.id}">ویرایش</button><button class="danger" data-action="dns-smart-delete" data-id="${n.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : "<p>برای دامنه‌های منتخب، نود خروجی TLS احرازشده تعریف کنید و پس از آزمون، فعال کنید.</p>"}${owner() && dnsData.policies.length ? `<h3>مسیریابی سیاست‌ها</h3><div class="compact-actions">${dnsData.policies.map((p) => `<button data-action="dns-smart-route" data-id="${p.id}">${esc(p.name)} · مسیریابی دامنه</button>`).join("")}</div>` : ""}<h3>حجم مستقل Smart DNS</h3>${dnsData.accounts.length ? `<div class="table-scroll"><table><thead><tr><th>حساب</th><th>حجم relay / سهمیه</th><th>نشست‌ها</th>${writable() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${dnsData.accounts.map((a) => `<tr><td>${esc(a.user_name)}<span class="subline">${a.relay_enabled ? "فعال" : "غیرفعال"}</span></td><td>${bytes((a.relay_up || 0) + (a.relay_down || 0))} / ${a.relay_limit ? bytes(a.relay_limit) : "نامحدود"}</td><td>${number(a.relay_sessions || 0)}<span class="subline">${number(a.relay_errors || 0)} خطا</span></td>${writable() ? `<td><button data-action="dns-smart-account" data-id="${a.id}">مجوز و حجم relay</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : "<p>ابتدا حساب DNS کاربر را بسازید.</p>"}<p class="muted">حجم relay شامل بایت‌های رمزگذاری‌شدهٔ عبور داده‌شده است؛ از شمارش درخواست DNS و حجم VPN مستقل است.</p>`;
  } catch (error) {
    if (box.isConnected) box.textContent = error.message;
  }
}
function smartExitSelect(name, label, optional = false) {
  return `<label>${esc(label)}<select name="${name}">${optional ? '<option value="">بدون جایگزین</option>' : ""}${smartData.exits.map((n) => `<option value="${n.id}">${esc(n.name)} · ${esc(smartModes[n.mode])}</option>`).join("")}</select></label>`;
}
async function handleSmartDNSAction(action, id) {
  if (action === "dns-smart-add" || action === "dns-smart-edit") {
    const row = smartData.exits.find((n) => n.id === id);
    form(
      row ? "ویرایش نود خروجی" : "نود خروجی Smart DNS",
      input("نام", "name", { value: row?.name || "" }) +
        input("IP یا دامنهٔ خروجی", "host", { value: row?.host || "" }) +
        input("پورت TLS خروجی", "port", {
          type: "number",
          value: row?.port || 9445,
          extra: 'min="1" max="65535"',
        }) +
        input("نام گواهی TLS", "sni", { value: row?.sni || "" }) +
        input("نام کاربری خصوصی خروجی", "username", {
          required: !row,
          extra: row ? 'autocomplete="off"' : 'required autocomplete="off"',
          hint: row
            ? "خالی = حفظ مقدار قبلی"
            : "از تنظیم نقش خروجی دریافت می‌شود",
        }) +
        input("رمز خصوصی خروجی", "password", {
          type: "password",
          required: !row,
          extra: row
            ? 'autocomplete="new-password"'
            : 'required autocomplete="new-password"',
          hint: "حداقل ۱۲ کاراکتر؛ در فهرست و تاریخچه نمایش داده نمی‌شود",
        }) +
        `<label>حالت<select name="mode">${Object.entries(smartModes)
          .map(
            ([key, label]) =>
              `<option value="${key}" ${key === (row?.mode || "disabled") ? "selected" : ""}>${label}</option>`,
          )
          .join(
            "",
          )}</select></label><p class="notice full">اتصال تازه یا تغییریافته را غیرفعال ذخیره کنید؛ پس از آزمون TLS و احراز هویت، حالت فعال را انتخاب کنید. تخلیه، فقط اتصال تازه را متوقف می‌کند؛ غیرفعال‌سازی اتصال‌های جاری را نیز می‌بندد.</p>`,
      async (f) => {
        await api("/dns/smart/exits" + (row ? "/" + row.id : ""), {
          method: row ? "PUT" : "POST",
          body: JSON.stringify({ ...f, port: Number(f.port) }),
        });
        await saved();
      },
    );
  }
  if (action === "dns-smart-probe") {
    const r = await api(`/dns/smart/exits/${id}/probe`, { method: "POST" });
    toast(
      r.ok
        ? "TLS و احراز هویت موفق بود؛ این نتیجه هنوز آزمون سرویس مقصد نیست."
        : "آزمون خروجی موفق نشد؛ گواهی، نشانی و اعتبارنامه را بررسی کنید.",
      !r.ok,
    );
    await loadSmartDNS();
  }
  if (action === "dns-smart-delete") {
    if (
      !confirm("نود خروجی حذف شود؟ ابتدا باید آن را از قواعد سیاست‌ها بردارید.")
    )
      return;
    await api(`/dns/smart/exits/${id}`, { method: "DELETE" });
    await loadSmartDNS();
  }
  if (action === "dns-smart-route") {
    const p = dnsData.policies.find((r) => r.id === id);
    form(
      "مسیریابی دامنه · " + p.name,
      `<label class="full">دامنه‌ها؛ هر خط یک دامنه<textarea name="domains" rows="5" dir="ltr" required></textarea></label><label>رفتار<select name="behavior"><option value="route">خروج از نودهای منتخب</option><option value="allow">مستقیم از resolver</option><option value="block">مسدود</option></select></label>` +
        smartExitSelect("primary", "خروجی اصلی") +
        smartExitSelect("fallback1", "جایگزین اول", true) +
        smartExitSelect("fallback2", "جایگزین دوم", true) +
        `<p class="notice full">قاعدهٔ دقیق‌تر اولویت دارد. جایگزین فقط پیش از ارسال دادهٔ مشتری انتخاب می‌شود؛ شکست همهٔ خروجی‌ها اتصال را رد می‌کند. ذخیره، ممکن است نشست‌های جاری این سیاست را قطع کند.</p>`,
      async (f) => {
        const domains = f.domains
          .split(/\r?\n/)
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        const exits = [f.primary, f.fallback1, f.fallback2].filter(Boolean);
        if (
          f.behavior === "route" &&
          (!exits.length || new Set(exits).size !== exits.length)
        )
          throw new Error("خروجی اصلی و جایگزین‌های متفاوت انتخاب کنید.");
        const replace = new Set(domains);
        const rules = p.rules
          .filter((r) => !replace.has(r.domain))
          .concat(
            domains.map((domain) => ({
              domain,
              action: f.behavior,
              ...(f.behavior === "route" ? { exit_ids: exits } : {}),
            })),
          );
        await api("/dns/policies/" + p.id, {
          method: "PUT",
          body: JSON.stringify({ name: p.name, rules }),
        });
        await saved();
      },
    );
  }
  if (action === "dns-smart-account") {
    const a = dnsData.accounts.find((r) => r.id === id);
    form(
      "مجوز و حجم relay · " + a.user_name,
      `<label>Smart DNS<select name="relay_enabled"><option value="true">فعال</option><option value="false" ${!a.relay_enabled ? "selected" : ""}>غیرفعال</option></select></label>` +
        input("سهمیهٔ حجم relay به GiB", "gib", {
          type: "number",
          value: (a.relay_limit || 0) / 1073741824,
          extra: 'min="0" step="any"',
          hint: "صفر = نامحدود؛ مستقل از درخواست DNS و VPN",
        }) +
        input("حداکثر اتصال هم‌زمان", "connections", {
          type: "number",
          value: a.relay_connections || 8,
          extra: 'min="1" max="64"',
        }),
      async (f) => {
        await api(`/dns/accounts/${id}`, {
          method: "PUT",
          body: JSON.stringify({
            user_id: a.user_id,
            policy_id: a.policy_id,
            enabled: !!a.enabled,
            query_limit: a.query_limit,
            qps: a.qps,
            relay_enabled: f.relay_enabled === "true",
            relay_limit: Math.floor(Number(f.gib) * 1073741824),
            relay_connections: Number(f.connections),
          }),
        });
        await saved();
      },
    );
  }
  if (action === "dns-smart-catalog") {
    if (!smartData.exits.length)
      throw new Error("ابتدا نود خروجی را تعریف کنید.");
    const source = await api("/dns/catalog");
    const groups = source.services.flatMap((s) =>
      s.groups.map((g) => ({
        service: s.key,
        group: g.key,
        label: s.label + " / " + g.label,
      })),
    );
    form(
      "مسیریابی سرویس‌ها از کاتالوگ",
      input("نام سیاست", "name", { full: true }) +
        smartExitSelect("primary", "خروجی اصلی") +
        smartExitSelect("fallback1", "جایگزین اول", true) +
        smartExitSelect("fallback2", "جایگزین دوم", true) +
        `<fieldset class="full catalog-groups"><legend>گروه‌های سرویس</legend>${groups.map((g, i) => `<label><input type="checkbox" name="group_${i}">${esc(g.label)}</label>`).join("")}</fieldset><label class="full">استثناهای مستقیم؛ هر خط یک دامنه<textarea name="domains_off" rows="3" dir="ltr"></textarea></label><p class="notice full">انتخاب گروه، موفقیت همهٔ بازی‌ها یا سرویس‌ها را تضمین نمی‌کند. پشتیبانی این مسیر HTTPS با SNI آشکار است؛ سیاست را پس از آزمون، به حساب DNS اختصاص دهید.</p>`,
      async (f) => {
        const selected = groups
          .filter((g, i) => f["group_" + i] === "on")
          .map(({ service, group }) => ({ service, group }));
        if (!selected.length) throw new Error("حداقل یک گروه انتخاب کنید.");
        const exits = [f.primary, f.fallback1, f.fallback2].filter(Boolean);
        await api("/dns/policies/from-catalog", {
          method: "POST",
          body: JSON.stringify({
            name: f.name,
            groups: selected,
            exit_ids: exits,
            domains_off: f.domains_off
              .split(/\r?\n/)
              .map((s) => s.trim())
              .filter(Boolean),
          }),
        });
        await saved();
      },
    );
  }
}
