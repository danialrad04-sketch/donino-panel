"use strict";
let dnsData = { policies: [], accounts: [] };
function renderDNS() {
  return (
    heading(
      "DNS اختصاصی",
      "سیاست دامنه، سهمیهٔ درخواست و دسترسی هر کاربر را مستقل از ترافیک VPN مدیریت کنید.",
    ) +
    '<p class="notice">این بخش DNS را مدیریت می‌کند. عبور ترافیک بازی، Smart DNS و DoQ هنوز در این نسخه فعال نیستند. resolver محلی باید با نصب اختیاری DNS راه‌اندازی شده باشد.</p>' +
    '<div id="dns-content">در حال دریافت…</div>'
  );
}
async function loadDNS() {
  try {
    const [policies, accounts] = await Promise.all([
      api("/dns/policies"),
      api("/dns/accounts"),
    ]);
    dnsData = { policies, accounts };
    if (page !== "dns" || !$("#dns-content")) return;
    $("#dns-content").innerHTML =
      `<section class="card"><div class="card-head"><h2>سیاست‌های دامنه</h2>${owner() ? '<button class="primary" data-action="dns-add-policy">سیاست جدید</button>' : ""}</div>${policies.length ? `<div class="table-scroll"><table><thead><tr><th>نام</th><th>قواعد</th>${owner() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${policies.map((p) => `<tr><td>${esc(p.name)}</td><td>${number(p.rules.length)}</td>${owner() ? `<td class="actions"><button data-action="dns-edit-policy" data-id="${p.id}">ویرایش</button><button class="danger" data-action="dns-delete-policy" data-id="${p.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="muted">ابتدا یک سیاست بسازید. سیاست بدون قاعده، پاسخ resolver معتبر را بدون بازنویسی برمی‌گرداند.</p>'}</section>
    <section class="card"><div class="card-head"><h2>خدمت DNS کاربران</h2>${writable() ? '<button class="primary" data-action="dns-add-account">فعال‌سازی DNS</button>' : ""}</div>${accounts.length ? `<div class="table-scroll"><table><thead><tr><th>کاربر / سیاست</th><th>درخواست / سهمیه</th><th>بایت DNS</th><th>وضعیت</th>${writable() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${accounts.map((a) => `<tr><td><b>${esc(a.user_name)}</b><span class="subline">${esc(a.policy_name)}</span></td><td>${number(a.queries)} / ${a.query_limit ? number(a.query_limit) : "نامحدود"}<span class="subline">${number(a.qps)} درخواست در ثانیه</span></td><td>${bytes(a.request_bytes + a.response_bytes)}<span class="subline">${number(a.blocked)} مسدود؛ ${number(a.errors)} خطا</span></td><td>${badge(a.enabled ? "active" : "disabled")}</td>${writable() ? `<td class="actions"><button data-action="dns-edit-account" data-id="${a.id}">ویرایش</button><button data-action="dns-token" data-id="${a.id}">اعتبارنامه</button><button data-action="dns-periods" data-id="${a.id}">دوره‌ها</button><button data-action="dns-reset" data-id="${a.id}">دورهٔ تازه</button><button class="danger" data-action="dns-delete-account" data-id="${a.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="muted">DNS برای هیچ کاربری فعال نشده است. دسترسی عمومی پیش‌فرض بسته است.</p>'}</section>`;
  } catch (error) {
    if (page === "dns" && $("#dns-content"))
      $("#dns-content").textContent = error.message;
  }
}
function showDNSCredential(value) {
  modal(
    "اعتبارنامهٔ خصوصی DoH",
    `<p class="notice">این اعتبارنامه فقط همین بار نمایش داده می‌شود. در کلاینت سازگار، آن را در هدر Authorization با پیشوند Bearer قرار دهید. نام کاربری و رمز VPN جای آن را نمی‌گیرند.</p><label>نشانی DoH<input readonly dir="ltr" value="${esc(location.origin + value.doh_path)}"></label><label>اعتبارنامه<textarea readonly dir="ltr">${esc(value.token)}</textarea></label>`,
  );
}
async function handleDNSAction(action, id) {
  if (action === "dns-add-policy" || action === "dns-edit-policy") {
    const current = dnsData.policies.find((p) => p.id === id);
    form(
      current ? "ویرایش سیاست DNS" : "سیاست DNS جدید",
      input("نام سیاست", "name", { value: current?.name || "", full: true }) +
        `<label class="full">قواعد دامنه<textarea name="rules" rows="8" dir="ltr">${esc((current?.rules || []).map((r) => r.action + " " + r.domain + (r.addresses.length ? " " + r.addresses.join(",") : "")).join("\n"))}</textarea><small>هر خط: block example.com برای مسدودسازی، allow sub.example.com برای استثنا، یا rewrite example.com 1.2.3.4 برای بازنویسی. دامنه و زیردامنه‌های آن مشمول‌اند؛ قاعدهٔ دقیق‌تر اولویت دارد. خالی = بدون بازنویسی.</small></label>`,
      async (f) => {
        const rules = f.rules
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean)
          .map((line) => {
            const parts = line.split(/\s+/);
            if (
              !(
                (["block", "allow"].includes(parts[0]) && parts.length === 2) ||
                (parts[0] === "rewrite" && parts.length === 3)
              )
            )
              throw new Error("ساختار یکی از قواعد صحیح نیست.");
            return {
              action: parts[0],
              domain: parts[1],
              addresses: parts[2] ? parts[2].split(",") : [],
            };
          });
        await api("/dns/policies" + (current ? "/" + current.id : ""), {
          method: current ? "PUT" : "POST",
          body: JSON.stringify({ name: f.name, rules }),
        });
        await saved();
      },
    );
  }
  if (action === "dns-add-account" || action === "dns-edit-account") {
    const current = dnsData.accounts.find((a) => a.id === id);
    if (!dnsData.policies.length) throw new Error("ابتدا یک سیاست DNS بسازید.");
    form(
      current ? "ویرایش خدمت DNS" : "فعال‌سازی DNS کاربر",
      `<label>کاربر<select name="user_id" ${current ? "disabled" : ""}>${data.users.map((u) => `<option value="${u.id}" ${u.id === current?.user_id ? "selected" : ""}>${esc(u.name)}</option>`).join("")}</select></label><label>سیاست<select name="policy_id">${dnsData.policies.map((p) => `<option value="${p.id}" ${p.id === current?.policy_id ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>` +
        input("سهمیهٔ درخواست DNS", "query_limit", {
          type: "number",
          value: current?.query_limit || 0,
          extra: 'min="0" max="9000000000000000"',
          hint: "صفر = نامحدود؛ مستقل از حجم VPN",
        }) +
        input("درخواست در ثانیه", "qps", {
          type: "number",
          value: current?.qps || 20,
          extra: 'min="1" max="100"',
        }) +
        `<label>وضعیت<select name="enabled"><option value="true">فعال</option><option value="false" ${current && !current.enabled ? "selected" : ""}>غیرفعال</option></select></label>`,
      async (f) => {
        const value = await api(
          "/dns/accounts" + (current ? "/" + current.id : ""),
          {
            method: current ? "PUT" : "POST",
            body: JSON.stringify({
              user_id: current?.user_id || f.user_id,
              policy_id: f.policy_id,
              query_limit: Number(f.query_limit),
              qps: Number(f.qps),
              enabled: f.enabled === "true",
            }),
          },
        );
        await saved();
        if (!current) showDNSCredential(value);
      },
    );
  }
  if (action === "dns-token") {
    if (!confirm("اعتبارنامهٔ قبلی DoH باطل و اعتبارنامهٔ تازه صادر شود؟"))
      return;
    showDNSCredential(
      await api(`/dns/accounts/${id}/rotate-token`, { method: "POST" }),
    );
  }
  if (action === "dns-reset") {
    if (!confirm("مصرف فعلی بایگانی و دورهٔ تازهٔ DNS آغاز شود؟")) return;
    await api(`/dns/accounts/${id}/reset`, { method: "POST" });
    await loadDNS();
  }
  if (action === "dns-periods") {
    const values = await api(`/dns/accounts/${id}/periods`);
    modal(
      "دوره‌های مصرف DNS",
      `<div class="table-scroll"><table><thead><tr><th>دوره</th><th>درخواست</th><th>بایت DNS</th><th>وضعیت</th></tr></thead><tbody>${values.map((v) => `<tr><td>${number(v.period_no)}</td><td>${number(v.queries)}</td><td>${bytes(v.request_bytes + v.response_bytes)}</td><td>${v.closed ? "بسته" : "جاری"}</td></tr>`).join("")}</tbody></table></div>`,
    );
  }
  if (action === "dns-delete-policy" || action === "dns-delete-account") {
    if (!confirm("این مورد حذف شود؟ تاریخچهٔ حساب حذف‌شده نیز پاک می‌شود."))
      return;
    await api(
      `/dns/${action === "dns-delete-policy" ? "policies" : "accounts"}/${id}`,
      { method: "DELETE" },
    );
    await loadDNS();
  }
}
