"use strict";
let dnsData = { policies: [], accounts: [], runtime: {} };
function renderDNS() {
  return (
    heading(
      "DNS اختصاصی",
      "سیاست دامنه، سهمیهٔ درخواست و دسترسی هر کاربر را مستقل از ترافیک VPN مدیریت کنید.",
    ) +
    '<p class="notice">DNS معمولی با IP سرور و ثبت IP مشتری کار می‌کند؛ دامنه، SSL پنل و DoH اجباری نیست. رفع تحریم سرویس‌های منتخب با خروجی Smart DNS جداگانه تنظیم می‌شود. DNS به‌تنهایی همهٔ ترافیک یا UDP بازی را از خارج عبور نمی‌دهد.</p>' +
    '<div id="dns-content">در حال دریافت…</div>' +
    '<section id="smart-dns-content" class="card">در حال دریافت وضعیت خروجی‌ها…</section>' +
    (owner()
      ? '<section class="card"><h2>انتقال doctor-dns</h2><p>پیش‌نمایش و انتقال مرحله‌ای با ابزار محلی سرور انجام می‌شود. حساب منتقل‌شده تا تطبیق حجم، انقضا و مسیر relay غیرفعال می‌ماند.</p><button data-action="dns-imports">مشاهدهٔ انتقال‌ها</button></section>'
      : "")
  );
}
async function loadDNS() {
  try {
    const [policies, accounts, runtime] = await Promise.all([
      api("/dns/policies"),
      api("/dns/accounts"),
      api("/dns/runtime"),
    ]);
    dnsData = { policies, accounts, runtime };
    if (page !== "dns" || !$("#dns-content")) return;
    $("#dns-content").innerHTML =
      dnsConnectionCard(runtime) +
      `<section class="card"><div class="card-head dns-policy-head"><h2>سیاست‌های دامنه</h2>${owner() ? '<button class="primary" data-action="dns-add-policy">سیاست جدید</button><button class="secondary" data-action="dns-catalog">از کاتالوگ سرویس‌ها</button>' : ""}</div>${policies.length ? `<div class="table-scroll"><table><thead><tr><th>نام</th><th>قواعد</th>${owner() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${policies.map((p) => `<tr><td>${esc(p.name)}</td><td>${number(p.rules.length)}</td>${owner() ? `<td class="actions"><button data-action="dns-edit-policy" data-id="${p.id}">ویرایش</button><button class="danger" data-action="dns-delete-policy" data-id="${p.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="muted">ابتدا یک سیاست بسازید. سیاست بدون قاعده، پاسخ resolver معتبر را بدون بازنویسی برمی‌گرداند.</p>'}</section>
    <section class="card"><div class="card-head"><h2>خدمت DNS کاربران</h2>${writable() ? '<button class="primary" data-action="dns-add-account">فعال‌سازی DNS</button>' : ""}</div>${accounts.length ? `<div class="table-scroll"><table><thead><tr><th>کاربر / سیاست</th><th>درخواست / سهمیه</th><th>بایت DNS</th><th>وضعیت</th>${writable() ? "<th>عملیات</th>" : ""}</tr></thead><tbody>${accounts.map((a) => `<tr><td><b>${esc(a.user_name)}</b><span class="subline">${esc(a.policy_name)}</span><span class="subline">انقضای کاربر: ${date(a.user_expires)}</span></td><td>${number(a.queries)} / ${a.query_limit ? number(a.query_limit) : "نامحدود"}<span class="subline">${number(a.qps)} درخواست در ثانیه</span></td><td>${bytes(a.request_bytes + a.response_bytes)}<span class="subline">${number(a.blocked)} مسدود؛ ${number(a.errors)} خطا</span></td><td>${badge(!a.enabled || !a.user_enabled ? "disabled" : a.user_expires && a.user_expires * 1000 <= Date.now() ? "expired" : "active")}</td>${writable() ? `<td class="actions"><button data-action="dns-edit-account" data-id="${a.id}">ویرایش</button><button data-action="dns-ips" data-id="${a.id}">IPهای مجاز</button>${runtime.doh_url ? `<button data-action="dns-token" data-id="${a.id}">اعتبارنامه DoH</button>` : ""}<button data-action="dns-periods" data-id="${a.id}">دوره‌ها</button><button data-action="dns-reset" data-id="${a.id}">دورهٔ تازه</button><button class="danger" data-action="dns-delete-account" data-id="${a.id}">حذف</button></td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="muted">DNS برای هیچ کاربری فعال نشده است. دسترسی عمومی پیش‌فرض بسته است.</p>'}</section>`;
    await loadSmartDNS();
  } catch (error) {
    if (page === "dns" && $("#dns-content"))
      $("#dns-content").textContent = error.message;
  }
}
function dnsConnectionCard(runtime) {
  const addresses = runtime.addresses || [];
  return `<section class="card dns-connection"><div class="card-head"><h2>DNS معمولی با IP</h2>${badge(runtime.configured ? "active" : "disabled", runtime.configured ? "پیکربندی شده" : "نصب نشده")}</div><p>بدون نیاز به دامنه، HTTPS یا DoH. IP سرور را در تنظیمات DNS دستگاه وارد کنید و IP اینترنت مشتری را برای همان حساب ثبت کنید.</p>${addresses.length ? `<div class="dns-addresses">${addresses.map((ip) => `<code dir="ltr">${esc(ip)}</code>`).join("")}<span>UDP / TCP · پورت ${number(runtime.port)}</span></div>` : ""}${!runtime.configured ? '<p class="notice">روی سرور، sudo donino ← گزینهٔ ۱۰ را اجرا کنید تا DNS معمولی روی IP انتخابی و پورت ۵۳ نصب شود. ساخت حساب در پنل به‌تنهایی سرویس شبکه را نصب نمی‌کند.</p>' : runtime.port !== 53 ? '<p class="notice">کنسول‌ها و DNS سیستم معمولاً پورت ۵۳ می‌خواهند؛ برای پورت سفارشی کلاینت سازگار لازم است.</p>' : ""}<p class="muted">سهمیهٔ درخواست DNS از حجم VPN جداست. پاسخ DNS به‌تنهایی عبور UDP بازی یا کاهش پینگ را تضمین نمی‌کند.</p>${runtime.doh_url ? `<p>DoH اختیاری: <span class="mono">${esc(runtime.doh_url)}</span></p>` : '<p class="muted">DoH روی این پنل HTTP ارائه نمی‌شود و برای DNS معمولی لازم نیست.</p>'}</section>`;
}
function showDNSCredential(value) {
  if (!dnsData.runtime.doh_url) {
    modal(
      "راهنمای DNS معمولی",
      dnsConnectionCard(dnsData.runtime) +
        `<p class="note">حساب DNS ساخته شد. اکنون IP اینترنت مشتری را ثبت کنید؛ نام کاربری یا رمز DoH لازم نیست.</p><button class="primary" data-action="dns-ips" data-id="${esc(value.id)}">ثبت IP مشتری</button>`,
    );
    return;
  }
  modal(
    "اعتبارنامهٔ خصوصی DoH",
    `<p class="notice">DoH اختیاری است؛ DNS معمولی با IPهای مجاز هم قابل استفاده است. اعتبارنامه فقط همین بار نمایش داده می‌شود و باید در هدر Authorization با پیشوند Bearer قرار گیرد.</p><label>نشانی DoH<input readonly dir="ltr" value="${esc(dnsData.runtime.doh_url)}"></label><label>اعتبارنامه<textarea readonly dir="ltr">${esc(value.token)}</textarea></label>`,
  );
}
async function manageDNSIPs(id) {
  const leases = await api(`/dns/accounts/${id}/ip-leases`);
  form(
    "IPهای مجاز DNS",
    `<div class="full"><p class="note">IP اینترنت مشتری را وارد کنید، نه IP سرور DNS. دستگاه‌های پشت یک NAT از یک حساب مشترک استفاده می‌کنند؛ IP مشترک را نمی‌توان هم‌زمان به دو حساب داد. حداکثر سه IP فعال.</p>${leases.length ? leases.map((l) => `<div class="node-row"><div><b class="mono">${esc(l.ip)}</b><small>تا ${new Date(l.expires * 1000).toLocaleString("fa-IR")}</small></div><button type="button" class="danger" data-action="dns-remove-ip" data-id="${esc(id + "|" + l.ip)}">حذف IP</button></div>`).join("") : '<p class="muted">IP مجاز فعالی برای این حساب ثبت نشده است.</p>'}</div>` +
      input("IP مشتری (IPv4 یا IPv6)", "ip", {
        full: true,
        extra: 'dir="ltr" placeholder="203.0.113.20"',
      }) +
      input("مدت اعتبار IP (ساعت)", "hours", {
        type: "number",
        value: 24,
        extra: 'min="1" max="24"',
        hint: "با پایان اعتبار، DNS این IP قطع می‌شود؛ ثبت مجدد همان IP اعتبار را تمدید می‌کند.",
      }),
    async (f) => {
      await api(`/dns/accounts/${id}/ip-leases`, {
        method: "POST",
        body: JSON.stringify({ ip: f.ip.trim(), ttl: Number(f.hours) * 3600 }),
      });
      await saved();
    },
  );
}
async function handleDNSAction(action, id) {
  if (action === "dns-ips") return manageDNSIPs(id);
  if (action === "dns-remove-ip") {
    const [accountId, address] = id.split("|");
    await api(
      `/dns/accounts/${accountId}/ip-leases/${encodeURIComponent(address)}`,
      { method: "DELETE" },
    );
    return manageDNSIPs(accountId);
  }
  if (action.startsWith("dns-smart-")) return handleSmartDNSAction(action, id);
  if (action === "dns-catalog") return catalogPolicyForm();
  if (action === "dns-imports") return showDoctorImports();
  if (action === "dns-add-policy" || action === "dns-edit-policy") {
    const current = dnsData.policies.find((p) => p.id === id);
    form(
      current ? "ویرایش سیاست DNS" : "سیاست DNS جدید",
      input("نام سیاست", "name", { value: current?.name || "", full: true }) +
        `<label class="full">قواعد دامنه<textarea name="rules" rows="8" dir="ltr">${esc((current?.rules || []).map((r) => r.action + " " + r.domain + ((r.action === "route" ? r.exit_ids : r.addresses)?.length ? " " + (r.action === "route" ? r.exit_ids : r.addresses).join(",") : "")).join("\n"))}</textarea><small>هر خط: block example.com برای مسدودسازی، allow sub.example.com برای استثنا، rewrite example.com 1.2.3.4 برای بازنویسی، یا route example.com UUID1,UUID2 برای خروجی‌های مرتب. UUIDها شناسهٔ نود خروجی‌اند؛ فرم مسیریابی آن‌ها را انتخاب می‌کند. دامنه و زیردامنه‌های آن مشمول‌اند؛ قاعدهٔ دقیق‌تر اولویت دارد.</small></label>`,
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
                (["rewrite", "route"].includes(parts[0]) && parts.length === 3)
              )
            )
              throw new Error("ساختار یکی از قواعد صحیح نیست.");
            return {
              action: parts[0],
              domain: parts[1],
              addresses: parts[0] === "rewrite" ? parts[2].split(",") : [],
              exit_ids: parts[0] === "route" ? parts[2].split(",") : [],
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
              relay_enabled: !!current?.relay_enabled,
              relay_limit: current?.relay_limit || 0,
              relay_connections: current?.relay_connections || 8,
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

async function catalogPolicyForm() {
  const source = await api("/dns/catalog");
  const groups = source.services.flatMap((service) =>
    service.groups.map((group) => ({
      service: service.key,
      group: group.key,
      label: service.label + " / " + group.label,
      domains: group.domains.length,
    })),
  );
  form(
    "سیاست از کاتالوگ سرویس‌ها",
    input("نام سیاست", "name", { full: true }) +
      input("IP سرور relay؛ جداکردن با ویرگول", "relay_addresses", {
        full: true,
        extra: 'dir="ltr"',
        hint: "ساخت سیاست، relay را نصب نمی‌کند. دسترسی بازی‌ها و دانلود روی ISP شما هنوز آزموده نشده است.",
      }) +
      `<fieldset class="full catalog-groups"><legend>گروه‌های سرویس</legend>${groups.map((g, i) => `<label><input type="checkbox" name="catalog_group_${i}">${esc(g.label)} (${number(g.domains)})</label>`).join("")}</fieldset><label class="full">استثناهای مستقیم؛ هر دامنه یک خط<textarea name="domains_off" rows="3" dir="ltr"></textarea><small>دامنه باید در گروه‌های انتخاب‌شده باشد. گروه بدون آدرس IPv6، پاسخ AAAA بازنویسی‌شده ندارد.</small></label>`,
    async (f) => {
      const selected = groups
        .filter((g, i) => f["catalog_group_" + i] === "on")
        .map((g) => ({ service: g.service, group: g.group }));
      if (!selected.length) throw new Error("حداقل یک گروه را انتخاب کنید.");
      await api("/dns/policies/from-catalog", {
        method: "POST",
        body: JSON.stringify({
          name: f.name,
          groups: selected,
          relay_addresses: f.relay_addresses
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          domains_off: f.domains_off
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean),
        }),
      });
      await saved();
      toast("سیاست ساخته شد؛ راه‌اندازی relay جداگانه لازم است.");
    },
  );
}
async function showDoctorImports() {
  const values = await api("/imports/doctor");
  modal(
    "انتقال‌های مرحله‌ای doctor-dns",
    `<p class="notice">حجم Smart DNS به تعداد درخواست DNS یا حجم VPN تبدیل نشده است. IP، رمز و کیف پول منبع خودکار فعال نمی‌شوند. بازگشت فقط با ابزار محلی و تا پیش از تغییر حساب ممکن است.</p>${values.length ? `<div class="table-scroll"><table><thead><tr><th>شناسه</th><th>حساب</th><th>حجم منبع / مصرف</th><th>وضعیت</th></tr></thead><tbody>${values.map((v) => `<tr><td class="mono">${esc(v.id.slice(0, 8))}</td><td>${number(v.summary.counts.users)}</td><td>${bytes(v.summary.quota_bytes)} / ${bytes(v.summary.used_bytes)}</td><td>${v.state === "staged" ? "در انتظار تطبیق؛ غیرفعال" : "بازگشت انجام شد"}</td></tr>`).join("")}</tbody></table></div>` : "<p>انتقالی ثبت نشده است.</p>"}`,
  );
}
