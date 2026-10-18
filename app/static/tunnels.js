"use strict";
function renderTunnels() {
  return (
    heading(
      "تانل خودکار",
      "اتصال دوطرفه با Donino Tunnel؛ مدیریت کاربران و حجم در همین پنل می‌ماند.",
    ) +
    (owner()
      ? '<div id="tunnel-content" class="card">در حال دریافت وضعیت…</div>'
      : '<p class="notice">دسترسی مالک لازم است.</p>')
  );
}
function tunnelJobs(rows) {
  const labels = {
    running: "در حال اجرا",
    succeeded: "نصب و بررسی مسیر موفق",
    failed: "ناموفق",
    interrupted: "متوقف‌شده",
    rollback_failed: "بازگشت ناموفق؛ نیازمند بررسی",
  };
  return rows.length
    ? `<div class="table-scroll"><table><thead><tr><th>عملیات</th><th>وضعیت</th><th>مرحله</th></tr></thead><tbody>${rows.map((j) => `<tr><td class="mono">${esc(j.id.slice(0, 8))}</td><td>${esc(labels[j.status] || j.status)}</td><td>${esc(j.stage)}</td></tr>`).join("")}</tbody></table></div>`
    : "<p>هنوز عملیات نصبی ثبت نشده است.</p>";
}
async function loadTunnelJobs() {
  const box = document.querySelector("#tunnel-jobs");
  if (!box || page !== "tunnels" || !owner()) return;
  try {
    const state = await api("/tunnels/state");
    if (box.isConnected)
      box.innerHTML = state.available
        ? tunnelJobs(state.jobs)
        : esc(state.reason || "کنترل‌کننده در دسترس نیست");
  } catch (error) {
    if (box.isConnected) box.textContent = error.message;
  }
}
async function loadTunnels() {
  const box = document.querySelector("#tunnel-content");
  if (!box || !owner()) return;
  try {
    const state = await api("/tunnels/state");
    if (!box.isConnected) return;
    if (!state.available) {
      box.innerHTML = `<h2>آماده‌سازی اتصال تانل</h2><p>${esc(state.reason)}</p><p>نصب نقش ایران روی میزبان همین پنل و نقش خارج روی سرور مقصد لازم است. در این مرحله از پروژه، آماده‌سازی اولیهٔ دو میزبان از راهنمای نصب انجام می‌شود.</p><a class="subtle-link" href="https://github.com/danialrad04-sketch/donino-panel/blob/main/docs/TUNNEL-BRIDGE.fa.md" target="_blank" rel="noopener">راهنمای نصب و فعال‌سازی</a>`;
      return;
    }
    box.innerHTML = `<p class="notice">نسخهٔ آزمایشی: فوروارد TCP روی FRP WSS و FRP QUIC. نصب، مجموعهٔ کامل تانل‌های مدیریت‌شدهٔ دو سرور را جایگزین می‌کند و ممکن است اتصال جاری قطع شود. این فرم اشتراک کاربران را خودکار تغییر نمی‌دهد.</p>
      <section><h2>۱. جفت‌سازی خارج</h2><form id="tunnel-pair" class="form-grid"><label>نام اتصال<input name="name" required maxlength="64"></label><label>IP یا دامنهٔ خارج<input name="host" dir="ltr" required></label><label>پورت مدیریت HTTPS<input name="agent_port" type="number" min="1024" max="65535" value="9444" required></label><label>کد یک‌بارمصرف پنل خارج<input name="code" type="password" autocomplete="off" required></label><button class="primary" type="submit">جفت‌سازی امن</button></form></section>
      <section><h2>۲. نقشهٔ تانل</h2><p>مقصد هر سرویس، پورت اتصال موجود روی loopback سرور خارج است. گواهی، SNI و اعتبارنامهٔ کاربران در سرویس مقصد حفظ می‌شوند. کد جفت‌سازی در این پنل ذخیره نمی‌شود.</p><form id="tunnel-plan" class="form-grid"><label>اتصال خارج<select name="profile_id" required>${state.profiles
        .filter((p) => p.management === "https-v1")
        .map(
          (p) =>
            `<option value="${esc(p.id)}">${esc(p.name)} · ${esc(p.host)}</option>`,
        )
        .join(
          "",
        )}</select></label><label>IP یا دامنهٔ ایران<input name="iran" dir="ltr" value="${esc(state.iran_address || "")}" required></label><label>حامل<select name="carrier"><option value="frp-wss">FRP WSS</option><option value="frp-quic">FRP QUIC</option><option value="both">هر دو، با مسیر جایگزین برای اتصال جدید</option></select></label><label>سرویس‌ها: نام، پورت ایران، پورت مقصد خارج<textarea name="services" dir="ltr" rows="4" required placeholder="vpn,443,8443"></textarea></label><button type="button" id="tunnel-connection">آزمون ارتباط مدیریت</button><button class="primary" type="submit">نمایش نقشه و پورت‌ها</button></form></section>
      <section id="tunnel-review" hidden><h2>۳. مرور و نصب</h2><pre id="tunnel-map" dir="ltr"></pre><label><input type="checkbox" id="tunnel-confirm">جایگزینی مجموعهٔ تانل‌های مدیریت‌شدهٔ هر دو سرور و احتمال قطع اتصال جاری را تأیید می‌کنم.</label><button type="button" class="primary" id="tunnel-start" disabled>شروع نصب دوطرفه</button></section><p id="tunnel-message" role="status"></p><section><h2>عملیات پایدار</h2><button type="button" id="tunnel-reload">دریافت وضعیت</button><div id="tunnel-jobs">${tunnelJobs(state.jobs)}</div></section>`;
    const pair = box.querySelector("#tunnel-pair"),
      form = box.querySelector("#tunnel-plan"),
      review = box.querySelector("#tunnel-review"),
      message = box.querySelector("#tunnel-message"),
      start = box.querySelector("#tunnel-start"),
      confirm = box.querySelector("#tunnel-confirm");
    let plan = null,
      generation = 0,
      busy = false;
    function invalidate() {
      generation += 1;
      plan = null;
      review.hidden = true;
      start.disabled = true;
      confirm.checked = false;
    }
    async function action(button, work) {
      if (busy) return;
      busy = true;
      button.disabled = true;
      message.textContent = "در حال بررسی…";
      try {
        await work();
      } catch (error) {
        message.textContent = error.message;
      } finally {
        busy = false;
        if (button !== start) button.disabled = false;
      }
    }
    pair.onsubmit = (e) => {
      e.preventDefault();
      invalidate();
      const body = Object.fromEntries(new FormData(pair));
      body.agent_port = Number(body.agent_port);
      pair.elements.code.value = "";
      action(pair.querySelector("button"), async () => {
        const p = await api("/tunnels/pair", {
          method: "POST",
          body: JSON.stringify(body),
        });
        const option = new Option(p.name + " · " + p.host, p.id);
        form.elements.profile_id.add(option);
        form.elements.profile_id.value = p.id;
        message.textContent = "جفت‌سازی انجام شد؛ نقشهٔ تانل را بسازید.";
      });
    };
    form.addEventListener("input", invalidate);
    form.addEventListener("change", invalidate);
    box.querySelector("#tunnel-connection").onclick = (e) =>
      action(e.target, async () => {
        const result = await api("/tunnels/connection", {
          method: "POST",
          body: JSON.stringify({ profile_id: form.elements.profile_id.value }),
        });
        message.textContent =
          result.ok && result.ready && result.runtime_match
            ? "مدیریت امن آماده است؛ این نتیجه هنوز آزمون عبور ترافیک VPN نیست."
            : "ارتباط/پیش‌نیازها یا نسخهٔ دو طرف آماده نیست؛ هر دو نصب را بررسی کنید.";
      });
    form.onsubmit = (e) => {
      e.preventDefault();
      invalidate();
      action(form.querySelector("button[type=submit]"), async () => {
        const requestedGeneration = generation;
        const values = Object.fromEntries(new FormData(form));
        const services = values.services
          .trim()
          .split(/\r?\n/)
          .map((line) => {
            const parts = line.split(",").map((s) => s.trim());
            if (parts.length !== 3)
              throw new Error(
                "هر سطر باید نام، پورت ایران و پورت خارج داشته باشد.",
              );
            return {
              id: parts[0],
              listen_port: Number(parts[1]),
              target_port: Number(parts[2]),
            };
          });
        const proposedPlan = await api("/tunnels/preview", {
          method: "POST",
          body: JSON.stringify({
            profile_id: values.profile_id,
            iran: values.iran.trim(),
            services,
            transports:
              values.carrier === "both"
                ? ["frp-wss", "frp-quic"]
                : [values.carrier],
          }),
        });
        if (requestedGeneration !== generation || !box.isConnected) {
          message.textContent =
            "فرم هنگام دریافت نقشه تغییر کرد؛ دوباره نقشه بسازید.";
          return;
        }
        plan = proposedPlan;
        box.querySelector("#tunnel-map").textContent = JSON.stringify(
          plan.summary,
          null,
          2,
        );
        review.hidden = false;
        message.textContent =
          "پورت‌های نقشه را در فایروال میزبان و شرکت میزبان بررسی کنید. این فرم فایروال را تغییر نمی‌دهد. نقشه یک ساعت اعتبار دارد.";
      });
    };
    confirm.onchange = () => {
      start.disabled = !confirm.checked || !plan || busy;
    };
    start.onclick = () => {
      if (!plan || !confirm.checked) return;
      const id = plan.id;
      invalidate();
      action(start, async () => {
        const job = await api("/tunnels/start", {
          method: "POST",
          body: JSON.stringify({ plan_id: id, confirm_replace: true }),
        });
        message.textContent =
          "عملیات " +
          job.id.slice(0, 8) +
          " ثبت شد؛ نتیجه را در وضعیت عملیات دنبال کنید. بستن صفحه کار را متوقف نمی‌کند.";
        await loadTunnelJobs();
      });
    };
    box.querySelector("#tunnel-reload").onclick = loadTunnelJobs;
  } catch (error) {
    if (box.isConnected) box.textContent = error.message;
  }
}
