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
function tunnelOperationContent(state) {
  const bindings = state.bindings || [];
  const labels = {
    preparing: "در حال ساخت نقشه",
    previewed: "آمادهٔ مرور",
    stale: "نیازمند نقشهٔ تازه",
    preview_unknown: "پاسخ ساخت نقشه نامطمئن",
    starting: "شروع ثبت شد",
    start_unknown: "نتیجهٔ شروع نامطمئن؛ وضعیت را دریافت کنید",
    running: "نصب در حال اجرا",
    succeeded: "نصب حامل موفق؛ آزمون VPN لازم است",
    failed: "نصب ناموفق",
    interrupted: "نصب متوقف شد",
    rollback_failed: "بازگشت نیازمند بررسی",
  };
  const bound = bindings.length
    ? `<h3>نقشه‌های متصل به پنل</h3><div class="table-scroll"><table><thead><tr><th>نود / نقشه</th><th>وضعیت</th><th>تنظیمات مبدأ</th><th>عملیات</th></tr></thead><tbody>${bindings.map((b) => `<tr><td>${esc(data.nodes.find((n) => n.id === b.node_id)?.name || "نود حذف‌شده")}<span class="subline mono">${esc(b.id.slice(0, 8))}</span></td><td>${esc(labels[b.phase] || b.phase)}${b.endpoint_published ? '<span class="subline">آدرس تانل در اشتراک منتشر شده</span>' : ""}${(b.checks || []).length ? `<span class="subline">آخرین آزمون VPN: ${esc({ succeeded: "موفق", failed: "ناموفق", running: "در حال اجرا", invalidated: "باطل‌شده" }[b.checks[0].phase] || b.checks[0].phase)}</span>` : ""}</td><td>${b.source_matches ? "مطابق" : "تغییر کرده؛ نقشهٔ تازه لازم است"}</td><td>${b.can_start ? `<button type="button" data-binding-review="${esc(b.id)}">مرور نقشه</button>` : ""}${b.phase === "succeeded" && b.source_matches ? `<button type="button" data-binding-verify="${esc(b.id)}">آزمون و انتشار</button>` : ""}${b.endpoint_published ? `<button type="button" data-binding-unpublish="${esc(b.id)}">لغو انتشار</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
    : "";
  const known = new Set(bindings.map((b) => b.job_id));
  const other = state.jobs.filter((j) => !known.has(j.id));
  return bound + (other.length || !bindings.length ? tunnelJobs(other) : "");
}
async function loadTunnelJobs() {
  const box = document.querySelector("#tunnel-jobs");
  if (!box || page !== "tunnels" || !owner()) return;
  try {
    const state = await api("/tunnels/state");
    if (box.isConnected)
      box.innerHTML = state.available
        ? tunnelOperationContent(state)
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
      <section><h2>۲. نقشهٔ تانل</h2><p>نود انتخاب‌شده باید روی همان سرور خارجِ جفت‌شده باشد. مقصد از پورت اتصال موجود در پنل ساخته می‌شود؛ فقط پورت عمومی ایران را تعیین کنید. گواهی، SNI و اعتبارنامهٔ کاربران در سرویس مقصد حفظ می‌شوند. کد جفت‌سازی در این پنل ذخیره نمی‌شود.</p><form id="tunnel-plan" class="form-grid"><label>اتصال خارج<select name="profile_id" required>${state.profiles
        .filter((p) => p.management === "https-v1")
        .map(
          (p) =>
            `<option value="${esc(p.id)}">${esc(p.name)} · ${esc(p.host)}</option>`,
        )
        .join(
          "",
        )}</select></label><label>IP یا دامنهٔ ایران<input name="iran" dir="ltr" value="${esc(state.iran_address || "")}" required></label><label>حامل<select name="carrier"><option value="frp-wss">FRP WSS</option><option value="frp-quic">FRP QUIC</option><option value="both">هر دو، با مسیر جایگزین برای اتصال جدید</option></select></label><label>ساخت نقشه<select name="mode"><option value="panel">از اتصال‌های همین پنل</option><option value="manual">پورت‌های دستی</option></select></label><label id="tunnel-node-choice">نود خارج<select name="node_id" required>${data.nodes.map((n) => `<option value="${esc(n.id)}">${esc(n.name)} · ${esc(n.host)}</option>`).join("")}</select></label><fieldset id="tunnel-inbounds" class="full"></fieldset><label id="tunnel-manual-services" hidden>سرویس‌ها: نام، پورت ایران، پورت مقصد خارج<textarea name="services" dir="ltr" rows="4" disabled placeholder="vpn,1443,8443"></textarea></label><button type="button" id="tunnel-connection">آزمون ارتباط مدیریت</button><button class="primary" type="submit">نمایش نقشه و پورت‌ها</button></form></section>
      <section id="tunnel-review" hidden><h2>۳. مرور و نصب</h2><pre id="tunnel-map" dir="ltr"></pre><label><input type="checkbox" id="tunnel-confirm">جایگزینی مجموعهٔ تانل‌های مدیریت‌شدهٔ هر دو سرور و احتمال قطع اتصال جاری را تأیید می‌کنم.</label><button type="button" class="primary" id="tunnel-start" disabled>شروع نصب دوطرفه</button></section><section id="tunnel-acceptance" hidden></section><p id="tunnel-message" role="status"></p><section><h2>عملیات پایدار</h2><button type="button" id="tunnel-reload">دریافت وضعیت</button><div id="tunnel-jobs">${tunnelOperationContent(state)}</div></section>`;
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
    function renderInboundChoices() {
      const bound = form.elements.mode.value === "panel";
      box.querySelector("#tunnel-node-choice").hidden = !bound;
      form.elements.node_id.disabled = !bound;
      box.querySelector("#tunnel-manual-services").hidden = bound;
      form.elements.services.disabled = bound;
      form.elements.services.required = !bound;
      const choices = box.querySelector("#tunnel-inbounds");
      choices.hidden = !bound;
      if (!bound) {
        choices.replaceChildren();
        return;
      }
      const inbounds = data.inbounds.filter(
        (i) => i.node_id === form.elements.node_id.value && i.enabled,
      );
      choices.innerHTML =
        "<legend>اتصال‌ها و پورت عمومی ایران</legend>" +
        (inbounds.length
          ? inbounds
              .map(
                (i) =>
                  `<div class="tunnel-service-row"><label><input type="checkbox" class="tunnel-service-choice" data-inbound="${esc(i.id)}"> ${esc(i.name)} · ${esc(i.protocol.toUpperCase())} · مقصد ${i.port}</label><label>پورت ایران<input type="number" min="1" max="65535" required disabled name="port_${esc(i.id)}" value="${i.port === 443 ? 1443 : i.port}" dir="ltr"></label></div>`,
              )
              .join("")
          : "<p>نود و اتصال فعال روی سرور خارج بسازید یا حالت دستی را انتخاب کنید.</p>");
    }
    form.elements.mode.onchange = renderInboundChoices;
    form.elements.node_id.onchange = renderInboundChoices;
    form.addEventListener("change", (e) => {
      if (e.target.matches(".tunnel-service-choice"))
        form.elements["port_" + e.target.dataset.inbound].disabled =
          !e.target.checked;
    });
    renderInboundChoices();
    box.addEventListener("click", async (e) => {
      const remove = e.target.closest("[data-binding-unpublish]");
      if (remove) {
        action(remove, async () => {
          await api(
            `/tunnels/bindings/${remove.dataset.bindingUnpublish}/publication`,
            { method: "DELETE" },
          );
          box.querySelector("#tunnel-acceptance").hidden = true;
          message.textContent =
            "آدرس تانل از اشتراک‌های بعدی حذف شد؛ نصب تانل و اعتبارنامه‌ها باقی هستند.";
          await loadTunnelJobs();
        });
        return;
      }
      const verify = e.target.closest("[data-binding-verify]");
      if (verify) {
        action(verify, async () => {
          const value = await api(
            `/tunnels/bindings/${verify.dataset.bindingVerify}`,
          );
          renderTunnelAcceptance(
            box,
            value,
            action,
            message,
            state.probe_available,
          );
        });
        return;
      }
      const button = e.target.closest("[data-binding-review]");
      if (!button || busy) return;
      invalidate();
      action(button, async () => {
        const value = await api(
          "/tunnels/bindings/" + button.dataset.bindingReview,
        );
        if (!box.isConnected) return;
        if (!value.can_start)
          throw new Error(
            "این نقشه تغییر کرده یا قابل شروع نیست؛ نقشهٔ تازه بسازید.",
          );
        plan = { ...value, bound: true };
        box.querySelector("#tunnel-map").textContent = JSON.stringify(
          value.summary,
          null,
          2,
        );
        review.hidden = false;
        message.textContent =
          "نقشهٔ ذخیره‌شده بازیابی شد؛ مقصدها و پورت‌ها را دوباره مرور کنید. این مرحله هنوز تأیید انتقال VPN نیست.";
      });
    });
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
        const bound = values.mode === "panel";
        const services = bound
          ? [...form.querySelectorAll(".tunnel-service-choice:checked")].map(
              (input) => ({
                inbound_id: input.dataset.inbound,
                listen_port: Number(
                  form.elements["port_" + input.dataset.inbound].value,
                ),
              }),
            )
          : values.services
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
        const proposedPlan = await api(
          bound ? "/tunnels/bindings" : "/tunnels/preview",
          {
            method: "POST",
            body: JSON.stringify({
              profile_id: values.profile_id,
              iran: values.iran.trim(),
              services,
              ...(bound ? { node_id: values.node_id } : {}),
              transports:
                values.carrier === "both"
                  ? ["frp-wss", "frp-quic"]
                  : [values.carrier],
            }),
          },
        );
        if (requestedGeneration !== generation || !box.isConnected) {
          message.textContent =
            "فرم هنگام دریافت نقشه تغییر کرد؛ دوباره نقشه بسازید.";
          return;
        }
        plan = { ...proposedPlan, bound };
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
      const id = plan.id,
        bound = plan.bound;
      invalidate();
      action(start, async () => {
        const job = await api(
          bound ? `/tunnels/bindings/${id}/start` : "/tunnels/start",
          {
            method: "POST",
            body: JSON.stringify(
              bound
                ? { confirm_replace: true }
                : { plan_id: id, confirm_replace: true },
            ),
          },
        );
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

function renderTunnelAcceptance(box, binding, action, message, available) {
  const section = box.querySelector("#tunnel-acceptance");
  section.hidden = false;
  if (!available) {
    section.innerHTML =
      "<h2>۴. آزمون و انتشار</h2><p>کلاینت و مقصد امن آزمون هنوز روی میزبان پنل پیکربندی نشده‌اند. راهنمای تانل را برای فعال‌سازی بررسی کنید.</p>";
    return;
  }
  section.innerHTML = `<h2>۴. آزمون واقعی VPN و انتشار</h2><p>حداکثر ۸ اتصال TLS را انتخاب کنید. ترافیک آزمون از حجم دستگاه انتخاب‌شده مصرف می‌شود. آزمون مجدد، انتشار قبلی مسیرهای مربوط را لغو می‌کند. نتیجه سلامت لحظهٔ آزمون است.</p><form class="form-grid" id="tunnel-verify-form"><label>جستجوی حساب<input name="search" type="search" autocomplete="off"></label><label>حساب آزمون<select name="user_id" required></select></label><label>دستگاه آزمون<select name="device_id" required></select></label><fieldset class="full"><legend>اتصال‌های قابل بررسی</legend>${(binding.services || []).map((s, i) => `<label><input type="checkbox" name="inbound" value="${esc(s.inbound_id)}" ${i < 8 ? "checked" : ""}> ${esc(data.inbounds.find((r) => r.id === s.inbound_id)?.name || s.inbound_id.slice(0, 8))} · ${s.listen_port}</label>`).join("")}</fieldset><button type="submit" class="primary">آزمون انتقال VPN</button></form><div id="tunnel-publication"></div>`;
  const form = section.querySelector("form");
  let userGeneration = 0,
    inputGeneration = 0,
    timer;
  const changed = () => {
    inputGeneration += 1;
    section.querySelector("#tunnel-publication").replaceChildren();
  };
  form.addEventListener("input", changed);
  form.addEventListener("change", changed);
  async function devices() {
    const generation = ++userGeneration;
    form.elements.device_id.replaceChildren();
    if (!form.elements.user_id.value) return;
    try {
      const rows = await api(`/users/${form.elements.user_id.value}/devices`);
      if (!section.isConnected || generation !== userGeneration) return;
      rows
        .filter((r) => r.enabled)
        .forEach((r) => form.elements.device_id.add(new Option(r.name, r.id)));
    } catch (error) {
      message.textContent = error.message;
    }
  }
  function users(rows) {
    form.elements.user_id.replaceChildren();
    rows
      .filter((r) => r.enabled)
      .forEach((r) => form.elements.user_id.add(new Option(r.name, r.id)));
    devices();
  }
  users(data.users);
  form.elements.user_id.onchange = devices;
  let searchGeneration = 0;
  form.elements.search.oninput = () => {
    clearTimeout(timer);
    const generation = ++searchGeneration;
    timer = setTimeout(async () => {
      try {
        const rows = await api(
          "/users?limit=25&q=" + encodeURIComponent(form.elements.search.value),
        );
        if (section.isConnected && generation === searchGeneration) users(rows);
      } catch (error) {
        message.textContent = error.message;
      }
    }, 250);
  };
  form.onsubmit = (e) => {
    e.preventDefault();
    const inbound_ids = [
      ...form.querySelectorAll("[name=inbound]:checked"),
    ].map((input) => input.value);
    if (!inbound_ids.length || inbound_ids.length > 8) {
      message.textContent = "بین ۱ تا ۸ اتصال انتخاب کنید.";
      return;
    }
    const body = { device_id: form.elements.device_id.value, inbound_ids };
    const requestedGeneration = inputGeneration;
    section.querySelector("#tunnel-publication").replaceChildren();
    action(form.querySelector("button"), async () => {
      message.textContent =
        "کلاینت واقعی در حال آزمون انتقال است؛ تا پایان منتظر بمانید.";
      const check = await api(`/tunnels/bindings/${binding.id}/verify`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!section.isConnected || section.hidden) return;
      if (requestedGeneration !== inputGeneration) {
        message.textContent =
          "انتخاب‌ها هنگام آزمون تغییر کردند؛ نتیجه در تاریخچه است. برای انتشار، انتخاب‌ها را دوباره آزمون کنید.";
        await loadTunnelJobs();
        return;
      }
      if (check.phase !== "succeeded") {
        message.textContent =
          "آزمون انتقال موفق نشد؛ آدرس تانل منتشر نشد. وضعیت مسیر و گواهی را بررسی کنید.";
        await loadTunnelJobs();
        return;
      }
      message.textContent =
        "انتقال VPN موفق شد؛ برای افزودن آدرس به اشتراک تأیید جداگانه لازم است.";
      const publication = section.querySelector("#tunnel-publication");
      publication.innerHTML =
        '<p>انتشار فقط اتصال‌های آزموده‌شده را به اشتراک اضافه می‌کند. آدرس اصلی باقی می‌ماند. آدرس تانل پس از ۲۴ ساعت از خروجی حذف می‌شود مگر دوباره آزمون و منتشر شود؛ این کار کانفیگ ذخیره‌شدهٔ کلاینت را باطل نمی‌کند.</p><label><input type="checkbox" id="tunnel-publish-confirm">افزودن آدرس آزموده‌شده به اشتراک کاربران مجاز نود را تأیید می‌کنم.</label><button type="button" id="tunnel-publish" disabled>انتشار در اشتراک</button>';
      const button = publication.querySelector("button"),
        confirm = publication.querySelector("input");
      confirm.onchange = () => {
        button.disabled = !confirm.checked;
      };
      button.onclick = () => {
        if (!confirm.checked) return;
        confirm.checked = false;
        button.disabled = true;
        action(button, async () => {
          await api(`/tunnels/bindings/${binding.id}/publication`, {
            method: "POST",
            body: JSON.stringify({ check_id: check.id, confirm_publish: true }),
          });
          publication.replaceChildren();
          message.textContent =
            "آدرس تانل برای ۲۴ ساعت به اشتراک اضافه شد. برای تمدید، آزمون تازه و انتشار لازم است.";
          await loadTunnelJobs();
        });
      };
      await loadTunnelJobs();
    });
  };
}
