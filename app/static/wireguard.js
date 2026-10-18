"use strict";
function renderWireGuard() {
  return (
    heading(
      "WireGuard",
      "کلید و IP مستقل هر دستگاه؛ حجم و انقضا از حساب کاربر اعمال می‌شوند.",
    ) +
    (owner()
      ? '<div class="card" id="wg-content">در حال دریافت…</div>'
      : '<p class="notice">دسترسی مالک لازم است.</p>')
  );
}

async function loadWireGuard() {
  const box = document.querySelector("#wg-content");
  if (!box) return;
  try {
    const endpoints = await api("/wireguard/endpoints");
    if (!box.isConnected) return;
    box.innerHTML = `<p class="notice">پیش‌نمایش IPv4: عامل WireGuard و مسیر خروجی باید روی نود آماده باشند. ساخت رابط، شبکهٔ میزبان را خودکار مسیریابی نمی‌کند. پروفایل تمام‌ترافیک، IPv6 را برای جلوگیری از عبور مستقیم مسدود می‌کند.</p><h2>رابط تازه</h2><form id="wg-create" class="form-grid"><label>نام<input name="name" required maxlength="64"></label><label>نود<select name="node_id" required>${data.nodes.map((n) => `<option value="${esc(n.id)}">${esc(n.name)}</option>`).join("")}</select></label><label>دامنه یا IP سرور<input name="host" dir="ltr" required></label><label>پورت UDP<input name="port" type="number" min="1024" max="65535" value="51820" required></label><label>محدودهٔ خصوصی IPv4<input name="pool" dir="ltr" value="10.66.0.0/24" required></label><label>DNS اختیاری، با ویرگول<input name="dns" dir="ltr" placeholder="1.1.1.1"></label><label>مسیرهای IPv4، با ویرگول<input name="routes" dir="ltr" value="0.0.0.0/0" required></label><button type="submit" class="primary">ساخت رابط غیرفعال</button></form><p id="wg-message" role="status"></p><div id="wg-endpoints">${endpoints.length ? endpoints.map((e) => `<article class="card"><h2>${esc(e.name)} · ${e.enabled ? "فعال" : "غیرفعال"}</h2><p class="mono" dir="ltr">${esc(e.host)}:${e.port} · ${esc(e.pool)}</p><p>نود: ${esc(data.nodes.find((n) => n.id === e.node_id)?.name || e.node_id.slice(0, 8))}</p><div class="actions"><button type="button" data-wg-toggle="${esc(e.id)}" data-enabled="${e.enabled ? "0" : "1"}">${e.enabled ? "غیرفعال‌کردن رابط" : "فعال‌کردن رابط"}</button><button type="button" data-wg-peers="${esc(e.id)}">دستگاه‌ها و کانفیگ</button></div><div data-wg-list="${esc(e.id)}" hidden></div></article>`).join("") : "<p>هنوز رابطی ساخته نشده است.</p>"}</div>`;
    const form = box.querySelector("#wg-create");
    form.onsubmit = async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      button.disabled = true;
      try {
        const values = Object.fromEntries(new FormData(form));
        await api("/wireguard/endpoints", {
          method: "POST",
          body: JSON.stringify({
            ...values,
            port: Number(values.port),
            dns: values.dns
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
            routes: values.routes
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          }),
        });
        await loadWireGuard();
      } catch (error) {
        box.querySelector("#wg-message").textContent = error.message;
      } finally {
        button.disabled = false;
      }
    };
    box.onclick = async (event) => {
      const toggle = event.target.closest("[data-wg-toggle]"),
        peers = event.target.closest("[data-wg-peers]");
      if (!toggle && !peers) return;
      const button = toggle || peers;
      button.disabled = true;
      try {
        if (toggle) {
          await api(`/wireguard/endpoints/${toggle.dataset.wgToggle}`, {
            method: "PUT",
            body: JSON.stringify({ enabled: toggle.dataset.enabled === "1" }),
          });
          await loadWireGuard();
        } else await loadWireGuardPeers(box, peers.dataset.wgPeers);
      } catch (error) {
        box.querySelector("#wg-message").textContent = error.message;
      } finally {
        button.disabled = false;
      }
    };
  } catch (error) {
    if (box.isConnected) box.textContent = error.message;
  }
}

async function loadWireGuardPeers(box, eid) {
  const rows = await api(`/wireguard/endpoints/${eid}/peers`);
  const section = box.querySelector(`[data-wg-list="${CSS.escape(eid)}"]`);
  section.hidden = false;
  section.innerHTML = `<h3>دستگاه‌های WireGuard</h3><form class="form-grid wg-peer-create"><label>جستجوی حساب<input name="search" type="search"></label><label>حساب<select name="user" required></select></label><label>دستگاه<select name="device_id" required></select></label><button type="submit">ساخت peer و IP مستقل</button></form><p>کانفیگ و QR شامل کلید خصوصی‌اند؛ آنها را فقط به صاحب همان دستگاه بدهید. تعویض کلید، کانفیگ قبلی را باطل می‌کند.</p><div class="table-scroll"><table><thead><tr><th>دستگاه</th><th>IP</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>${rows.map((p) => `<tr><td class="mono">${esc(p.device_id.slice(0, 8))}</td><td class="mono">${esc(p.address)}</td><td>${p.enabled ? "فعال" : "غیرفعال"}</td><td><a href="/api/wireguard/peers/${esc(p.id)}/profile" download>دریافت conf</a> <button type="button" data-wg-qr="${esc(p.id)}">QR خصوصی</button> <button type="button" data-wg-peer="${esc(p.id)}" data-enabled="${p.enabled ? "0" : "1"}">${p.enabled ? "لغو دسترسی" : "فعال‌کردن"}</button> <button type="button" data-wg-rotate="${esc(p.id)}">تعویض کلید</button></td></tr>`).join("")}</tbody></table></div><div class="wg-private-qr" hidden></div><p class="wg-peer-message" role="status"></p>`;
  const form = section.querySelector("form"),
    message = section.querySelector(".wg-peer-message");
  let generation = 0,
    timer;
  async function devices() {
    const current = ++generation;
    form.elements.device_id.replaceChildren();
    if (!form.elements.user.value) return;
    try {
      const devices = await api(`/users/${form.elements.user.value}/devices`);
      if (!section.isConnected || current !== generation) return;
      devices
        .filter((d) => d.enabled)
        .forEach((d) => form.elements.device_id.add(new Option(d.name, d.id)));
    } catch (error) {
      message.textContent = error.message;
    }
  }
  function users(rows) {
    form.elements.user.replaceChildren();
    rows
      .filter((u) => u.enabled)
      .forEach((u) => form.elements.user.add(new Option(u.name, u.id)));
    devices();
  }
  users(data.users);
  form.elements.user.onchange = devices;
  form.elements.search.oninput = () => {
    clearTimeout(timer);
    const current = ++generation;
    timer = setTimeout(async () => {
      try {
        const rows = await api(
          "/users?limit=25&q=" + encodeURIComponent(form.elements.search.value),
        );
        if (section.isConnected && current === generation) users(rows);
      } catch (error) {
        message.textContent = error.message;
      }
    }, 250);
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      await api(`/wireguard/endpoints/${eid}/peers`, {
        method: "POST",
        body: JSON.stringify({ device_id: form.elements.device_id.value }),
      });
      await loadWireGuardPeers(box, eid);
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
  section.onclick = async (event) => {
    const revoke = event.target.closest("[data-wg-peer]"),
      rotate = event.target.closest("[data-wg-rotate]"),
      qr = event.target.closest("[data-wg-qr]");
    const button = revoke || rotate || qr;
    if (!button) return;
    if (qr) {
      const target = section.querySelector(".wg-private-qr");
      target.hidden = false;
      target.innerHTML = `<img class="qr" alt="QR محرمانهٔ دستگاه WireGuard" src="/api/wireguard/peers/${esc(qr.dataset.wgQr)}/qr"><button type="button" class="wg-hide-qr">بستن QR</button>`;
      target.querySelector("button").onclick = () => target.replaceChildren();
      return;
    }
    if (
      rotate &&
      !confirm("کلید قبلی این دستگاه باطل می‌شود؛ تعویض کلید را تأیید می‌کنید؟")
    )
      return;
    button.disabled = true;
    try {
      if (revoke)
        await api(`/wireguard/peers/${revoke.dataset.wgPeer}`, {
          method: "PUT",
          body: JSON.stringify({ enabled: revoke.dataset.enabled === "1" }),
        });
      else
        await api(`/wireguard/peers/${rotate.dataset.wgRotate}/rotate`, {
          method: "POST",
        });
      await loadWireGuardPeers(box, eid);
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
}
