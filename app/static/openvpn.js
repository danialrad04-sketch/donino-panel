"use strict";
function renderOpenVPN() {
  return (
    heading(
      "OpenVPN",
      "گواهی و IP مستقل هر دستگاه؛ حجم و انقضا از حساب کاربر اعمال می‌شوند.",
    ) +
    (owner()
      ? '<div class="card" id="ovpn-content">در حال دریافت…</div>'
      : '<p class="notice">دسترسی مالک لازم است.</p>')
  );
}

async function loadOpenVPN() {
  const box = document.querySelector("#ovpn-content");
  if (!box) return;
  try {
    const endpoints = await api("/openvpn/endpoints");
    if (!box.isConnected) return;
    box.innerHTML = `<p class="notice">پیش‌نمایش OpenVPN 2.6 و IPv4: عامل OpenVPN و مسیر خروجی باید روی نود آماده باشند. ساخت رابط، شبکهٔ میزبان را خودکار مسیریابی نمی‌کند. پروفایل تمام‌ترافیک، IPv6 را برای جلوگیری از عبور مستقیم مسدود می‌کند.</p><h2>رابط تازه</h2><form id="ovpn-create" class="form-grid"><label>نام<input name="name" required maxlength="64"></label><label>نود<select name="node_id" required>${data.nodes.map((n) => `<option value="${esc(n.id)}">${esc(n.name)}</option>`).join("")}</select></label><label>دامنه یا IP سرور<input name="host" dir="ltr" required></label><label>پروتکل<select name="protocol"><option value="udp">UDP</option><option value="tcp">TCP</option></select></label><label>پورت<input name="port" type="number" min="1024" max="65535" value="1194" required></label><label>محدودهٔ خصوصی IPv4<input name="pool" dir="ltr" value="10.67.0.0/24" required></label><label>DNS اختیاری، با ویرگول<input name="dns" dir="ltr" placeholder="1.1.1.1"></label><label>مسیرهای IPv4، با ویرگول<input name="routes" dir="ltr" value="0.0.0.0/0" required></label><button type="submit" class="primary">ساخت رابط غیرفعال</button></form><p id="ovpn-message" role="status"></p><div id="ovpn-endpoints">${endpoints.length ? endpoints.map((e) => `<article class="card"><h2>${esc(e.name)} · ${e.enabled ? "فعال" : "غیرفعال"}</h2><p class="mono" dir="ltr">${esc(e.host)}:${e.port} · ${esc(e.protocol.toUpperCase())} · ${esc(e.pool)}</p><p>نود: ${esc(data.nodes.find((n) => n.id === e.node_id)?.name || e.node_id.slice(0, 8))}</p><div class="actions"><button type="button" data-ovpn-toggle="${esc(e.id)}" data-enabled="${e.enabled ? "0" : "1"}">${e.enabled ? "غیرفعال‌کردن رابط" : "فعال‌کردن رابط"}</button><button type="button" data-ovpn-peers="${esc(e.id)}">دستگاه‌ها و کانفیگ</button></div><div data-ovpn-list="${esc(e.id)}" hidden></div></article>`).join("") : "<p>هنوز رابطی ساخته نشده است.</p>"}</div>`;
    const form = box.querySelector("#ovpn-create");
    form.onsubmit = async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      button.disabled = true;
      try {
        const values = Object.fromEntries(new FormData(form));
        await api("/openvpn/endpoints", {
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
        await loadOpenVPN();
      } catch (error) {
        box.querySelector("#ovpn-message").textContent = error.message;
      } finally {
        button.disabled = false;
      }
    };
    box.onclick = async (event) => {
      const toggle = event.target.closest("[data-ovpn-toggle]"),
        peers = event.target.closest("[data-ovpn-peers]");
      if (!toggle && !peers) return;
      const button = toggle || peers;
      button.disabled = true;
      try {
        if (toggle) {
          await api(`/openvpn/endpoints/${toggle.dataset.ovpnToggle}`, {
            method: "PUT",
            body: JSON.stringify({ enabled: toggle.dataset.enabled === "1" }),
          });
          await loadOpenVPN();
        } else await loadOpenVPNPeers(box, peers.dataset.ovpnPeers);
      } catch (error) {
        box.querySelector("#ovpn-message").textContent = error.message;
      } finally {
        button.disabled = false;
      }
    };
  } catch (error) {
    if (box.isConnected) box.textContent = error.message;
  }
}

async function loadOpenVPNPeers(box, eid) {
  const rows = await api(`/openvpn/endpoints/${eid}/peers`);
  const section = box.querySelector(`[data-ovpn-list="${CSS.escape(eid)}"]`);
  section.hidden = false;
  section.innerHTML = `<h3>دستگاه‌های OpenVPN</h3><form class="form-grid ovpn-peer-create"><label>جستجوی حساب<input name="search" type="search"></label><label>حساب<select name="user" required></select></label><label>دستگاه<select name="device_id" required></select></label><button type="submit">ساخت peer و IP مستقل</button></form><p>فایل ovpn شامل کلید خصوصی است؛ آن را فقط به صاحب همان دستگاه بدهید. تعویض گواهی، کانفیگ قبلی را باطل می‌کند.</p><div class="table-scroll"><table><thead><tr><th>دستگاه</th><th>IP</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>${rows.map((p) => `<tr><td class="mono">${esc(p.device_id.slice(0, 8))}</td><td class="mono">${esc(p.address)}</td><td>${p.enabled ? "فعال" : "غیرفعال"}</td><td><a href="/api/openvpn/peers/${esc(p.id)}/profile" download>دریافت ovpn</a> <button type="button" data-ovpn-peer="${esc(p.id)}" data-enabled="${p.enabled ? "0" : "1"}">${p.enabled ? "لغو دسترسی" : "فعال‌کردن"}</button> <button type="button" data-ovpn-rotate="${esc(p.id)}">تعویض گواهی</button></td></tr>`).join("")}</tbody></table></div><p class="ovpn-peer-message" role="status"></p>`;
  const form = section.querySelector("form"),
    message = section.querySelector(".ovpn-peer-message");
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
      await api(`/openvpn/endpoints/${eid}/peers`, {
        method: "POST",
        body: JSON.stringify({ device_id: form.elements.device_id.value }),
      });
      await loadOpenVPNPeers(box, eid);
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
  section.onclick = async (event) => {
    const revoke = event.target.closest("[data-ovpn-peer]"),
      rotate = event.target.closest("[data-ovpn-rotate]");
    const button = revoke || rotate;
    if (!button) return;
    if (
      rotate &&
      !confirm("گواهی قبلی باطل می‌شود و ممکن است کلاینت‌های نود نیاز به اتصال دوباره داشته باشند؛ تعویض گواهی را تأیید می‌کنید؟")
    )
      return;
    button.disabled = true;
    try {
      if (revoke)
        await api(`/openvpn/peers/${revoke.dataset.ovpnPeer}`, {
          method: "PUT",
          body: JSON.stringify({ enabled: revoke.dataset.enabled === "1" }),
        });
      else
        await api(`/openvpn/peers/${rotate.dataset.ovpnRotate}/rotate`, {
          method: "POST",
        });
      await loadOpenVPNPeers(box, eid);
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
}
