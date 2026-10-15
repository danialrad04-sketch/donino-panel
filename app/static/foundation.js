"use strict";

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

async function foundationAction(action, id) {
  if (action === "devices") {
    const devices = await api(`/users/${id}/devices`);
    modal(
      "دستگاه‌های کاربر",
      `<p class="note">هر دستگاه کلید مستقل دارد. غیرفعال‌سازی پس از همگام‌سازی اعمال می‌شود و فعلاً هستهٔ Xray نود را دوباره راه‌اندازی می‌کند.</p><div class="table-scroll"><table><thead><tr><th>نام</th><th>وضعیت</th><th>انقضا</th><th>عملیات</th></tr></thead><tbody>${devices.map((d) => `<tr><td>${esc(d.name)}</td><td>${d.enabled ? "فعال" : "غیرفعال"}</td><td>${date(d.expires)}</td><td><button data-action="device-toggle" data-id="${id}:${d.id}">${d.enabled ? "غیرفعال" : "فعال"}</button><button data-action="device-rotate" data-id="${id}:${d.id}">تعویض کلید</button></td></tr>`).join("")}</tbody></table></div><div class="form-actions"><button class="primary" data-action="device-add" data-id="${id}">دستگاه جدید</button></div>`,
    );
    return;
  }
  if (action === "device-add") {
    return form(
      "دستگاه جدید",
      input("نام دستگاه", "name", { full: true, extra: 'maxlength="80"' }) +
        input("انقضای مستقل (اختیاری)", "expires", {
          type: "datetime-local",
          required: false,
          full: true,
        }),
      async (f) => {
        await api(`/users/${id}/devices`, {
          method: "POST",
          body: JSON.stringify({
            name: f.name,
            expires: f.expires
              ? Math.floor(new Date(f.expires).getTime() / 1000)
              : null,
          }),
        });
        await foundationAction("devices", id);
      },
    );
  }
  if (action === "device-toggle" || action === "device-rotate") {
    const [uid, did] = id.split(":");
    if (action === "device-rotate")
      return confirmAction(
        "تعویض کلید دستگاه",
        "تنظیمات دریافت‌شدهٔ این دستگاه باطل می‌شوند؛ پس از همگام‌سازی، اشتراک به‌روز را دریافت کنید.",
        () => api(`/users/${uid}/devices/${did}/rotate`, { method: "POST" }),
      );
    const device = (await api(`/users/${uid}/devices`)).find(
      (d) => d.id === did,
    );
    await api(`/users/${uid}/devices/${did}`, {
      method: "PUT",
      body: JSON.stringify({
        name: device.name,
        expires: device.expires,
        enabled: !device.enabled,
      }),
    });
    return foundationAction("devices", uid);
  }
  if (action === "assignments") {
    const current = await api(`/nodes/${id}/assignments`);
    return form(
      "تخصیص کاربران به نود",
      `<label class="full">حالت<select name="mode"><option value="all" ${current.mode === "all" ? "selected" : ""}>همهٔ کاربران</option><option value="selected" ${current.mode === "selected" ? "selected" : ""}>فقط کاربران انتخاب‌شده</option></select></label><label class="full">کاربران<select name="user_ids" multiple size="8">${data.users.map((u) => `<option value="${u.id}" ${current.user_ids.includes(u.id) ? "selected" : ""}>${esc(u.name)}</option>`).join("")}</select><small>انتخاب خالی در حالت انتخابی، دسترسی همهٔ کاربران به این نود را می‌بندد.</small></label>`,
      async (f) => {
        const user_ids = Array.from(
          document.querySelector("[name=user_ids]").selectedOptions,
          (o) => o.value,
        );
        await api(`/nodes/${id}/assignments`, {
          method: "PUT",
          body: JSON.stringify({ mode: f.mode, user_ids }),
        });
        await saved();
      },
    );
  }
  if (action === "security") {
    const [mfa, tokens] = await Promise.all([
      api("/security/mfa"),
      api("/security/tokens"),
    ]);
    modal(
      "امنیت حساب",
      `<h3>ورود دومرحله‌ای: ${mfa.enabled ? "فعال" : "غیرفعال"}</h3><button class="secondary" data-action="${mfa.enabled ? "mfa-disable" : "mfa-setup"}">${mfa.enabled ? "غیرفعال‌سازی با احراز هویت" : "راه‌اندازی دومرحله‌ای"}</button><h3>کلیدهای API</h3><p class="note">کلید جدید فقط یک بار نمایش داده می‌شود و تنها مجوزهای انتخابی را دارد.</p>${tokens.map((t) => `<div class="node-row"><div><b>${esc(t.name)}</b><small>${esc(JSON.parse(t.scopes).join(" · "))} — ${date(t.expires)}</small></div><button class="danger" data-action="token-delete" data-id="${t.id}">لغو</button></div>`).join("") || "<p>کلیدی ساخته نشده است.</p>"}<div class="form-actions"><button class="primary" data-action="token-add">کلید جدید</button></div>`,
    );
    return;
  }
  if (action === "mfa-setup") {
    return form(
      "راه‌اندازی ورود دومرحله‌ای",
      input("رمز فعلی", "password", {
        type: "password",
        full: true,
        extra: 'autocomplete="current-password"',
      }),
      async (f) => {
        const result = await api("/security/mfa/setup", {
          method: "POST",
          body: JSON.stringify(f),
        });
        form(
          "تأیید برنامهٔ احراز هویت",
          `<p class="note full">این کلید را در برنامهٔ احراز هویت خود اضافه کن و سپس کد شش‌رقمی را بنویس. کلید را محرمانه نگه دار.</p><label class="full">کلید راه‌اندازی<textarea readonly dir="ltr">${esc(result.secret)}</textarea></label>` +
            input("کد شش‌رقمی", "code", {
              full: true,
              extra:
                'inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" dir="ltr"',
            }),
          async (code) => {
            const enabled = await api("/security/mfa/enable", {
              method: "POST",
              body: JSON.stringify(code),
            });
            $("#modal").close();
            showLogin();
            modal(
              "کدهای بازیابی — یک بار نمایش",
              `<p class="note">این ده کد را در محل امن ذخیره کن. هر کد یک بار قابل استفاده است. جلسه‌های قبلی و کلیدهای API لغو شدند؛ با ورود دومرحله‌ای وارد شو.</p><textarea id="secret-output" dir="ltr" readonly rows="10">${enabled.recovery_codes.join("\n")}</textarea><div class="form-actions"><button class="primary" data-action="copy-secret">کپی کدها</button></div>`,
            );
          },
        );
      },
    );
  }
  if (action === "mfa-disable") {
    return form(
      "غیرفعال‌سازی ورود دومرحله‌ای",
      input("رمز فعلی", "password", { type: "password", full: true }) +
        input("کد برنامه", "code", {
          required: false,
          extra: 'inputmode="numeric" maxlength="6" dir="ltr"',
        }) +
        input("یا کد بازیابی", "recovery_code", {
          required: false,
          extra: 'maxlength="32" dir="ltr"',
        }),
      async (f) => {
        await api("/security/mfa/disable", {
          method: "POST",
          body: JSON.stringify(f),
        });
        $("#modal").close();
        showLogin();
      },
    );
  }
  if (action === "token-add") {
    const scopes = [
      "users:read",
      "nodes:read",
      "inbounds:read",
      ...(account.role !== "viewer" ? ["users:write"] : []),
      ...(owner() ? ["nodes:write", "inbounds:write", "audit:read"] : []),
    ];
    return form(
      "کلید API جدید",
      input("نام کلید", "name", { full: true, extra: 'maxlength="80"' }) +
        input("اعتبار (روز)", "days", {
          type: "number",
          value: 30,
          extra: 'min="1" max="366"',
        }) +
        `<label>مجوزها<select name="scopes" multiple size="5" required>${scopes.map((s) => `<option value="${s}">${s}</option>`).join("")}</select></label>`,
      async (f) => {
        const selected = Array.from(
          document.querySelector("[name=scopes]").selectedOptions,
          (o) => o.value,
        );
        const result = await api("/security/tokens", {
          method: "POST",
          body: JSON.stringify({
            name: f.name,
            scopes: selected,
            expires: Math.floor(Date.now() / 1000) + Number(f.days) * 86400,
          }),
        });
        modal(
          "کلید API — یک بار نمایش",
          `<p class="note">کلید را امن نگه دار؛ دسترسی آن ${esc(result.scopes.join(" · "))} است.</p><textarea id="secret-output" readonly dir="ltr">${esc(result.token)}</textarea><div class="form-actions"><button class="primary" data-action="copy-secret">کپی کلید</button></div>`,
        );
      },
    );
  }
  if (action === "token-delete") {
    await api("/security/tokens/" + id, { method: "DELETE" });
    return foundationAction("security");
  }
}
