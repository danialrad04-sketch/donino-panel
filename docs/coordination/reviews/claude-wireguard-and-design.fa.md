# بازبینی ادامهٔ کلاد — ۲۰۲۶-۱۰-۱۹

دو تحویل تازه روی remote بررسی شد:

- `claude/panel-design-v2`، commit `61d446e`، ادغام‌شده در PR ۲۳/main
  `18bf301`: تغییر CSS/theme و changelog؛ رفتار API عوض نشده است. در شاخهٔ
  WireGuard ادغام شد. پذیرش مرورگر مالک، پرتال، حالت روشن/تیره، موبایل و
  جریان خصوصی WireGuard موفق شد؛ خطای JavaScript گزارش نشد.
- `claude/wireguard-continue`، commit `f543a52`: پنج خط برای انتخاب صریح
  `WG_QUICK_USERSPACE_IMPLEMENTATION` از متغیر backend آزمون. تغییر معتبر
  و با حفظ attribution ادغام شد. این تغییر به‌تنهایی پذیرش WireGuard را
  کامل نمی‌کرد: مشکل IPv6 ct-mark آزمایشگاه، DNS معکوس سرور مقصد fixture و
  قطع دستگاه دیگر هنگام بازسازی رابط همچنان وجود داشتند.

Codex وابستگی DNS معکوس fixture را حذف کرد، revoke درجا برای حذف peerها
اضافه کرد و چرخهٔ انتقال، شمارنده/دوره، قطع نشست باز، quota، expiry، restart
با reconnect صریح کلاینت و restore را با userspace و split-route واقعی
گذراند. کلید یا کانفیگ خصوصی در گزارش/تصویر ذخیره نشده است.

backend کرنل و full-tunnel، PostgreSQL و نصب OS باید روی head نهایی PR ۲۴
سبز باشند؛ نتیجهٔ یک head برای head دیگر معتبر نیست. OpenVPN، نصب خودکار
نود WireGuard، AWG و gateهای واقعی VPS/WAN/ACME و ظرفیت، کار باقی‌مانده‌اند.
این بازبینی اجازهٔ نامیدن نسخه به‌عنوان stable v1 نیست.
