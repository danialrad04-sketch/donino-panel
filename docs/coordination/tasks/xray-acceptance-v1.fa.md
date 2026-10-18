# مأموریت فعال کلاد: پذیرش تکمیلی چهار transport

شناسه `xray-acceptance-v1`؛ شاخه `claude/xray-acceptance-v1` از آخرین `origin/main` که PR ۱۳ و راهنمای ریشه را دارد. چهار مسیر مأموریت قبلی ادغام شده‌اند؛ آن پیاده‌سازی را دوباره نساز. ابتدا `CLAUDE.md` و `docs/coordination/reviews/xray-transports-v1.fa.md` و آزمون واقعی موجود را بخوان.

محدودهٔ اصلی: `tests/test_xray_transports.py` و یک سند شواهد `docs/XRAY-TRANSPORT-ACCEPTANCE.md`. checkpoint خودت مجاز است. کد محصول/عامل، schema، DNS، installer و bridge تانل را تغییر نده؛ اگر تست عیب واقعی پیدا کرد، minimal reproducer و وابستگی دقیق را ثبت کن تا Codex اصلاح را هماهنگ کند. تست را برای سبزشدن با mock، skip بی‌دلیل یا خاموش‌کردن TLS ضعیف نکن.

پذیرش با Xray واقعی پین‌شده برای VLESS WS+TLS، VLESS gRPC+TLS، VMess gRPC+TLS و Trojan WS+TLS:

۱. افزودن کاربر/دستگاه جدید در زمان اجرای عامل، اعمال `hot` بدون تغییر PID/epoch هسته، انتقال کلاینت تازه در هر چهار مسیر و سالم‌ماندن یک جریان قدیمیِ در حال انتقال. پس از نمونه‌برداری، بایت‌ها باید به device ID و دورهٔ درست برسند؛ ادعای live-add بدون شاهد واقعی کافی نیست.

۲. کاربر دارای تاریخ انقضای واقعی، انتقال موفق پیش از پایان، تغییر انقضا به گذشته از API و قطع پس از tick/اعمال. credential ذخیره‌شده نباید بتواند دوباره منتقل کند؛ لینک جدید اشتراک هم نباید آن کاربر را مجاز نگه دارد. رفتار restart و محدودهٔ قطع را ثبت کن. از mock کردن `eligible` یا ساعت سرویس به‌عنوان جایگزین انقضای واقعی استفاده نکن. آزمون‌های quota، device، user و period موجود را حفظ کن.

۳. کنترل منفی TLS برای هر چهار مسیر: CA نامعتبر و hostname ناسازگار واقعاً رد شوند، و CA معتبر با hostname درست موفق باشد. کلاینت‌ها را از خروجی واقعی subscription بساز. `allowInsecure` و خاموش‌کردن بررسی گواهی مجاز نیست. این آزمونِ Xray جای پذیرش مستقل Mihomo/v2rayN نیست.

آزمون‌ها باید timeout محدود، پاک‌سازی processها و دادهٔ موقتی داشته باشند؛ در PostgreSQL suite نیز دادهٔ آزمون‌های دیگر را خراب نکنند. suite مرتبط و manifest و `git diff --check` را بررسی کن، PR به main بساز و evidence/محدودیت‌ها را ثبت کن. نسخه/tag/merge نساز. پس از پایان، checkpoint `waiting_for_review` و توقف تا بازبینی یا انتساب تازه؛ با «ادامه» اول PR و assignments جدید را بررسی کن.
