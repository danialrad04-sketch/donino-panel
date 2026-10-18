# کار مستقل برای همکاری Claude

این متن را می‌توان مستقیم به Claude داد. هدف، پیش‌برد موازی فاز ۸ است؛ مسیر DNS، انتقال doctor-dns و relay در شاخهٔ کاری Codex ادامه دارد.

> مخزن `danialrad04-sketch/donino-panel` را از آخرین `main` بگیر؛ ابتدا `docs/IMPLEMENTATION-STATUS.fa.md`، `docs/MASTER-PLAN.fa.md`، `docs/PROTOCOL-MATRIX.fa.md` و آزمون Xray موجود را بخوان. شاخهٔ مستقل `claude/xray-transports-v1` بساز و transportهای Xray را با حفظ سازگاری فعلی تکمیل کن.
>
> خروجی این کار چهار مسیر واقعی است: **VLESS WS+TLS، VLESS gRPC+TLS، VMess gRPC+TLS و Trojan WS+TLS**. VLESS TCP REALITY Vision، VMess WS TLS و Trojan TCP TLS موجود باید همچنان کار کنند. `flow` مربوط به Vision را روی WS/gRPC اعمال نکن. از adapter و ساختار `inbounds.settings` فعلی استفاده کن؛ این کار نباید migration یا جدول جدید لازم داشته باشد.
>
> برای هر مسیر، validation ورودی، تنظیم server/client، subscription URI و خروجی Mihomo، فیلدهای لازم در فرم اتصال و توضیح پورت/دامنه/گواهی را کامل کن. از ساخت config ظاهری بدون آزمون انتقال پرهیز کن. پیش از ادعای سازگاری با یک کلاینت، همان کلاینت یا قالب مورد ادعا را بررسی کن.
>
> آزمون پذیرش باید با Xray واقعیِ پین‌شده اجرا شود: انتقال رمزگذاری‌شدهٔ هر مسیر، جمع مصرف به device ID درست، قطع دسترسی کاربر غیرفعال/منقضی، تغییر دوره و عدم خرابی مسیرهای قدیمی. TLS را با CA آزمایشیِ صریح و hostname درست بررسی کن؛ `allowInsecure` یا خاموش‌کردن بررسی گواهی راه‌حل نیست. در صورت نیاز به restart برای تغییر transport، آن رفتار را دقیق مستند کن.
>
> محدودهٔ اصلی فایل‌ها `app/core.py`، `app/engines.py`، آزمون تازهٔ `tests/test_xray_transports.py` و بخش فرم اتصال در `app/static/app.js` است. در `app/main.py` فقط مدل/validation مرتبط با inbound را به‌صورت محدود تغییر بده. فایل را از اول بازنویسی نکن. اعتبارنامه، device ID، شمارهٔ دوره، امضای تنظیمات و حسابداری موجود را حفظ کن.
>
> به schema و migration، `app/db.py`، بودجه و هویت عامل، `agent/main.py`، DNS، `app/doctor_*`، `app/gaming_catalog.py` و installer دست نزن؛ این بخش‌ها هم‌زمان در کار دیگری هستند. شاخهٔ قدیمی `development/1.0` و PR بستهٔ ۱ مبنای کد یا DB نیستند. نسخه، tag یا انتشار پایدار تازه نساز.
>
> پیش از تحویل `python scripts/release_manifest.py` را اجرا و تغییرات را با آزمون، راه‌اندازی مرورگر و `git diff --check` بررسی کن. یک PR قابل بازبینی به `main` بساز که مشکل/قابلیت، تست‌های اجراشده و محدودیت‌های واقعی را توضیح دهد. روی `main` مستقیم push نکن و PR را merge نکن. اگر جایی به تغییر schema یا بخش تحت کار Codex نیاز شد، آن وابستگی را در PR ثبت کن و آن تغییر را جدا نگه دار.

تحویل مطلوب: یک PR محدود و آزموده‌شده برای transportها، بدون تغییر قرارداد DNS یا سهمیه و بدون ادعای تکمیل فازهای دیگر. Codex پس از بازبینی، آن را با ادامهٔ DNS/relay ادغام می‌کند. برای هماهنگی، عنوان/شمارهٔ PR و نتیجهٔ CI کافی است؛ کلید خصوصی یا credential لازم نیست در گفتگو فرستاده شود.
