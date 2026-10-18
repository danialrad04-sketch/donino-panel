# مأموریت فعال کلاد: کلاینت واقعی Mihomo برای شش مسیر TLS

شناسه `mihomo-tls-acceptance-v1`؛ شاخه `claude/mihomo-tls-acceptance-v1` از آخرین main شامل PR ۱۵ و همین انتساب. ابتدا CLAUDE.md، assignments و checkpoint و بازبینی `reviews/xray-acceptance-v1.fa.md` را بخوان. مأموریت Xray قبلی تمام شده؛ آن را دوباره پیاده نکن. این مأموریت را پس از انتشار انتساب در main شروع کن.

هدف: خروجی واقعی subscription نوع Mihomo/Clash همین پنل با **باینری واقعی Mihomo** باز و استفاده شود. شش مسیر: VLESS WS+TLS، VLESS gRPC+TLS، VMess WS+TLS، VMess gRPC+TLS، Trojan TCP+TLS و Trojan WS+TLS. REALITY، sing-box و v2rayN در این مأموریت نیستند؛ از این آزمون برای آنها ادعای پذیرش نکن.

نسخهٔ مرجع: `MetaCubeX/mihomo`، `v1.19.32`، artifact `mihomo-linux-amd64-compatible-v1.19.32.gz`. SHA256 فایل فشرده:

```text
ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20
```

Codex فایل release را دریافت و digest واقعی را با metadata GitHub تطبیق داده است. پیش از اجرا روی محیط خودت دوباره checksum را تطبیق بده؛ نام فایل/نسخه به‌تنهایی کافی نیست. منبع https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32 ؛ مجوز موتور مستقل است. باینری یا geodata یا برنامهٔ upstream را داخل مخزن commit نکن.

فایل‌های مجاز: `scripts/fetch_mihomo.py`، `tests/test_mihomo.py`، `.github/workflows/mihomo.yml` و `docs/MIHOMO-ACCEPTANCE.md`، به‌علاوه checkpoint خودت و manifest. اسکریپت دریافت مانند fetch_xray، دانلود و decompression محدود، checksum اجباری و خطای واضح برای platform ناسازگار داشته باشد. workflow جدا فقط آزمون مربوط را با actionهای پین‌شده اجرا کند؛ workflow اصلی را دست نزن. اگر export فعلی در core اشکال دارد، minimal reproducer و خروجی redacted را در PR ثبت کن تا Codex اصلاح را هماهنگ کند؛ محصول، DB، عامل، هویت، DNS، installer و bridge تانل را خودسرانه تغییر نده.

پذیرش:

۱. یک fixture مستقل با پنل، عامل و Xray واقعی و شش inbound بساز. پروفایل را از endpoint واقعی subscription بگیر. بدنهٔ proxyها را دستی بازنویسی یا با مقادیر درست جایگزین نکن؛ چنین کاری عیب export را پنهان می‌کند. فقط تنظیمات lab مثل پورت SOCKS محلی، انتخاب یک proxy، مقصد آزمایشی و trust صریح CA را اضافه کن و هر تفاوت با تولید را مستند کن.

۲. Mihomo واقعی باید config را بپذیرد و از هر شش مسیر، از SOCKS محلی تا HTTP/echo محلی انتقال انجام دهد. CA آزمایشی و hostname درست لازم است؛ `skip-cert-verify`، `allowInsecure` یا خاموش‌کردن verification ممنوع. CA غلط و hostname غلط باید واقعاً رد شوند؛ خطای TLS را از لاگ تأیید کن تا اختلال unrelated با رد گواهی اشتباه نشود. همهٔ فرآیندها و listenerها روی loopback آزمایش و پاک‌سازی شوند؛ پورت مدیریتی عمومی باز نکن.

۳. پس از انتقال، عامل نمونه بگیرد و بایت‌ها به device ID و دورهٔ درست برسند. غیرفعال‌کردن دستگاه، link/config ذخیره‌شدهٔ آن را پس از tick قطع کند و دستگاه دیگر همچنان کار کند. پروفایل قبلی و تازهٔ subscription را هم بررسی کن. تا پذیرش واقعی، صرف `config -t` یا مقایسهٔ فیلدها را «سازگاری Mihomo» ننام.

۴. دریافت خودکار geodata/provider یا تماس خارجی غیرضروری را در fixture غیرفعال کن؛ مسیر تست نباید به CDN، دامنه یا VPS بیرونی وابسته باشد. timeout واقعی، EOF/خواندن ناقص، cleanup و SQLite/PostgreSQL fixtureها را رعایت کن. از الگوی bounded read و isolation آزمون Xray استفاده کن؛ تست‌های موجود را ضعیف یا skip نکن.

پس از تست هدف و CI مستقل، شواهد دقیق نسخه/پروفایل/محدودیت و diff check و manifest را ثبت کن، PR به main بساز و checkpoint را با ابزار هماهنگی `waiting_for_review` کن. ابزار manifest را هم به‌روز می‌کند؛ هر دو فایل را commit/push کن. نسخه/tag/merge نساز. بعد منتظر Codex یا انتساب بعدی بمان؛ «ادامه» ابتدا feedback و main جدید را بررسی می‌کند.
