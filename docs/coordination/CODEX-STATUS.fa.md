# نقطهٔ تحویل Codex — اتصال تانل و همکاری

مبنای این بسته main پس از PR ۱۵، schema 10 است؛ نسخهٔ کار `1.0.0a8` همچنان پیش‌نمایش است. branch این تغییر `development/claude-tunnel-bridge` است. هنگام شروع PR باز نبود؛ در ادامه PR ۱۳ کلاد با چهار transport و CI موفق رسید، بازبینی و ادغام شد. پذیرش تکمیلی در PR ۱۵ تحویل و بازبینی شد؛ مشکلات checkpoint/manifest و fixture اصلاح شدند. مأموریت جدید Mihomo در assignments ثبت شده است.

انجام‌شده: راهنمای ریشه، انتساب transportهای Xray به کلاد، checkpoint قابل ادامه و validator، بررسی pin/license دو مخزن Donino Tunnel و Hashem، bridge محلی opt-in مالک، رابط فارسی و قرارداد واقعی renderer/Unix worker. شرح شواهد در [VALIDATION](../VALIDATION.md) و حدود دقیق در [راهنمای تانل](../TUNNEL-BRIDGE.fa.md) است. وضعیت GitHub checks و PR همان commit را پیش از merge بررسی کن؛ نوشتهٔ این فایل جای CI نیست.

اقدام بعدی Codex: remote و PRهای کلاد را fetch کن؛ اگر `claude/mihomo-tls-acceptance-v1` تحویل شده، انتقال واقعی از export پنل با Mihomo پین‌شده و TLS معتبر را بررسی کن. سپس integration تانل را با binding پایدار inbound/node به plan، پذیرش واقعی انتقال VPN بین دو node آزمایشی و انتشار endpoint فقط پس از تأیید مسیر ادامه بده. هنگام تغییر قرارداد transport با کلاد هماهنگ شو؛ کد worker و installer تازهٔ موازی از صفر نساز.

باقی‌ماندهٔ مهم: نصب اولیهٔ دو نقش از داخل پنل، bootstrap عامل دوردست پنل، جداسازی مجوز حداقلی worker، چند جفت/سرور، endpoint/اشتراک، آزمون شکست/restart دو node، حامل‌های بیشتر و relay واقعی گیمینگ. هیچ VPS یا دامنهٔ کاربر در اختیار نیست. حساب‌های doctor-dns هنوز staged/غیرفعال‌اند؛ ساخت تانل آنها را فعال نمی‌کند. WireGuard/OpenVPN و بقیهٔ ماتریس هنوز مأموریت اجرا و پذیرش جدا می‌خواهند.

کلاد پس از PR پذیرش تکمیلی در `waiting_for_review` می‌ماند. تعیین مأموریت بعدی در `assignments.json` فقط پس از بازبینی یا دستور تازهٔ کاربر انجام شود؛ «ادامه» نباید موجب انتخاب خودسرانهٔ فاز تازه یا merge/tag توسط کلاد شود.

## ادامه به دستور تازهٔ کاربر

Codex مأموریت Mihomo را از PR ۱۷ تحویل گرفت؛ عیب SNI خروجی Trojan را اصلاح کرد و هر ۹ آزمون با شش مسیر واقعی موفق شد. کلاد در assignments معلق است و checkpoint تحویل او بدون تغییر در history نگهداری شد. گام بعد binding پایدار تانل به inboundها، revision guard و وضعیت قابل پیگیری است؛ مأموریت تازه برای کلاد تعیین نشود.

## alpha 9 — نقشهٔ متصل

Schema 11، binding پایدار node/inbound، ساخت مقصد از DB، محافظت revision/انقضا/peer، claim شروع، بازیابی پاسخ گم‌شده و مرور مجدد UI پیاده و محلی آزموده شدند. بخش نصب واقعی دو node، آزمون برنامه و انتشار endpoint هنوز باز است؛ `application_verified` و `endpoint_published` در این مرحله false هستند. هیچ مأموریت تازه‌ای به کلاد داده نشود.


## ادامه پس از alpha 9

PR ۱۸ و alpha.9 ادغام و منتشر شدند. مرحلهٔ قبل در `development/tunnel-verification` و PR ۱۹ تکمیل شد: آزمون واقعی شش مسیر TLS روی حامل‌های FRP، رسید محافظت‌شده، انتشار اضافیِ موقت در اشتراک، ابطال هنگام تغییر/restore و schema 12. مرجع نتیجهٔ نهایی بررسی‌ها و انتشار، همان PR و checkpoint است. نصب اولیهٔ نقش‌ها، مانیتور/تمدید امن lease و پذیرش دو VPS واقعی هنوز کار بعدند؛ کلاد فعلاً متوقف می‌ماند.

به‌روزرسانی alpha 11: PR ۱۹ ادغام و alpha.10 منتشر شد. کار فعال در `development/smart-dns-routing`، افزودن Smart DNS واقعی HTTPS و مدیریت خروجی/حجم است. PR ۲۰ برای این مرحله ثبت شده است؛ مرجع نتیجهٔ نهایی، checkpoint و همان PR است؛ کلاد متوقف می‌ماند.
