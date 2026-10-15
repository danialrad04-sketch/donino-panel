# بررسی پنل‌ها و مسیر طراحی Donino

تاریخ بررسی: ۲۰۲۶-۱۰-۱۵. این یک نمونه‌برداری از پروژه‌های شاخص است، نه ادعای شناسایی تمام پنل‌های اینترنت. ۱۴ مخزن از طریق GitHub API و README رسمی بررسی شدند؛ دو نشانی دیگر پاسخ ۴۰۴ دادند. SHA، شاخه و متادیتای هر درخواست در [reference-snapshots.json](reference-snapshots.json) ثبت شده است. نتایج جست‌وجوی وب با منابع اصلی تطبیق داده شدند.

## پژوهش تکمیلی برنامهٔ ۱.۰

نسخه‌های قفل‌شده، فایل‌های خوانده‌شده و حدود بررسی در [planning-reference-snapshots.json](planning-reference-snapshots.json) ثبت شده‌اند. در این مرحله هیچ نصب‌کنندهٔ مرجع اجرا و هیچ کد مرجع وارد محصول نشد.

| منبع | یافتهٔ مرتبط | اثر در طراحی |
|---|---|---|
| [doctor-dns](https://github.com/danialrad04-sketch/doctor-dns)؛ fork از mehdi047/doctor-dns | relay/exit، ACL و شمارنده IP، quota/expiry، SQLite و قالب سرویس؛ دانلود Xbox در README حل‌نشده است | [طراحی DNS](DNS-GAMING-DESIGN.fa.md) و migration مستقل؛ پیش‌فرض ACL بسته؛ متن MIT و copyright اصلی هنگام بازاستفاده حفظ شود |
| [PasarGuard Scripts](https://github.com/PasarGuard/scripts) | جریان ACME، نصب cert و hook تمدید؛ بررسی انتخاب‌شده از pasarguard.sh | [مشخصات installer](INSTALLER-SPEC.fa.md) با تکرارپذیری، حفظ cert معتبر و حل تعارض پورت؛ مجوز کپی این اسکریپت تأیید نشده است |
| [donino-tunnel](https://github.com/danialrad04-sketch/donino-tunnel) | فقط README دربارهٔ Network Studio و backend Xray/adapterها خوانده شد | کنترل کاربر/موتور در Donino Panel و نقش carrier در پروژه تونل؛ ادعای تست‌های آن مستقلاً تأیید نشده است |
| مستندات Xray، sing-box، WireGuard، OpenVPN، Unbound/dnsdist و Let’s Encrypt | نقش server/endpoint، مدیریت نشست، DNS رمزگذاری‌شده و challenge | [ماتریس پروتکل](PROTOCOL-MATRIX.fa.md) و معیارهای آزمون؛ نسخه موتور/کلاینت پیش از اعلام پشتیبانی باید قفل شود |

[برنامهٔ جامع](MASTER-PLAN.fa.md) این پژوهش را به دامنهٔ اجرایی تبدیل می‌کند؛ این بخش ممیزی امنیت یا اثبات کارکرد production پروژه‌های مرجع نیست.

## خانوادهٔ Xray و sing-box

| پروژه | قابلیت‌های شاخصِ بررسی‌شده | گزارش مجوز GitHub | تصمیم برای Donino |
|---|---|---|---|
| [3x-ui](https://github.com/MHSanaei/3x-ui) | مدیریت inbound و client، چند پروتکل، سهمیه، REALITY، نود، API و مسیریابی | GPL-3.0 | مدیریت کاربر و اتصال و REALITY مستقل پیاده شد؛ پروتکل‌ها و مسیریابی گسترده در نقشهٔ توسعه |
| [PasarGuard Panel](https://github.com/PasarGuard/panel) | چند نود، RBAC، سهمیه و انقضا، چند اتصال، اشتراک، HWID | AGPL-3.0، متن فایل نیازمند بررسی مستقل | الگوی کنترل مرکزی و نود با عامل اختصاصی؛ RBAC پایه و سهمیه موجود؛ HWID موجود نیست |
| [PasarGuard Node](https://github.com/PasarGuard/node) | اجرای هسته روی سرورهای جدا از پنل و مدیریت ارتباط نود | GPL-3.0 | عامل Donino مستقل است و سازگاری با پروتکل این نود را ادعا نمی‌کند |
| [Marzban](https://github.com/Gozargah/Marzban) | REST API، چند نود، چرخهٔ حجم، اشتراک چند کلاینت، CLI | AGPL-3.0 | API، سهمیه، CLI و اشتراک پایه مستقل؛ تمدید دوره‌ای و مهاجرت در آینده |
| [Hiddify Manager](https://github.com/hiddify/Hiddify-Manager) | مدیریت دامنه، پروتکل‌های متنوع، نصب و تجربهٔ کاربری کلاینت | GPL-3.0 | تجربهٔ یک اشتراک برای چند اتصال؛ مدیریت دامنه و sing-box هنوز وجود ندارد |
| [Remnawave](https://github.com/remnawave/panel) | پنل مدیریت proxy مبتنی بر Xray، اکوسیستم اشتراک جداگانه | AGPL-3.0 در API؛ LICENSE در مسیر درخواست‌شده نبود | تفکیک کنترل مرکزی از نود؛ هیچ ادعای سازگاری API یا مهاجرت نداریم |
| [s-ui](https://github.com/alireza0/s-ui) | مدیریت sing-box، inbound/outbound، پروتکل‌های QUIC و اشتراک | GPL-3.0 | برای adapter جدا در آینده؛ sing-box در Donino اجرا نمی‌شود |
| [x-ui / vaxilu](https://github.com/vaxilu/x-ui) | مدیریت چند کاربر و چند پروتکل Xray | GPL-3.0 | مرجع تاریخی این خانواده؛ کد وارد نشده |
| [x-ui / alireza0](https://github.com/alireza0/x-ui) | routing، REALITY، محدودیت IP، ورودی/خروجی، گواهی و آمار | GPL-3.0 | REALITY و آمار پایه موجود؛ محدودیت IP و گواهی خودکار در آینده |

## خانواده‌های متفاوت VPN و دسترسی شبکه

| پروژه | حوزه و درس طراحی | وضعیت مجوز در بررسی |
|---|---|---|
| [wg-easy](https://github.com/wg-easy/wg-easy) | مدیریت WireGuard، وضعیت peer، QR، انقضا و ورود دومرحله‌ای؛ نیازمند adapter و مدل peer متفاوت | AGPL-3.0 |
| [Pritunl](https://github.com/pritunl/pritunl) | VPN سازمانی توزیع‌شده مبتنی بر OpenVPN؛ معماری متفاوت از inboundهای Xray | API برابر NOASSERTION؛ بازاستفاده تأیید نشده |
| [NetBird](https://github.com/netbirdio/netbird) | دسترسی شبکه مبتنی بر هویت و WireGuard، کنترل مرکزی و ارتباط peer-to-peer | README: BSD-3-Clause به‌جز management، signal و relay با AGPLv3؛ مجوز ترکیبی |
| [Headscale](https://github.com/juanfont/headscale) | کنترل‌پلین خودمیزبان سازگار با Tailscale؛ سرویس کنترل است و به‌خودی‌خود پنل هم‌ردهٔ Xray نیست | BSD-3-Clause |
| [Outline Server](https://github.com/OutlineFoundation/outline-server) | Shadowsocks و API مدیریت کلید؛ Outline Manager رابط جداگانه دارد | Apache-2.0؛ نشانی Jigsaw-Code به OutlineFoundation تغییر مسیر داد |

`firezone/firezone` و `ppanel-dev/ppanel` در زمان درخواست پاسخ ۴۰۴ دادند؛ بررسی‌شده محسوب نمی‌شوند. نبود یک قابلیت در README را به معنای نبود آن در محصول فرض نکردیم. این گزارش معیار طراحی است، نه رتبه‌بندی یا ممیزی امنیت پروژه‌ها.

## چرا فایل‌ها را در هم نریختیم؟

این پروژه‌ها زبان، پایگاه داده، مدل کاربر، روش شمارش مصرف و روش کنترل هستهٔ متفاوت دارند. ترکیب فایل‌های Go، Python، TypeScript، Xray و sing-box یک محصول یکپارچه ایجاد نمی‌کند. Donino یک مدل کاربر، یک API و یک قرارداد نود دارد؛ پشتیبانی از هسته‌های دیگر باید با adapter و آزمون مستقل اضافه شود.

مجوز گزارش‌شدهٔ API جای بررسی فایل و تک‌تک وابستگی‌ها را نمی‌گیرد. برای مثال فایل LICENSE مشاهده‌شدهٔ PasarGuard Panel دارای سربرگ تغییر‌یافته بود؛ بدون بررسی بیشتر نباید آن را همسان با متن رسمی AGPL دانست. در این نسخه هیچ فایل یا کد آن پنل‌ها وارد Donino نشده است. نام‌ها و نشان‌های آن‌ها هم برند Donino نیستند.

## مرز استقلال

Donino پنل کنترل و عامل خود را دارد؛ رمزنگاری و پروتکل VPN را از نو اختراع نمی‌کند و اجرای واقعی پروتکل‌ها را به [Xray-core](https://github.com/XTLS/Xray-core) می‌سپارد. این مرز، توسعه و آزمون پروتکل را از امکانات مدیریتی جدا می‌کند. نسخهٔ Xray آزموده‌شده: `v26.3.27` با checksum ثابت در اسکریپت دریافت.
