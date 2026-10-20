# ماتریس پروتکل، موتور و خروجی

> تصمیم دامنهٔ انتشار، ۲۰۲۶-۱۰-۲۰: به انتخاب کاربر، v1 به امکانات فعلی محدود است. موارد پیاده‌نشدهٔ این نقشه به نسخه‌های بعد منتقل شده‌اند. [دامنه و شرایط انتشار v1](V1.fa.md) و [وضعیت پیاده‌سازی](IMPLEMENTATION-STATUS.fa.md) مرجع وضعیت فعلی‌اند؛ برچسب‌های «هدف ۱.۰» در جداول اولیه، هدف تاریخی نقشه‌اند. آزمون VPS/دامنه/ISP بدون شاهد اجراشده همچنان تأییدشده نیست.

به‌روزرسانی: ۲۰۲۶-۱۰-۱۹. وضعیت «موجود» مربوط به Donino 0.2 است؛ ردیف‌های هدف، وعدهٔ پشتیبانی فعلی نیستند. تعریف آزمون مشترک در [PROTO-01](ACCEPTANCE-TESTS.fa.md) است. هیچ ترکیب دلخواهی از نام‌های این جدول معتبر فرض نمی‌شود.

## قرارداد ثبت قابلیت

هر رکورد باید این فیلدها را داشته باشد: `engine/version/asset_sha256/os/arch`، `protocol/role`، `transport/security`، `client/version`، روش احراز هویت، دانه‌بندی حسابداری، روش قطع نشست، خروجی‌ها، محدودیت و وضعیت مدرک پذیرش. نقش یکی از `server`، `client`، `endpoint` یا `integration` است؛ پشتیبانی outbound به‌تنهایی به معنی امکان ساخت سرور نیست.

وضعیت‌ها: **موجودِ آزموده‌شده در محدوده مشخص**، **هدف ۱.۰**، **مشروط/آزمایشی**، **بعد از ۱.۰**. نسخهٔ موتور جدید تا زمان انتخاب و ثبت checksum «انتخاب‌نشده» است؛ جای خالی نسخه، مانع اعلام آن ترکیب به‌عنوان پایدار است. مبنای فعلی Xray `v26.3.27` روی Linux amd64، SHA-256 فایل ZIP: `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`؛ مرجع اجرایی [fetch_xray.py](../scripts/fetch_xray.py).

## خانواده‌ها

در ستون حسابداری/قطع، روش مورد نیازِ طراحی آمده است. برای تمام ردیف‌های هدف باید امکان واقعی موتور با نسخهٔ منتخب اثبات شود؛ اگر نشود، قابلیت با برچسب محدود باقی می‌ماند یا از انتشار خارج می‌شود.

| شناسه | پروتکل/نقش | موتور یا مسیر هدف | وضعیت و فاز | حسابداری و قطع دسترسی | خروجی هدف |
|---|---|---|---|---|---|
| P-01 | VLESS، server | Xray | موجود: REALITY/TCP/Vision؛ WS و gRPC با TLS در فاز ۸ آزموده شد | credential؛ فعلاً restart نود برای ابطال نشست | URI، base64، Mihomo؛ JSON در ۱۳ |
| P-02 | VMess، server | Xray | موجود: WS/TLS؛ gRPC با TLS در فاز ۸ آزموده شد | credential؛ فعلاً restart | URI، base64، Mihomo؛ JSON در ۱۳ |
| P-03 | Trojan، server | Xray | موجود: TCP/TLS؛ WS با TLS در فاز ۸ آزموده شد | credential؛ فعلاً restart | URI، base64، Mihomo؛ JSON در ۱۳ |
| P-04 | Shadowsocks / 2022، server | Xray 26.3.27 | پیش‌نمایش alpha.16؛ سه روش AEAD قدیمی و2022 AES128/256 | رمز مستقل دستگاه، مصرف دوره‌ای، قطع نشست با restart؛ TCP/UDP واقعی وMihomo TCP آزموده شد | SIP002 URI وMihomo؛ [محدوده](SHADOWSOCKS.fa.md) |
| P-05 | Hysteria2، server | sing-box یا موتور مستقل | هدف ۹ | شناسه احراز هویت؛ مصرف و خاتمه نشست شرط پذیرش | URI، sing-box، Mihomo سازگار |
| P-06 | TUIC v5، server | sing-box یا موتور مستقل | هدف ۹ | هویت کاربر؛ مصرف/انقضا/نشست QUIC | URI و JSON/YAML سازگار |
| P-07 | AnyTLS، server | sing-box یا موتور مستقل | هدف ۹ | کاربر/نشست؛ بررسی API موتور منتخب | خروجی کلاینت دارای پشتیبانی |
| P-08 | Naive / ShadowTLS، server | موتور منتخب پس از تحقیق | مشروط ۹ | هویت outer/inner و مصرف نباید دوبار حساب شود؛ بدون حسابداری مستقل، «کامل» نیست | فقط قالب تأییدشده همان ترکیب |
| P-09 | HTTP CONNECT / HTTPS / SOCKS / Mixed، server | آداپتور Xray/sing-box | هدف ۸ | کاربر احرازشده؛ UDP وابسته به نوع؛ دسترسی بدون auth پیش‌فرض ممنوع | endpoint و JSON متناسب با کلاینت |
| P-10 | WireGuard، endpoint | ابزار رسمی Linux/WireGuard | پیش‌نمایش alpha.14؛ پذیرش kernel/userspace در CI | peer و شمارنده kernel؛ حذف peer و route؛ پس از reboot/reset نسل جدید | `.conf` و QR محلی |
| P-11 | AmneziaWG، endpoint | موتور سازگار Amnezia | هدف ۶ | peer؛ پارامترهای نسخه و کلاینت دقیقاً همسان | `.conf` سازگار همان نسخه و QR |
| P-12 | OpenVPN UDP/TCP، server | OpenVPN Community 2.6 | پیش‌نمایش alpha.15؛ کلاینت واقعی UDP/TCP | گواهی هر دستگاه، status/management؛ revoke + kill نشست فعال | `.ovpn` و bundle کلاینت |
| P-13 | IKEv2/IPsec، server | strongSwan | هدف ۱۱ | SA/شناسه دستگاه؛ VICI و terminate با بررسی احراز هویت | پروفایل OS و گواهی لازم |
| P-14 | OpenConnect، server | ocserv | هدف ۱۱ | کاربر/نشست؛ status و disconnect | اطلاعات اتصال/پروفایل کلاینت |
| P-15 | SSTP/L2TP-IPsec/SSL VPN، server | SoftEther یا موتور مناسب | مشروط ۱۱ | session؛ سازگاری و محدودیت هر روش جدا | پروفایل همان سیستم‌عامل |
| P-16 | MTProto، server | آداپتور مستقل | مشروط ۹ | secret/هویت و شمارنده قابل تفکیک باید اثبات شود | لینک Telegram سازگار |
| P-17 | DNS UDP/TCP، server | resolver + dnsdist/ACL | هدف ۴ | درخواست/بایت DNS، هویت IP یا شبکه؛ قطع ACL | IP و تنظیم DNS |
| P-18 | DoH/DoT/DoQ، server | dnsdist + resolver | هدف ۴ | احراز هویت براساس قابلیت کلاینت/سرور؛ بدون فرض header HTTP برای DoT/DoQ | URL یا hostname/port |
| P-19 | Smart DNS، integration | Donino resolver/relay/exit | هدف ۵ | IP lease روی relay؛ مرز بایت client-facing | IP، سیاست سرویس و راهنمای دستگاه |
| P-20 | TCP/UDP forward، reverse، site-to-site | Donino adapter / donino-tunnel | هدف ۱۰ | آمار مسیر با مصرف کاربر مخلوط نشود؛ توقف مسیر | فایل/پروفایل آداپتور منتخب |
| P-21 | DoH3 / DNSCrypt، server | موتور دارای build feature لازم | DoH3 مشروط ۴؛ DNSCrypt بعد از ۱.۰ | auth و accounting مستقل؛ UDP/443 یا پورت اختصاصی | تنظیم کلاینت سازگار |
| P-22 | Headscale / NetBird، integration | API کنترل جداگانه | بعد از ۱.۰ | هویت peer و policy همان سرویس؛ قرارداد مالکیت مستقل | enrollment کلاینت همان محصول |

Hysteria نسل اول، Snell و هر پروتکل دیگری که در registry موتور دیده شود خودکار وارد دامنهٔ ۱.۰ نمی‌شود. اضافه‌شدن آن به دامنه نیازمند ردیف، مالک اجرا، نسخه، فاز و تست است. L2TP بدون IPsec و VPN بدون رمزگذاری به‌عنوان مسیر امن ارائه نمی‌شود. WireGuard و OpenVPN پروتکل DNS نیستند؛ DNS صرفاً می‌تواند بخشی از پروفایل آن‌ها باشد.

## انتقال، امنیت و ترکیب معتبر

| لایه | دامنه هدف | قاعده |
|---|---|---|
| Xray transport | TCP/RAW، WS، gRPC، HTTPUpgrade، XHTTP | در فاز ۸، برای هر پروتکل/موتور/کلاینت انتخاب نسخه لازم است |
| QUIC | Hysteria2/TUIC و انتقال‌های دارای پشتیبانی واقعی | با HTTP/3 هم‌پورت به‌صورت خودکار سازگار فرض نشود |
| mKCP و روش‌های قدیمی | فقط گزینهٔ سازگاری پس از ارزیابی | برچسب قدیمی/آزمایشی؛ پیش‌فرض نصب نیست |
| TLS و REALITY/Vision | طبق پشتیبانی ترکیب منتخب | REALITY گواهی عمومی دامنهٔ پنل نیست؛ Vision روی هر انتقالی معتبر نیست |
| TUN/TProxy | شیوهٔ ورود/هدایت ترافیک | پروتکل کاربری مستقل نیست؛ route، DNS، privilege و leak آزموده شوند |
| IPv4/IPv6 و MTU | در هر adapter جدا | نبود IPv6 با حذف خاموش AAAA پنهان نشود؛ حالت پشتیبانی صریح باشد |

اعتبارسنجی در backend انجام می‌شود؛ UI فقط گزینه‌های معتبر را نشان می‌دهد. تنظیم نامعتبر نباید به فایل نهایی یا موتور برسد. پنل پیش از اعمال، config-test، بررسی پورت، دسترسی cert و امکان rollback را اجرا می‌کند. downgrade یا حذف بی‌صدای فیلد امنیتی در export مجاز نیست.

## سازنده و تحویل کانفیگ

مسیرها: ویزارد ساده → الگوی نام‌دار → clone/ساخت گروهی → editor خبره با schema → API/CLI → import نسخه‌دار. تمام مسیرها باید یک اعتبارسنج و policy را مصرف کنند؛ editor خبره راه دورزدن مجوز یا اجرای فرمان نیست.

خروجی‌ها براساس capability: URI/base64، Xray JSON، sing-box JSON، Mihomo YAML/JSON، WireGuard conf، OpenVPN ovpn، پروفایل دستگاه/روتر. یک فایل واحد برای پروتکل‌های ناسازگار ادعا نمی‌شود. برای هر خروجی، نسخهٔ کلاینت، import موفق و اتصال ثبت می‌شود؛ قالبی که پروتکل را پشتیبانی نمی‌کند با علت قابل فهم رد می‌شود.

## منابع اصلی

- [Xray configuration](https://xtls.github.io/en/config/) و [inbound](https://xtls.github.io/en/config/inbound.html)
- [sing-box inbound](https://sing-box.sagernet.org/configuration/inbound/)
- [WireGuard quick start](https://www.wireguard.com/quickstart/) و [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go)
- [OpenVPN management interface](https://openvpn.net/community-docs/management-interface.html)
- [strongSwan swanctl](https://docs.strongswan.org/docs/latest/swanctl/swanctl.html)، [ocserv](https://ocserv.gitlab.io/www/features.html)، [SoftEther](https://www.softether.org/features)
- [dnsdist DoH](https://www.dnsdist.org/guides/dns-over-https.html) و [DoQ](https://www.dnsdist.org/guides/dns-over-quic.html)

این پیوندهای مستندات پویا هستند. پیش از پذیرش هر adapter، نسخهٔ مستند و موتور در مدرک آزمون همان adapter ثبت می‌شود؛ مشاهدهٔ امروز به معنی سازگاری نسخهٔ آینده نیست.
