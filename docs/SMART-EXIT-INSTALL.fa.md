# نصب مستقل خروجی Smart DNS — alpha 12

این نقش را **روی سرور خروجیِ تحت اختیار خود** اجرا کنید. کنترل‌پنل و gateway روی میزبان اصلی می‌مانند؛ سرور خروجی به دیتابیس یا کنترل‌پنل اضافی نیاز ندارد. نصب از راه SSH یا همگام‌سازی خودکار allowlist از پنل در این نسخه عرضه نشده است.

نصب از همان `install.sh` و سورس انتشارِ بررسی‌شده استفاده می‌کند. روی Debian 12 یا Ubuntu 24.04 با amd64 و systemd:

```sh
sudo ./install.sh --role smart-exit --domain exit.example.com \
  --exit-allow-domain service.example.com \
  --exit-allow-domain another-service.example.net \
  --exit-port 9445
```

دامنه‌های نمونه را جایگزین کنید. A/AAAA دامنهٔ خروجی باید با آدرس‌های همان سرور تطبیق داشته باشند. در صورت نیاز، هر IP عمومی مورد انتظار را با `--expected-ip IP` تکرار کنید. نصب پیش از تغییر سرویس، DNS دامنه، OS، پورت، inventory و manifest سورس را بررسی می‌کند. `plan` با همین گزینه‌ها گزارش می‌دهد. خروجی به‌طور پیش‌فرض روی IPv4 `0.0.0.0:9445` گوش می‌دهد؛ برای آدرس خاص `--exit-listen IP` بدهید. انتخاب `::` شنوندهٔ IPv6 است؛ وجود IPv4 روی همان socket تضمین نمی‌شود.

در حالت پیش‌فرض، NGINX برای HTTP-01 روی ۸۰ و Certbot با cert-name مستقل `donino-smart-exit` نصب می‌شوند. گواهی به نام دامنه و کلید متناظر بررسی و hook تمدید نصب می‌شود. پورت TLS خروجی مستقل است؛ لازم نیست ۴۴۳ پنل روی این سرور وجود داشته باشد. برای NGINX موجود، تنها با بررسی تعارض‌ها از `--allow-existing-nginx` استفاده کنید؛ فایل‌های سرویس‌های دیگر بازنویسی نمی‌شوند. نصب، firewall یا route سیستم/ارائه‌دهنده را تغییر نمی‌دهد؛ دسترسی ۸۰ برای ACME و پورت خروجی برای gateway را مطابق سیاست شبکهٔ خود فراهم کنید.

برای گواهی موجود، NGINX و Certbot جدید نصب نمی‌شوند:

```sh
sudo ./install.sh --role smart-exit --domain exit.example.com \
  --exit-allow-domain service.example.com --exit-port 9445 \
  --tls existing --cert-file /absolute/fullchain.pem --key-file /absolute/privkey.pem
```

گواهی باید معتبر، دارای SAN صحیح و زنجیرهٔ قابل اعتماد باشد. CA خصوصی فقط با `--ca-file /absolute/trusted-ca.pem` پذیرفته می‌شود؛ این فایل، trust store عمومی سیستم را تغییر نمی‌دهد. همان CA را به‌صورت آگاهانه روی کنترل‌پنل/gateway در `DONINO_SMART_DNS_CA` تنظیم کنید. برای گواهی existing، صدور/تمدید را ارائه‌دهندهٔ خودتان انجام می‌دهد؛ پس از تعویض، دستور نصب را با همان ورودی‌های صحیح یا مسیر نگهداری موردنظر اجرا کنید. mode ذخیره‌شدهٔ TLS در upgrade/repair حفظ می‌شود.

## اتصال به پنل

در پایان، مسیر `/etc/donino-smart-exit/gateway-access.json` اعلام می‌شود. فایل root-only و 0600 است؛ host/port، نام گواهی، username و password لازم برای فرم «نود خروجی جدید» را دارد. محتوای آن را در Git، screenshot، PR، log عمومی یا گفتگو نفرستید. نصب password را روی خط فرمان یا stdout نمایش نمی‌دهد؛ کاربر مجاز سرور آن را از فایل خصوصی می‌خواند.

در پنل، نود را ابتدا غیرفعال بسازید، «آزمون اتصال خروجی» را اجرا و پس از موفقیت، فعال کنید. این آزمون TLS و احراز هویت را بررسی می‌کند، نه موفقیت سرویس مقصد. سپس [قواعد route، مجوز حساب، حجم و اثبات IP](SMART-DNS.fa.md) را تنظیم کنید. دامنه‌هایی که از پنل route می‌شوند باید در allowlist خروجی هم باشند؛ دامنه و زیردامنه‌های suffix مجاز پوشش داده می‌شوند. کاتالوگ به‌تنهایی تنظیمات سرور خروجی را تغییر نمی‌دهد.

## نگهداری

```sh
sudo ./install.sh doctor --role smart-exit
sudo ./install.sh upgrade --role smart-exit
sudo ./install.sh repair --role smart-exit
sudo ./install.sh uninstall --role smart-exit
```

برای upgrade از سورس انتشارِ جدیدِ بررسی‌شده استفاده کنید. upgrade تنظیم دامنه، bind/port، allowlist، mode گواهی و credential را نگه می‌دارد؛ تغییر allowlist یا پورت را صریحاً با گزینه‌های مربوط بدهید. تغییر پورت در پنل هم نیازمند ذخیرهٔ غیرفعال، آزمون و فعال‌سازی دوباره است. تغییر دامنه به‌صورت ضمنی انجام نمی‌شود. راه‌اندازی مجدد سرویس هنگام upgrade، repair و تمدید گواهی می‌تواند اتصال‌های خروجی جاری را قطع کند؛ اتصال برقرارشده روی نود دیگر replay نمی‌شود.

`doctor` واقعاً TLS، hostname و SOCKS authentication را تا listener محلی می‌آزماید؛ در خروجی `application_verified=false` باقی می‌ماند. فایل managed تغییرکرده یا متعلق به نصب دیگری، پیش از توقف/حذف رد می‌شود. خطای NGINX، فایل و inventory قبلی را برمی‌گرداند. در تمدید، اگر readiness پس از نصب جفت تازه شکست بخورد، جفت قبلی هم در ذخیرهٔ root و هم در نمای سرویس دوباره نصب و سرویس restart می‌شود. این رفتار جای پایش مداوم یا HA را نمی‌گیرد.

uninstall فقط واحد و فایل‌های managed همین نقش را حذف می‌کند. credential، کلید/گواهی، داده‌ها، state، نسخه‌های نصب‌شده، کاربر سرویس و بسته‌ها حفظ می‌شوند؛ کنترل‌پنل دیگری حذف نمی‌شود. برای این نقش فرمان backup/restore کنترل‌پنل پشتیبانی نمی‌شود. از `/etc/donino-smart-exit` و state نصب، با روش خصوصی و رمزگذاری‌شدهٔ خود نسخهٔ پشتیبان مستقل نگه دارید. چرخش password از داخل پنل/نصب، در این برش خودکار نیست.

## جداسازی و حدود پذیرش

- کاربر: `donino-exit`؛ سرویس: `donino-smart-exit.service`.
- کد immutable: `/opt/donino-smart-exit/releases/` و symlink انتخاب‌شدهٔ `current`.
- اطلاعات خصوصی root: `/etc/donino-smart-exit/`؛ state: `/var/lib/donino-exit-installer/`.
- تنظیم و جفت TLS سرویس: `/var/lib/donino-smart-exit/` با مالکیت کاربر نقش و فایل‌های خصوصی. root از مسیر کاربر سرویس برای نوشتن فایل دنبال نمی‌کند؛ مواد لازم از pipe خصوصی به فرایند کم‌دسترسی تحویل می‌شوند.
- systemd با `NoNewPrivileges`، `ProtectSystem=strict` و `ProtectHome` اجرا می‌شود. برای پورت‌های ۱۰۲۴ به بالا capability شبکه داده نمی‌شود؛ برای پورت پایین فقط bind capability نیاز است.

خروجی همچنان فقط SOCKS احرازشده روی TLS برای domainهای مجاز و مقصد عمومیِ بررسی‌شده روی ۴۴۳ است؛ proxy عمومی، مقصد داخلی و ترافیک دلخواه UDP ایجاد نمی‌کند. نصب و مسیر تمدید با CA محلی روی OSهای ایزوله آزموده می‌شوند؛ صدور عمومی ACME، firewall ارائه‌دهنده، دسترسی از ایران، بازی‌ها و throughput روی VPS واقعی هنوز پذیرش می‌خواهند. نسخهٔ پایدار v1 و تکمیل WireGuard/OpenVPN با افزودن این نقش اعلام نمی‌شوند.
