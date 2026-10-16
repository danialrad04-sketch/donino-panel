# راه‌اندازی Donino روی سرور

این راهنما برای یک سرور Linux با systemd، Python 3.12+، دسترسی مدیریتی و دامنهٔ واقعی است. کنترل‌پنل و نود می‌توانند روی دو سرور جدا باشند. برای هر نود، یک Xray تحت مدیریت عامل Donino اجرا می‌شود؛ هم‌زمان همان هسته را با پنل یا سرویس دیگری مدیریت نکنید.

## پشتیبان، بررسی و بازیابی

پیش از هر تغییر بزرگ، پشتیبان بگیرید و سلامت پنل را بررسی کنید:

```bash
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db /opt/donino-panel/.venv/bin/python -m app.cli doctor
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db /opt/donino-panel/.venv/bin/python -m app.cli backup /var/backups/donino/donino-$(date -u +%Y%m%dT%H%M%SZ).db
```

فایل پشتیبان و فایل `manifest.json` کنار آن را خارج از سرور نگه دارید؛ هر دو حساس‌اند. برای بازیابی، سرویس پنل را متوقف کنید و سپس:

```bash
sudo systemctl stop donino-panel
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db /opt/donino-panel/.venv/bin/python -m app.cli restore /var/backups/donino/NAME.db --replace
sudo systemctl start donino-panel
```

بازیابی بدون manifest یا با checksum ناسازگار انجام نمی‌شود. نسخهٔ قبلی پایگاه داده قبل از جایگزینی در کنار همان مسیر با پسوند `.pre-restore-…db` ذخیره می‌شود.

## پنل مرکزی

ابتدا مخزن را با حساب دارای دسترسی دریافت کنید، سپس کد را در `/opt/donino-panel` قرار دهید. نمونهٔ زیر فرض می‌کند آن مسیر هنوز وجود ندارد:

```bash
git clone https://github.com/danialrad04-sketch/donino-panel.git
sudo cp -a donino-panel /opt/donino-panel
cd /opt/donino-panel
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
id -u donino >/dev/null 2>&1 || sudo useradd --system --home /var/lib/donino-panel --shell /usr/sbin/nologin donino
sudo install -d -m 700 /etc/donino
sudo install -d -m 700 -o donino -g donino /var/lib/donino-panel
sudo install -m 600 .env.example /etc/donino/panel.env
sudoedit /etc/donino/panel.env
```

در فایل تنظیمات، `DONINO_PUBLIC_URL` را با `https://` و دامنهٔ واقعی پنل تعیین کنید. `DONINO_SECURE_COOKIE=true` بماند. `DONINO_DB=/var/lib/donino-panel/donino.db` باشد. بدون این متغیر، مسیر پیش‌فرض `data/donino.db` است که نمونهٔ سرویس اجازهٔ نوشتن در آن را نمی‌دهد.

ساخت مالک و فعال کردن سرویس:

```bash
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db .venv/bin/python -m app.cli admin admin
sudo install -m 644 deploy/donino-panel.service /etc/systemd/system/donino-panel.service
sudo systemctl daemon-reload
sudo systemctl enable --now donino-panel
sudo systemctl status donino-panel
```

حساب پیش‌فرض وجود ندارد؛ رمز را تعاملی وارد کنید. برای نقش‌های دیگر:

```bash
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db .venv/bin/python -m app.cli admin support --role operator
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db .venv/bin/python -m app.cli admin observer --role viewer
```

اجرای دوبارهٔ دستور admin برای یک حساب، رمز و نقش آن را به‌روزرسانی و تمام نشست‌های آن حساب را باطل می‌کند. حداقل یک مالک باید حفظ شود.

## HTTPS

یک گواهی معتبر برای دامنهٔ پنل تهیه کنید. `deploy/nginx.conf.example` را با دامنه و مسیر گواهی واقعی تنظیم و در پیکربندی Nginx نصب کنید. نمونهٔ ارائه‌شده شامل صدور گواهی یا نصب خودکار Nginx نیست. پیش از reload، `sudo nginx -t` را اجرا کنید.

Uvicorn فقط روی `127.0.0.1:8000` گوش می‌دهد. Nginx باید روی همان سرور قرار بگیرد. برای پراکسی راه‌دور باید آدرس پراکسی معتمد و فایروال را جداگانه تنظیم کنید؛ `--forwarded-allow-ips=*` نگذارید. نمونهٔ Nginx لاگ درخواست را غیرفعال می‌کند تا مسیرهای محرمانهٔ اشتراک ثبت نشوند. لاگ سایر پراکسی‌ها یا CDN نیز نباید token اشتراک را ذخیره کند.

پس از راه‌اندازی، `https://YOUR_PANEL_DOMAIN/healthz` باید `status=ok` برگرداند. ورود به پنل باید روی همان دامنه انجام شود؛ تغییر Origin یا حذف هدر `X-Donino: 1` از درخواست‌های تغییردهنده موجب رد درخواست می‌شود.

## نصب نود روی هر سرور

روی سرور نود نیز کد و محیط Python را مطابق مرحلهٔ اول در `/opt/donino-panel` قرار دهید. حساب سرویس و مسیر state را بسازید:

```bash
cd /opt/donino-panel
id -u donino >/dev/null 2>&1 || sudo useradd --system --home /var/lib/donino-node --shell /usr/sbin/nologin donino
sudo install -d -m 700 /etc/donino
sudo install -d -m 700 -o donino -g donino /var/lib/donino-node
sudo .venv/bin/python scripts/fetch_xray.py /opt/donino-xray
sudo install -m 600 deploy/node.env.example /etc/donino/node.env
sudoedit /etc/donino/node.env
```

اسکریپت دریافت فقط Linux amd64 را پشتیبانی می‌کند و فایل موجود را بازنویسی نمی‌کند. برای معماری دیگر، باینری و داده‌های رسمی Xray متناظر را با checksum انتشار رسمی نصب کنید؛ آن معماری‌ها در این نسخه آزموده نشده‌اند.

در پنل، نود جدید را با نام و IP یا دامنهٔ واقعی **همین سرور نود** بسازید. مقدار host باید بدون scheme و پورت باشد. کلید یک‌بارنمایش را در `DONINO_NODE_TOKEN` و دامنهٔ پنل را در `DONINO_PANEL_URL` فایل تنظیمات قرار دهید. سپس:

```bash
sudo install -m 644 deploy/donino-node.service /etc/systemd/system/donino-node.service
sudo systemctl daemon-reload
sudo systemctl enable --now donino-node
sudo systemctl status donino-node
sudo journalctl -u donino-node -n 50 --no-pager
```

عامل نود فقط ارتباط خروجی HTTPS با پنل می‌گیرد؛ نیازی به باز کردن پورت مدیریت نود روی اینترنت نیست. پورت `10085/tcp` برای آمار Xray فقط روی loopback رزرو است. پورت‌های inbound مانند `443/tcp` را در فایروال میزبان و ارائه‌دهنده باز کنید. فایل state نود حاوی کلیدهای اتصال است و باید خصوصی بماند.

## ساخت اتصال

- **VLESS/REALITY:** SNI و target باید با هم سازگار و از سرور نود قابل دسترس باشند. پنل زوج کلید X25519 و short ID را می‌سازد. پیش‌فرض `www.microsoft.com:443` فقط یک مقدار آغازین است؛ دسترسی از محل سرور و رفتار مقصد را بررسی کنید. REALITY برای پنل HTTPS گواهی تهیه نمی‌کند.
- **VMess/WS/TLS:** دامنهٔ SNI باید به سرور نود برسد؛ گواهی معتبر همان دامنه و کلید روی نود لازم است. مسیر WebSocket پیش‌فرض `/donino` است.
- **Trojan/TLS:** مانند حالت قبل به گواهی معتبر روی نود نیاز دارد؛ انتقال TCP است.

برای گواهی‌های نود، فایل‌ها را مثلاً در `/etc/donino/tls/` قرار دهید. حساب `donino` باید بتواند فایل‌ها و دایرکتوری‌های والد را بخواند؛ از world-readable کردن کلید خصوصی خودداری کنید. نمونهٔ سرویس `ProtectHome=true` دارد، پس مسیر داخل home کاربر مناسب نیست. تمدید گواهی در این نسخه خارجی است؛ پس از تعویض فایل گواهی، سرویس `donino-node` را restart کنید تا Xray گواهی جدید را بخواند.

پس از ساخت اتصال، نود باید متصل و بدون خطا دیده شود. کاربر جدید بسازید، لینک اشتراک را دریافت و در کلاینت سازگار وارد کنید. لینک Clash با `?format=clash` و لینک خام با `?format=raw` در دسترس است. خروجی Clash ساختار JSON معتبر دارد که YAML نیز آن را می‌پذیرد؛ سازگاری نسخهٔ خاص کلاینت باید جداگانه بررسی شود.

## نگهداری و بازیابی

از صفحهٔ تنظیمات یا CLI پشتیبان سازگار بگیرید:

```bash
cd /opt/donino-panel
sudo -u donino env DONINO_DB=/var/lib/donino-panel/donino.db .venv/bin/python -m app.cli backup /var/lib/donino-panel/backup.db
```

پشتیبان حاوی رمزهای هش‌شده، نشست‌ها، لینک اشتراک و کلیدهای REALITY است. آن را رمزگذاری و خارج از سرور نگه دارید. فایل‌های گواهی روی نود در این پشتیبان نیستند و باید جداگانه حفظ شوند. برای بازیابی، سرویس پنل را متوقف کنید، پایگاه فعلی را در جای امن نگه دارید، فایل پشتیبان را در `DONINO_DB` با مالک `donino` و mode `600` جایگزین کنید و سرویس را بالا بیاورید. بازیابی نشست‌ها و لینک‌های قدیمی را نیز بازیابی می‌کند؛ در رخداد افشای اطلاعات باید رمزها و کلیدها را تعویض کنید.

نسخهٔ ۰.۲ پایگاه دادهٔ ۰.۱ را با پشتیبان خودکار به schema شمارهٔ ۲ ارتقا می‌دهد. این کار در اولین startup یا با `python -m app.cli migrate` انجام می‌شود. [راهنمای ارتقای مرحله‌ای](UPGRADE-0.2.fa.md) ترتیب ارتقای پنل و عامل نود و روش بازیابی را توضیح می‌دهد.

صفحهٔ کاربر از منوی اشتراک در دسترس است. لینک `/u/TOKEN` همان سطح محرمانگی لینک اشتراک را دارد. QR روی همین پنل ساخته می‌شود. فایل `usage.db` داخل `DONINO_NODE_STATE` صف مصرف است؛ آن مسیر را در ارتقا نگه دارید. استفاده از state یک نود برای نود یا دامنهٔ پنل دیگر مسدود می‌شود.
