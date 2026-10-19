# WireGuard — پیش‌نمایش alpha.14

این نقش مستقل از عامل Xray است. کلید خصوصی دستگاه و PSK در پایگاه داده با
کلید اصلی پنل رمز می‌شوند؛ فایل conf و QR خصوصی فقط در اختیار مالک پنل است.
هر دستگاه IP مستقل و سهمیه/دورهٔ مشترک حساب دارد. سقف هر نود چهار رابط و
۱۲۸ peer است. سهمیهٔ `lease` پذیرفته نمی‌شود؛ سهمیهٔ معمول در چند نود سقف
بایتی سخت نیست و تاخیر گزارش مصرف دارد.

## آماده‌سازی نقش نود

فعلاً نصب این نقش دستی است؛ نصب‌کنندهٔ کنترل‌پنل آن را خودکار فعال نمی‌کند.
روی Linux دارای systemd، Python پشتیبانی‌شده، `iproute2` و `wireguard-tools`
لازم است. سورس همان نسخهٔ پنل و وابستگی‌های قفل‌شده را در
`/opt/donino-panel` و `.venv` آن آماده کنید. برای کرنل فاقد WireGuard، بستهٔ
رسمی `wireguard-go` و دسترسی `/dev/net/tun` لازم است؛ عامل خودش بسته یا ماژول
کرنل نصب نمی‌کند.

برای این نقش یک نود و توکن enrollment مستقل بسازید. توکن را در فایل خصوصی
با مجوز ۶۰۰ روی نود قرار دهید؛ در خط فرمان، Git یا گفتگو ننویسید. از فرمان
زیر با دامنه و UUID واقعی خود استفاده کنید:

```sh
sudo /opt/donino-panel/.venv/bin/python -m agent.enroll \
  --panel https://panel.example.com --node-id NODE_UUID \
  --state /var/lib/donino-wireguard --token-file /root/wg-enrollment-token
```

پس از enrollment موفق فایل توکن را حذف کنید. گواهی HTTPS پنل بررسی می‌شود؛
برای CA خصوصی گزینهٔ `--ca-file` موجود است. TLS verification را خاموش نکنید.
فایل `/etc/donino/wireguard.env` با مالک root و مجوز ۶۰۰:

```ini
DONINO_PANEL_URL=https://panel.example.com
DONINO_WG_STATE=/var/lib/donino-wireguard
# فقط برای backend کاربران و با مسیر اجرایی مطلق:
# DONINO_WG_USERSPACE=/usr/bin/wireguard-go
```

```sh
sudo install -m 644 deploy/donino-wireguard-tmpfiles.conf /etc/tmpfiles.d/donino-wireguard.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/donino-wireguard.conf
sudo install -m 644 deploy/donino-wireguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now donino-wireguard
```

عامل فقط رابط‌های `dnw*` ثبت‌شده با کلید عمومی مطابق را کنترل می‌کند.
ExecStopPost بدون شبکه و بدون نیاز به گواهی معتبر، رابط‌های متعلق به عامل را
متوقف و شمارنده‌های مشاهده‌شده را در دفتر پایدار حفظ می‌کند. نام مشابه برای
پذیرش مالکیت کافی نیست. خرابی state یا تغییر کلید رابط نیازمند بررسی اپراتور
است؛ فایل state حاوی اطلاعات خصوصی است و نباید عمومی شود.

## مسیریابی و استفاده

اپراتور باید پیش از فعال‌کردن رابط، پورت UDP، forwarding و NAT یا مسیر برگشت
محدودهٔ انتخابی را مطابق شبکهٔ خود آماده کند. عامل قواعد عمومی firewall،
NAT، sysctl یا default route میزبان را تغییر نمی‌دهد. محدودهٔ خصوصی رابط
نباید با مسیرهای میزبان یا رابط‌های دیگر هم‌پوشانی داشته باشد.

در بخش WireGuard رابط را بسازید، فعال کنید و برای دستگاه حساب peer بسازید.
conf یا QR را فقط به صاحب همان دستگاه بدهید. لغو دسترسی، انقضا و تمام‌شدن
حجم peer را حذف می‌کنند. تغییر ساختاری تنظیمات، تعویض کلید یا ریست دوره می‌تواند همهٔ رابط‌های همین
عامل را بازسازی کند؛ دستگاه‌های دیگر هم قطع می‌شوند و ممکن است به اتصال
دوبارهٔ کلاینت نیاز داشته باشند. حذف سادهٔ peer نشست دستگاه‌های دیگر را نگه می‌دارد. تعویض کلید، کانفیگ قبلی را باطل می‌کند؛ conf تازه بدهید.
restore پایگاه داده همهٔ رابط‌ها را غیرفعال می‌کند و فعال‌سازی دوباره صریح است.

این نسخه فقط dataplane IPv4 دارد. مسیر `0.0.0.0/0` در conf همراه `::/0`
صادر می‌شود تا IPv6 از مسیر مستقیم عبور نکند؛ IPv6 در این حالت سرویس نمی‌شود.
کلاینت باید این سیاست را پشتیبانی کند. DNS انتخابی تنها آدرس resolver است؛
این تنظیم به‌تنهایی رفع تحریم بازی، رمزگذاری DNS یا دسترسی به همهٔ بازی‌ها نیست.

## پذیرش

آزمون API/عامل، آزمون انتقال واقعی را جایگزین نمی‌کند. fixture شبکه در
`tests/wireguard/network.py` داخل Docker خصوصی با NET_ADMIN اجرا می‌شود؛
full-tunnel پیش‌فرض و split-route صریح قابل تفکیک‌اند. کرنل محیط توسعه
WireGuard kernel و قانون IPv6 `ct mark` لازم برای wg-quick را ندارد؛ نتیجهٔ
userspace یا split-route شاهد پشتیبانی kernel/full-tunnel در آن محیط نیست.
آزمون VPS واقعی، اینترنت ایران/خارج و بار عملیاتی هنوز لازم‌اند.
