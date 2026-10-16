# مشخصات نصب، SSL و عملیات Donino

وضعیت: قرارداد فاز ۲ با یک scaffold محلی. `python -m app.installer` سه کار انجام می‌دهد: `preflight` (فقط خواندنی: سیستم‌عامل، معماری، پورت‌ها، فضا، DNS)، `plan` (فهرست فایل‌ها بدون secret) و `render` (نوشتن فایل‌های env، systemd و NGINX زیر ریشهٔ مشخص، با قفل، حالت resume و رد بازنویسی تفاوت‌دار با کد خروج ۷). **هنوز انجام نمی‌شود:** راه‌اندازی یا فعال‌سازی سرویس، reload نژینکس، صدور گواهی، تغییر فایروال. این‌ها به VPS واقعی نیاز دارند. برای نصب فعلی از [راهنمای نصب موجود](DEPLOYMENT.fa.md) استفاده کنید.

مرجع مطالعه: [PasarGuard Scripts در SHA ثابت](https://github.com/PasarGuard/scripts/blob/bba95f274216968542497a500c74a06802c48e88/pasarguard.sh)، به‌ویژه دریافت ACME، نصب cert و hook تمدید؛ این مطالعه مجوز کپی یا اثبات پایداری همه مسیرهای آن نیست. [چالش‌های Let’s Encrypt](https://letsencrypt.org/docs/challenge-types/) مرجع الزامات challenge است.

## قرارداد تجربه نصب

کاربر بستهٔ رسمی نسخه‌دار را با checksum معتبر دریافت می‌کند و یک اسکریپت نصب را اجرا می‌کند. اسکریپت role و دامنه را می‌پرسد، پیش‌نیازها را توضیح می‌دهد و باقی کار را خودکار انجام می‌دهد. تا انتشار artifact واقعی، URL ساختگی `curl | bash` در README قرار نمی‌گیرد. installer تعاملی و non-interactive باید یک state machine و همان اعتبارسنجی را مصرف کنند.

| ورودی هدف | رفتار |
|---|---|
| role: control / node / dns-relay / dns-exit / all-in-one | فقط سرویس‌های همان نقش نصب شود؛ ترکیب‌ها دفتر پورت مشترک دارند |
| domain، IP عمومی، ACME email | اعتبارسنجی نام/رکورد و نمایش نتیجه؛ ایمیل و secret در log عمومی نباشد |
| HTTP-01 یا DNS-01 | پیش‌فرض دامنهٔ ساده HTTP-01 با پورت ۸۰؛ DNS-01 با provider صریح |
| نسخه بسته، مسیر داده و DB | پیش‌فرض‌های ثابت و قابل کشف؛ overwrite بی‌صدا ممنوع |
| credential DNS یا DB خارجی | از فایل خصوصی/ورودی امن؛ خارج از argv، stdout و history |
| ثبت نود | enrollment یک‌بارمصرف، مدت‌دار و محدود به role؛ سپس mTLS |

هدف اولیه Linux/systemd: Ubuntu 24.04 LTS و Debian 12 روی amd64. arm64 پس از بسته و آزمون VM مستقل اضافه می‌شود؛ توزیع/معماری آزموده‌نشده پیش از هر mutation رد شود. «سازگاری جهانی» ادعا نشود. روش native/systemd مسیر اول است؛ Docker بسته‌بندی مستقل با همان معیار پذیرش خواهد بود.

## مراحل و خطاها

| مرحله | کار | شرط عبور و رفتار شکست |
|---|---|---|
| preflight خواندنی | OS/arch، root، CPU/RAM/disk، ساعت، DNS، شبکه، پورت و سرویس موجود | گزارش مشخص بدون تغییر فایروال یا توقف سرویس؛ حداقل منابع براساس آزمون ظرفیت نسخه تعیین شود |
| plan | roleها، پورت‌ها، بسته و اثر تغییرات | فایل طرح redacted ذخیره شود؛ install جدید با adopt سرویس قبلی فرق دارد |
| lock/state | قفل سراسری installer و journal مرحله | دو اجرا هم‌زمان نشوند؛ state بدون secret، هر مرحله قابل resume |
| artifacts | دریافت نسخه pinned، بررسی hash/signature و مجوز | خطای اصالت قبل از اجرا/جایگزینی متوقف شود؛ latest متحرک مبنای نصب نیست |
| data/services | کاربرهای کم‌اختیار، مسیر خصوصی و واحد systemd | DB از اینترنت قابل دسترس نباشد؛ engine/root helper حداقل قابلیت لازم |
| database | ایجاد DB و کاربر محدود، backup، migration نسخه‌دار | خطای backup/migration مانع startup نسخه جدید؛ DB موجود حذف یا reinitialize نشود |
| network/proxy | ایجاد دفتر پورت، vhost و challenge route | `nginx -t` و آزمون دسترسی؛ تنظیم قدیم تا موفقیت حفظ شود |
| certificate | issue یا استفاده مجدد از cert معتبر | chain/SAN/expiry و تطابق key؛ نصب اتمی با حق دسترسی محدود |
| start/verify | health API، DB، TLS از بیرون و role-specific probe | خطای موتور یا cert به‌عنوان نصب موفق چاپ نشود |
| bootstrap | ایجاد مالک با فرایند یک‌بارمصرف | بدون رمز مشترک/پیش‌فرض؛ افشای secret در log ممنوع؛ bootstrap پس از مصرف بسته شود |
| operations | timer تمدید، backup، health و نسخه | خروجی شامل نشانی پنل، نسخه، وضعیت و اقدامات باقی‌ماندهٔ مشخص |

exit code هدف: `0` فقط موفقیت پذیرفته؛ `2` ورودی/پیش‌نیاز؛ `3` دریافت/اعتبار artifact؛ `4` DB/migration؛ `5` DNS/TLS؛ `6` سلامت سرویس؛ `7` قفل/نیاز به رفع دستی. اجرای دوباره همان نسخه گواهی/کلید/کاربر و firewall rule تکراری نمی‌سازد و state کاربر را reset نمی‌کند. dry-run فقط خواندنی است.

## دامنه و گواهی

- تنها دادن دامنه وقتی کافی است که A/AAAA به میزبان درست اشاره کنند، CAA صدور را اجازه دهد و challenge از اینترنت قابل دسترس باشد. نصب‌کننده نمی‌تواند بدون مجوز رکورد DNS دامنه را تغییر دهد. IPv6 اشتباه باید پیش از issue گزارش شود.
- پیش‌فرض NGINX + ACME client با نسخه pinned است؛ انتخاب دقیق نسخه client در manifest فاز ۲ ثبت می‌شود. HTTP-01 از پورت عمومی ۸۰ می‌آید؛ تغییر پورت داخلی، الزام عمومی را حذف نمی‌کند. wildcard با DNS-01 و API کم‌اختیار provider لازم است.
- حساب ACME، credential provider و private key خارج از repo و با دسترسی محدود باشند. cert معتبر موجود حفظ می‌شود؛ `--force` در هر نصب اجرا نشود. آزمایش‌های VM با staging ACME برای پرهیز از rate limit انجام شوند؛ صدور واقعی بعداً شاهد جدا دارد.
- renew: قفل → دریافت → بررسی chain/SAN/key/expiry → نصب اتمی → config-test → reload → probe. در خطا نسخه قبلی سالم بماند، alarm ثبت شود و retry محدود با backoff انجام شود. cron/timer تکراری ساخته نشود.
- گواهی پنل، گواهی هر inbound و REALITY کلیدهای نقش‌های جدا هستند. نصب گواهی پنل خودکار به معنی معتبرشدن تمام پروتکل‌های نود نیست؛ مسیر cert و SAN هر endpoint باید جدا بررسی شود.

## دفتر پورت و حفظ دسترسی

| مصرف‌کننده | پیش‌فرض/دامنه | تصمیم لازم |
|---|---|---|
| SSH موجود | پورت فعلی میزبان | دست‌نخورده؛ هیچ flush یا تغییر عمومی policy برای حل تعارض |
| HTTP-01 و پنل | TCP/80 و TCP/443 | challenge route با سرویس خام HTTP گیمینگ تداخل دارد |
| DNS | UDP/53 و TCP/53 | systemd-resolved/dnsmasq موجود بررسی شود؛ کورکورانه stop نشود |
| DoT / DoQ | TCP/853 و UDP/853 | پورت یکسان ولی transport متفاوت؛ مالک هرکدام ثبت شود |
| DoH / DoH3 | TCP/443 و UDP/443 در حالت سازگار | DoH پشت NGINX route معتبر؛ DoH3 با VPN QUIC تصادم دارد |
| Gaming relay | معمولاً TCP/80 و TCP/443 | role مستقل ترجیح دارد؛ SNI passthrough با UI روی همان socket پیش‌فرض یکسان نیست |
| Xray / VPNها | پورت endpoint منتخب | دفتر پورت همه موتورهای همان نود را بررسی کند |
| API مدیریت موتور و DB | loopback/private socket | از اینترنت قابل دسترسی نباشند |

تخصیص شامل address/family/transport/port و مالک است؛ wildcard bind با IPv4/IPv6 هم بررسی می‌شود. حل تعارض یکی از تغییر پورت، IP مستقل، role مستقل یا multiplexing صریحِ آزموده‌شده است. installer نباید برای جا دادن همه نقش‌ها به‌طور پنهان QUIC/HTTP3 یا IPv6 را غیرفعال کند.

در relay فعال، تصاحب موقت پورت ۸۰ برای ACME می‌تواند دانلود را قطع کند. انتخاب قابل پذیرش: دامنه/IP کنترل جدا، DNS-01 با provider یا challenge routing آزموده‌شده. روش redirect موقت بدون اثبات عدم قطع، مسیر پیش‌فرض «بدون وقفه» محسوب نمی‌شود.

## فایل، DB و مجوزها

طرح مسیر: `/etc/donino/` تنظیمات و secret؛ `/var/lib/donino/` داده و journal؛ `/var/log/donino/` log بدون credential؛ `/var/backups/donino/` backup خصوصی؛ `/opt/donino/releases/<version>/` نسخه‌های immutable و اشاره‌گر نسخه جاری. دسترسی backup و کلیدها پیش‌فرض `0600` یا حداقلِ نیاز همان سرویس است. گروه مشترک فقط برای خواندن کلید لازم و بدون خواندن secretهای نامرتبط تعریف می‌شود.

نسخه major PostgreSQL و بسته‌های هر توزیع در فاز ۱/manifest قفل می‌شوند. tuning با RAM و بار آزموده‌شده انجام شود؛ pool محدود، timeout، index و retention مشخص باشد. memory tuning ثابت برای هر سرور، DB عمومی بدون auth و اصرار به Timescale پیش از نیازسنجی پذیرفته نیست. SQLite حالت شخصی backup سازگار با WAL و همان migration contract را حفظ می‌کند.

## ارتقا، بازیابی و خروج

رابط CLI هدف: `install / upgrade / doctor / repair / backup / restore / uninstall`. این زیر‌فرمان‌ها هنوز در CLI فعلی همگی وجود ندارند. `doctor` خواندنی و خروجی redacted دارد؛ `repair` فقط عملیات محدود و idempotent همان سرویس را انجام می‌دهد.

upgrade: بررسی سازگاری نسخه/داده → توقف کارهای تغییر‌دهنده لازم → backup DB+config+کلید و manifest → دریافت artifact معتبر → migration → canary/health → فعال‌کردن نسخه. شکست پیش از commit مرحله نباید «موفق» گزارش شود. downgrade بدون مسیر migration معکوس آزموده‌شده ممنوع است؛ بازیابی backup متناظر جایگزین آن می‌شود.

backup رمزگذاری‌شده و دارای checksum/manifest، شامل schema/code version، policy، کلیدهای لازم و آخرین مرز مصرف است؛ کلید بازکردن backup نباید فقط روی همان میزبان از دست‌رفتنی باشد. restore باید روی ماشین مستقل و بدون دسترسی مشتری عمومی آزمایش شود؛ نودها پیش از reconciliation مصرف و lease دوباره سرویس باز نکنند. RPO/RTO طبق OPS-01 اندازه‌گیری و منتشر شوند.

uninstall پیش‌فرض داده و backup را نگه می‌دارد و فقط منابع متعلق به Donino را حذف می‌کند؛ حذف داده عملیات جدا، صریح و گزارش‌شده است. adoption نصب‌های PasarGuard/3x-ui یا doctor-dns بخشی از installer عمومی نیست؛ importer نسخه‌دار و آزموده‌شده مسیر آن است.

## پذیرش

INST-01 تا INST-04 باید نصب تمیز، اجرای تکراری، resume بعد از خطا، تعارض پورت، SSL/renewal و upgrade/restore را پوشش دهند. نصب روی VPS واقعی و دامنه تحت اختیار مالک، شاهد جدا از VM دارد. تا پیش از آن README باید روش فعلی دستی را معتبر و installer جدید را «در توسعه» نشان دهد.
