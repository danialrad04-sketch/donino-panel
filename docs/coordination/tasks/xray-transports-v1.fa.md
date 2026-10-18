# مأموریت فعال کلاد: Xray transports v1

شناسه: `xray-transports-v1`، شاخه: `claude/xray-transports-v1`، مبنا: آخرین `origin/main` شامل PR ۱۲ یا جدیدتر. پیش از شروع، [وضعیت واقعی](../../IMPLEMENTATION-STATUS.fa.md)، [ماتریس پروتکل](../../PROTOCOL-MATRIX.fa.md) و [شرح پذیرش](../../CLAUDE-HANDOFF.fa.md) را بخوان.

خروجی: VLESS WS+TLS، VLESS gRPC+TLS، VMess gRPC+TLS، Trojan WS+TLS با validation، config سرور/کلاینت، URI، Mihomo، فرم اتصال و **انتقال واقعی** با Xray پین‌شده. سه مسیر موجود باید سالم بمانند. Vision روی WS/gRPC اعمال نمی‌شود. CA و hostname معتبر آزمایشی لازم‌اند؛ بررسی TLS خاموش نمی‌شود.

مالکیت اصلی: `app/core.py`، `app/engines.py`، `tests/test_xray_transports.py` و بخش محدود فرم اتصال در `app/static/app.js`. مدل inbound در `app/main.py` فقط با diff محدود. آزمون مصرف device، کاربر غیرفعال/منقضی و دوره‌ها باید حفظ شود. checkpoint خودت در همین پوشه مجاز است.

خارج محدوده: schema/migrations، `app/db.py`، بودجه، هویت و عامل، DNS، importer، installer، `app/tunnel_*` و `app/static/tunnels.js`. قابلیت نصب backend مستقل Xray در Donino Tunnel نباید برای کاربران Donino Panel فعال شود؛ مالک کاربران همین پنل است.

پذیرش: تست‌های هدف، suite مرتبط، مرورگر فرم جدید، manifest، `git diff --check` و PR قابل بازبینی. شکست/skip/محدودیت واقعی را ثبت کن. نسخه/tag/merge بر عهدهٔ Codex است. پس از ثبت PR، checkpoint را `waiting_for_review` کن؛ با «ادامه» ابتدا feedback و انتساب جدید را بررسی کن.
