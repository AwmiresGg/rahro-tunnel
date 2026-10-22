# Rahro — پنل Xray + تونل مقاوم در برابر DPI

<p align="center"><a href="README.md">English 🇬🇧</a> · <b>فارسی</b></p>

![داشبورد پنل Rahro](docs/assets/dashboard.png)

**Rahro** (رهرو) یک پنل مدیریت self-hosted برای دور زدن سانسور اینترنت است. هم
**تمام امکانات یک پنل Xray** را دارد (اینباند برای VLESS / VMess / Trojan /
Shadowsocks، REALITY، کاربر، سهمیه، سابسکریپشن، API ربات تلگرام) و هم **یک تونل
اختصاصی مقاوم در برابر DPI** برای رله‌کردن یک سرور داخلی به سرور خارج، با ترافیکی
که شبیه HTTPS معمولی است. همه‌چیز از **یک پنل** روی **Linux یا Windows**.

> **محدوده‌ی صادقانه:** هیچ ابزاری شکست‌ناپذیر نیست؛ این فقط هزینه‌ی تشخیص را بالا
> می‌برد تا مسدود کردنش یعنی مسدود کردن HTTPS معمولی. در برابر قطع کامل اینترنت
> کاری نمی‌تواند بکند. فقط از رمزنگاری وارسی‌شده استفاده می‌کند و **هسته‌ی Xray را
> به‌صورت باینریِ مدیریت‌شده** اجرا می‌کند (هیچ کد Xray/3x-ui کپی نشده). ببینید:
> [docs/SECURITY.md](docs/SECURITY.md).

---

## نصب (سرور خارج)

به‌عنوان root روی Ubuntu/Debian/CentOS — اول دانلود، بعد اجرا (روی هر ترمینالی کار می‌کند):

```bash
curl -fsSL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh -o rahro-install.sh
sudo bash rahro-install.sh
```

> یا با pipe: `curl -fsSL …/install.sh | sudo bash`. از `bash <(curl …)` استفاده
> نکن — بعضی ترمینال‌های موبایل/SSH خطای `/dev/fd/63: No such file or directory`
> می‌دهند.

اسکریپت یک باینریِ از‌پیش‌ساخته را از گیت‌هاب می‌گیرد (نیازی به Go/کامپایل نیست)،
`/etc/rahro/panel.json` را می‌نویسد، یک ادمین می‌سازد، سرویس `rahro-panel` را
بالا می‌آورد، و **آدرس پنل** و **رمز ادمین** را چاپ می‌کند. بار اول پنل هسته‌ی
**Xray** را هم در پس‌زمینه دانلود می‌کند (چند ثانیه).

پنل را باز کن: `https://<آی‌پی‌سرور>:2053` (گواهی self-signed — اخطار مرورگر را
بپذیر) و وارد شو.

---

## اولین کانفیگِ کارآمد (۳۰ ثانیه)

1. تب **Inbounds** → پروتکل **VLESS**، پورت **443**، network **tcp**، security
   **reality**.
2. دکمه‌ی **🔑 Generate REALITY keys** (کلیدها در Settings پر می‌شوند) → **Add inbound**.
3. تب **Users** → **Add user** → دکمه‌ی **sub** → لینک سابسکریپشن کپی می‌شود.
4. لینک را در v2rayNG / NekoBox / sing-box / Clash-Meta بگذار → **وصل می‌شود**.

پنل Xray را با اینباندهای تو و هر کاربر فعال به‌عنوان کلاینت اجرا می‌کند؛ سابسکریپشن
لینک‌های واقعیِ `vless://…reality` (و vmess/trojan/ss) می‌دهد که کلاینت‌های آماده
می‌فهمند. هر تغییر کاربر/اینباند، Xray را خودکار ری‌لود می‌کند.

---

## منوی ترمینالی (`rahro`)

روی سرور فقط تایپ کن **`rahro`** تا منوی x-ui مانند باز شود:

```
 1) وضعیت و اطلاعات     2/3/4) restart / start / stop
 5) تغییر یوزر و پسورد ادمین
 6) تغییر پورت پنل
 7) SSL / حالت دسترسی  (self-signed | http | domain + Let's Encrypt)
 8) مسیر مخفی          9) Public URL
10) مشاهده لاگ         11) آپدیت پنل (دانلود آخرین نسخه)
12) نمایش اطلاعات ورود 13) حذف
```

پس SSL، پورت و یوزر/پسورد را هم از ترمینال و هم از تب **Settings** وب می‌شود عوض کرد.

### گرفتن گواهی واقعی (دامنه)

یک رکورد A دامنه را به سرور وصل کن، پورت‌های ۸۰ و ۴۴۳ را باز کن، بعد `rahro` →
گزینه‌ی **۷** → **domain** → دامنه را وارد کن. Let's Encrypt خودکار گرفته می‌شود.

---

## نودها و تونل ایران (مولتی‌لوکیشن + رله)

Rahro یک ناوگان هم اجرا می‌کند:

- **نودهای لوکیشن** — سرورهای خارجی اضافه که به هر سابسکریپشن یک لوکیشن اضافه می‌کنند.
- **نودهای تانل** — یک **رله‌ی داخلی (مثلاً ایران)**: کاربر به IP داخلی وصل می‌شود
  (پینگ کم، مسدود نیست) و نود همه‌چیز را از **تونل Rahro** (که شبیه HTTPS است) به
  سرور خارج رله می‌کند. فقط ترافیک استتارشده از مرز عبور می‌کند.

در پنل → **Nodes** / **Tunnel nodes** → یکی بساز → **کد اتصال** را کپی کن → روی آن
سرور اجرا کن:

```bash
I="https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh"
# لوکیشن egress خارجی:
curl -fsSL "$I" | sudo bash -s -- node   <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure
# رله‌ی ایران:
curl -fsSL "$I" | sudo bash -s -- tunnel <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure
```

`<CONNECTION-CODE>` را با کد واقعی (بدون `< >`) و آی‌پی پنل را عوض کن. `-insecure`
وارسی گواهی self-signed پنل را رد می‌کند؛ وقتی پنل دامنه گرفت حذفش کن.

---

## ربات فروش تلگرام (توکن API)

پنل → **API tokens** → یکی بساز (فقط یک‌بار نشان داده می‌شود). ربات با هدر
`Authorization: Bearer <token>` صدا می‌زند:

```bash
# ساخت کاربر برای فروش (۵۰ گیگ، ۳۰ روز) — لینک سابسکریپشن را برمی‌گرداند:
curl -s https://<panel>/botapi/users -H "Authorization: Bearer rahro_xxx" \
  -d '{"username":"buyer1","quota_gb":50,"days":30}'
# مصرف:         GET  /botapi/users/<uuid>
# تمدید/شارژ:   POST /botapi/users/<uuid>/renew  {"add_days":30,"add_gb":50,"reset_usage":true}
# لوکیشن‌ها:    GET  /botapi/nodes
# دانلود بکاپ:  GET  /botapi/backup        (اسنپ‌شات .db، مثلاً برای آرشیو در تلگرام)
```

پاسخ ساخت/تمدید شامل `sub_link` است تا ربات مستقیم برای مشتری بفرستد. مصرفی که
`GET /botapi/users/<uuid>` برمی‌گرداند **ترافیک واقعیِ اندازه‌گیری‌شده** است: پنل
هر ~۴۵ ثانیه شمارنده‌های هر کاربر را از Xray می‌خواند و لحظه‌ای که کاربر به سقف
سهمیه یا انقضا برسد، خودکار غیرفعالش می‌کند.

---

## پیکربندی (`/etc/rahro/panel.json`)

```jsonc
{
  "log_level": "info",
  "panel": {
    "enabled": true,
    "listen": "0.0.0.0:2053",
    "tls_mode": "self-signed",          // off | self-signed | domain
    "domain": "panel.example.com",      // وقتی tls_mode = domain لازم است
    "db_path": "/etc/rahro/rahro-panel.db",
    "public_url": "https://1.2.3.4:2053",// برای ساخت لینک سابسکریپشن
    "base_path": "/x7f3a9"              // پیشوند مسیر مخفی (اختیاری)
  }
}
```

ویرایش کن (یا از منوی `rahro`)، بعد `systemctl restart rahro-panel`.

---

## ساخت از سورس

```bash
git clone https://github.com/AwmiresGg/rahro-tunnel.git && cd rahro-tunnel
make build        # همه‌ی باینری‌ها
make test         # کل مجموعه تست
make race         # تست‌ها زیر race detector
make dist         # باینری‌های کراس‌کامپایل لینوکس (amd64/arm64) + ویندوز
```

نیازمند Go 1.26+. کاملاً Go (بدون CGO)؛ به لینوکس و ویندوز کراس‌کامپایل می‌شود.
**ویندوز سرور:** `scripts/install.ps1` (در PowerShell با دسترسی Administrator).

---

## وضعیت

کارکرده و تست‌شده: ادغام هسته‌ی Xray (باینری مدیریت‌شده، دانلود خودکار، ساخت config
از اینباند+یوزر، ری‌لود روی تغییر)، اینباندها (VLESS/VMess/Trojan/Shadowsocks روی
tcp/ws/grpc/http/quic با none/tls/reality)، تولید کلید REALITY، لینک اشتراک و
سابسکریپشن کارآمد، **اندازه‌گیری واقعی مصرف هر کاربر از طریق stats API ایکس‌ری با
اعمال خودکار سهمیه/انقضا**، نودهای مولتی‌لوکیشن، مسیر دیتای رله‌ی تانل ایران،
**داشبورد وضعیت سرور** (CPU/RAM/دیسک/سواپ/آپتایم/لود)، **کلاینت‌های آنلاین با IP
هر کاربر و اعمال محدودیت تعداد IP**، **ریست ترافیک و چرخه‌ی ریست خودکار هر کاربر**،
تغییر حساب ادمین، **قفل brute-force لاگین ادمین** و هدرهای امنیتی (HSTS زیر TLS)،
**بکاپ یک‌کلیکی دیتابیس** (تب Settings پنل یا `GET /botapi/backup`)، منوی ترمینالی
`rahro`، API ربات تلگرام، و ترنسپورت مقاوم در برابر DPI خودِ Rahro (TLS با اثرانگشت
مرورگر uTLS، fallback به decoy سبک REALITY، padding فریم، ترنسپورت WebSocket).
end-to-end با باینری واقعی Xray تست شده. همه‌ی پکیج‌ها `go test` را پاس می‌کنند؛
پکیج‌های حساس به همزمانی `-race` را.

نقشه‌ی راه: REALITY کامل با جاسازی ClientHello برای ترنسپورت Rahro؛ ترنسپورت‌های
gRPC/QUIC؛ ورود دو‌مرحله‌ای ادمین (TOTP؛ schema آماده است)؛ اپ موبایل/GUI.
ببینید [docs/DESIGN.md](docs/DESIGN.md) و [docs/SECURITY.md](docs/SECURITY.md).

---

## لایسنس

Rahro نرم‌افزار **اختصاصی (proprietary)** است — © ۲۰۲۶ AwmiresGg، تمام حقوق
محفوظ. می‌توانی آن را برای راه‌اندازی سرویس خودت (حتی سرویس پولی) اجرا کنی؛ اما
بازتوزیع خودِ نرم‌افزار مجاز نیست. ببینید [LICENSE](LICENSE) و
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
