# Rahro — تونل مقاوم در برابر DPI + پنل مدیریت

<p align="center"><a href="README.md">English 🇬🇧</a> · <b>فارسی</b></p>

![داشبورد پنل Rahro](docs/assets/dashboard.png)

**Rahro** (رهرو) یک تونل دور زدن سانسور با پنل وب است که برای شبکه‌هایی ساخته شده
که از بازرسی عمیق بسته‌ها (DPI) و کاوش فعال (active probing) استفاده می‌کنند. روی
**سرورهای لینوکس و ویندوز** اجرا می‌شود، **کاربرها، اینباندها، نودها و تانل‌ها را از
یک پنل** مدیریت می‌کند، از **سابسکریپشن چندلوکیشنی** پشتیبانی می‌کند، و اجازه می‌دهد
یک رله‌ی ایران از طریق کانالی که شبیه HTTPS معمولی است به سرور خارج برسد.

> **محدوده‌ی صادقانه:** هیچ ابزاری «شکست‌ناپذیر» نیست. Rahro هزینه‌ی تشخیص را آن‌قدر
> بالا می‌برد که مسدود کردنش یعنی مسدود کردن HTTPS معمولی. در برابر قطع کامل اینترنت
> کاری نمی‌تواند بکند. فقط از رمزنگاری وارسی‌شده استفاده می‌کند (X25519 /
> ChaCha20-Poly1305 / HKDF، TLS 1.3) — هیچ کریپتوی دست‌نویسی ندارد. ببینید:
> [docs/SECURITY.md](docs/SECURITY.md).

---

## چطور کار می‌کند

```
        ┌──────── پنل اصلی (سرور خارج) ────────┐
        │ کاربرها · اینباندها · نودها · تانل‌ها · سابسکریپشن │
        └───┬───────────────────────────────┬───────┘
     کنترل (کد اتصال + سکرت)                  │
            │                                 │
   ┌────────▼ نودهای لوکیشن (egress) ──┐       │ تونل Rahro (شبیه HTTPS)
   │  NL · TR · DE …  سابسکریپشن چندلوکیشنی│    │
   └─────────────────────────────────────┘     │
                              ┌─────────────────▼ نود تانل (رله‌ی ایران) ─┐
   کاربر در ایران ─► IP داخلی  │ اینباند استاندارد و/یا Rahro می‌دهد و بعد │
   (پینگ کم، مسدود نیست)       │ ترافیک را از تونل Rahro به خارج رله می‌کند │
                              └──────────────────────────────────────────────┘
```

- **دفاع به سبک REALITY:** کلاینت ثابت می‌کند کلید X25519 سرور را می‌داند؛ هرکس که
  نداند (مرورگر، probe سانسورچی) به‌طور شفاف به یک سایت **decoy** واقعی پراکسی می‌شود،
  پس کاوش هیچ‌چیز یاد نمی‌گیرد.
- **استتار:** TLS 1.3 با ClientHello یک مرورگر واقعی (uTLS)، padding طول فریم‌ها، و
  مالتی‌پلکس کردن چندین استریم روی یک اتصال.
- **ترنسپورت‌ها:** TLS (پیش‌فرض) و WebSocket (سازگار با CDN)؛ بقیه قابل افزودن‌اند.

طراحی کامل: [docs/DESIGN.md](docs/DESIGN.md).

---

## ۱. نصب پنل (سرور خارج)

به‌عنوان root روی Ubuntu/Debian/CentOS — اول دانلود، بعد اجرا (روی هر ترمینالی کار می‌کند):

```bash
curl -fsSL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh -o rahro-install.sh
sudo bash rahro-install.sh
```

> یا با pipe: `curl -fsSL …/install.sh | sudo bash`.
> از `bash <(curl …)` استفاده نکن — بعضی ترمینال‌های موبایل/SSH با خطای
> `/dev/fd/63: No such file or directory` شکست می‌خورند.
>
> بیلد از روی کلون هم کار می‌کند (و `scripts/install.sh` خودش کلون را تشخیص می‌دهد
> و از همان‌جا بیلد می‌کند): `git clone https://github.com/AwmiresGg/rahro-tunnel.git && cd rahro-tunnel && sudo bash scripts/install.sh`.

این اسکریپت یک باینریِ از‌پیش‌ساخته را از گیت‌هاب دانلود می‌کند (نیازی به Go یا
کامپایل نیست؛ فقط اگر در دسترس نبود از سورس می‌سازد)، فایل `/etc/rahro/panel.json`
را می‌نویسد، یک ادمین می‌سازد، و سرویس `rahro-panel` را راه می‌اندازد. در پایان
**آدرس پنل** و **اطلاعات ورود ادمین** را چاپ می‌کند.

پنل را در مرورگر باز کن:

- `https://<server-ip>:2053` — TLS با گواهی self-signed (پیش‌فرض؛ اخطار مرورگر را بپذیر)، **یا**
- `http://<server-ip>:2053` — مقدار `"tls_mode": "off"`، **یا**
- `https://panel.example.com:2053` — مقدار `"tls_mode": "domain"` + `"domain"` برای گواهی رایگان Let's Encrypt.

فایل `/etc/rahro/panel.json` را ویرایش کن و بعد `systemctl restart rahro-panel`.

**ویندوز سرور** (PowerShell با دسترسی Administrator، Go نصب‌شده):

```powershell
irm https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.ps1 | iex
```

**Docker:**

```bash
git clone https://github.com/AwmiresGg/rahro-tunnel && cd rahro-tunnel
docker compose up -d --build
docker compose exec panel rahro-panel admin create -config /data/panel.json -u admin -p 'YOUR_PASS'
```

---

## ۲. افزودن نود (لوکیشن) و تانل‌های ایران

در پنل → **Nodes** → *Add location node* (یا **Tunnel nodes** → *Add tunnel
node*). یک **کد اتصال** می‌گیری. روی آن سرور اجرا کن:

```bash
I="https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh"

# لوکیشن egress خارجی (به هر سابسکریپشن یک لوکیشن اضافه می‌کند):
curl -fsSL "$I" | sudo bash -s -- node <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure

# رله‌ی ایران (از تونل Rahro به پنل/upstream وصل می‌شود):
curl -fsSL "$I" | sudo bash -s -- tunnel <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure
```

`-insecure` وارسی گواهی TLS پنل را رد می‌کند (وقتی پنل گواهی self-signed / IP دارد
لازم است). وقتی پنل دامنه با گواهی واقعی دارد، آن را بردار.

نود با سکرت خودش enroll می‌شود، کانفیگش را می‌گیرد و به‌عنوان سرویس systemd بالا
می‌آید (`journalctl -u rahro-node -f`).

---

## ۳. ساخت کاربر و اشتراک سابسکریپشن

پنل → **Users** → *Add user* (سهمیه به GB و تعداد روز را بگذار). هر کاربر **یک لینک
سابسکریپشن می‌گیرد که همه‌ی لوکیشن‌های فعال را لیست می‌کند**:

```
https://<panel>/sub/<token>
```

آن را در v2rayNG / NekoBox / sing-box / Clash-Meta بگذار. سهمیه و انقضا به‌صورت
مرکزی اعمال می‌شوند؛ دکمه‌ی «sub» در جدول کاربران لینک را کپی می‌کند.

---

## ۴. اتصال ربات فروش تلگرام (توکن API)

پنل → **API tokens** → *Create token* (فقط یک‌بار نشان داده می‌شود). ربات تو با
هدر `Authorization: Bearer <token>` پنل را صدا می‌زند:

```bash
# ساخت کاربر برای یک فروش (۵۰ گیگ، ۳۰ روز) — لینک سابسکریپشن را برمی‌گرداند:
curl -s https://<panel>/botapi/users \
  -H "Authorization: Bearer rahro_xxx" \
  -d '{"username":"buyer1","quota_gb":50,"days":30}'

# گرفتن کاربر + میزان مصرف:
curl -s https://<panel>/botapi/users/<uuid> -H "Authorization: Bearer rahro_xxx"

# تمدید / شارژ (افزودن روز و گیگ، به‌دلخواه ریست مصرف):
curl -s https://<panel>/botapi/users/<uuid>/renew \
  -H "Authorization: Bearer rahro_xxx" \
  -d '{"add_days":30,"add_gb":50,"reset_usage":true}'

# لیست لوکیشن‌هایی که فروش پوشش می‌دهد:
curl -s https://<panel>/botapi/nodes -H "Authorization: Bearer rahro_xxx"
```

پاسخ ساخت/تمدید شامل `sub_link` است، پس ربات می‌تواند مستقیم آن را برای مشتری بفرستد.

---

## CLI

```bash
rahro-panel run        -config /etc/rahro/panel.json   # اجرای پنل (سرویس همین کار را می‌کند)
rahro-panel admin create -u admin -p 'pass'            # ساخت / ریست ادمین
rahro-panel admin passwd -u admin -p 'newpass'
rahro-panel token create -name telegram-bot            # ساخت توکن API
rahro-server -genkey                                   # تولید جفت‌کلید X25519
rahro-node   enroll <code> -panel https://panel:2053   # enroll یک نود
rahro-node   run                                       # اجرای یک نودِ enroll‌شده
```

---

## ساخت از سورس

```bash
git clone https://github.com/AwmiresGg/rahro-tunnel && cd rahro-tunnel
make build      # همه‌ی باینری‌ها (go build ./...)
make test       # کل مجموعه تست
make race       # تست‌ها زیر race detector
make dist       # باینری‌های کراس‌کامپایل لینوکس (amd64/arm64) + ویندوز در ./dist
```

نیازمند Go 1.26 به بالا. همه‌چیز Go خالص است (CGO غیرفعال)، پس تمیز به لینوکس و
ویندوز کراس‌کامپایل می‌شود.

---

## مرجع پیکربندی (`panel.json`)

```jsonc
{
  "log_level": "info",                 // debug|info|warn|error
  "panel": {
    "enabled": true,
    "listen": "0.0.0.0:2053",
    "tls_mode": "self-signed",         // off | self-signed | domain
    "domain": "panel.example.com",     // وقتی tls_mode = domain لازم است
    "db_path": "/etc/rahro/rahro-panel.db",
    "public_url": "https://1.2.3.4:2053", // برای ساخت لینک‌های سابسکریپشن
    "base_path": "/x7f3a9"             // پیشوند مسیر مخفی (اختیاری)
  }
}
```

برای استقرار پروداکشن [docs/DEPLOY.md](docs/DEPLOY.md) و برای تهدیدمدل و سخت‌سازی
[docs/SECURITY.md](docs/SECURITY.md) را ببین.

---

## وضعیت

**پیاده‌شده و تست‌شده** (همه‌ی پکیج‌ها `go test` را پاس می‌کنند؛ پکیج‌های حساس به
همزمانی `-race` را هم):

- هسته‌ی کریپتو (X25519 / AEAD / HKDF / پنجره‌ی replay / authenticator سبک REALITY)
- پروتکل Rahro + مالتی‌پلکسر استریم با کنترل جریان
- ترنسپورت TLS با fallback به decoy (سبک REALITY)، اثرانگشت uTLS، ترنسپورت
  WebSocket، padding طول فریم
- اینباندهای کلاینت (SOCKS5، پراکسی HTTP/HTTPS) + egress سرور، اثبات‌شده end-to-end
- پنل: دیتابیس SQLite، API ادمین، SPA، CLI، endpoint سابسکریپشن
- کنترل‌پلین نود + enrollment با کد اتصال؛ مسیر دیتای رله‌ی تانل ایران
  (کاربر → نود تانل → تونل Rahro → egress لوکیشن → مقصد)، اثبات‌شده e2e
- API ربات تلگرام (با توکن): ساخت/تمدید کاربر، مصرف، نودها

**نقشه‌ی راه / هنوز پیاده نشده (محدودیت‌های صادقانه):**

- **اینباندهای استاندارد برای کلاینت‌های آماده (VLESS / Trojan / Shadowsocks).**
  امروز ingress کاربرِ یک نود تانل یک **پراکسی SOCKS5/HTTP** است که روی تونل Rahro
  رله می‌شود، و مسیر کاملاً native همان پروتکل Rahro است. پیاده‌سازی پروتکل‌های
  VLESS/Trojan/SS روی سیم تا کلاینت‌های دست‌نخورده‌ی v2rayNG/sing-box مستقیم وصل
  شوند، مرحله‌ی بعدی است؛ تا آن‌موقع خطوط `vless://` در سابسکریپشن placeholder برای
  همین یکپارچه‌سازی‌اند و مسیر کاری کاربر، پراکسی محلی SOCKS5/HTTP (یا اپ کلاینت
  آینده‌ی Rahro) است.
- **REALITY کامل** (جاسازی key-share در ClientHello + فوروارد خام TCP که گواهی واقعی
  decoy را حفظ کند) — ببینید docs/SECURITY.md. فعلاً برای نودهای روبه‌کاربر
  `tls_mode: domain` را برای گواهی معتبر استفاده کن.
- ترنسپورت‌های **gRPC / QUIC** — لایه‌ی ترنسپورت قابل افزودن است؛ TLS و WebSocket
  همین الان هستند.
- **اپ GUI / موبایل** کلاینت.

این‌ها صریحاً ذکر شده‌اند تا هیچ‌چیز اغراق نشود: تونل، استتار، پنل، نودها، enrollment،
مسیر رله‌ی ایران و API ربات همگی واقعی و تست‌شده‌اند؛ فرانت‌اندهای پروتکلِ
کلاینت‌های آماده، کار باقی‌مانده‌اند.
