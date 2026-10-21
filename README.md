# Rahro — DPI-resistant tunnel + management panel

<p align="center"><b>English</b> · <a href="README.fa.md">فارسی 🇮🇷</a></p>

![Rahro panel — dashboard](docs/assets/dashboard.png)

**Rahro** (رهرو, "wayfarer") is a censorship-circumvention tunnel with a web
panel, built for networks that use Deep Packet Inspection (DPI) and active
probing. It runs on **Linux and Windows servers**, manages **users, inbounds,
nodes and tunnels from one panel**, supports **multi-location subscriptions**,
and lets an Iran relay reach a foreign server over an obfuscated channel that
looks like ordinary HTTPS.

> **فارسی:** Rahro یک تونل ضدِ DPI با پنل وب است. روی سرور خارج نصب می‌شود،
> می‌توانی نودهای چندلوکیشنی و «نود تانل» (رله‌ی ایران) اضافه کنی، کاربرها و
> اینباندها را از یک پنل مدیریت کنی، و به ربات فروش تلگرام با توکن API وصلش کنی.
> نصب یک‌خطی پایین آمده است.

> **Honest scope:** no tool is "unbreakable." Rahro raises the cost of detection
> so that blocking it means blocking normal HTTPS. It cannot defeat a full
> internet shutdown. It uses only vetted cryptography (X25519 / ChaCha20-Poly1305
> / HKDF, TLS 1.3) — no bespoke crypto. See [docs/SECURITY.md](docs/SECURITY.md).

---

## How it works

```
        ┌──────── MAIN PANEL (foreign VPS) ────────┐
        │ users · inbounds · nodes · tunnels · subs │
        └───┬───────────────────────────────┬───────┘
     control (enroll code + secret)          │
            │                                 │
   ┌────────▼ LOCATION NODES (egress) ──┐     │ Rahro tunnel (looks like HTTPS)
   │  NL · TR · DE …  multi-location subs│     │
   └─────────────────────────────────────┘     │
                              ┌─────────────────▼ TUNNEL NODE (Iran relay) ─┐
   user in Iran ─► domestic IP│ serves standard inbounds and/or Rahro, then │
   (low latency, not blocked) │ relays out over the Rahro tunnel            │
                              └──────────────────────────────────────────────┘
```

- **REALITY-style defense:** a client proves it knows the server's X25519 key;
  anyone who doesn't (a browser, a censor's prober) is transparently proxied to
  a real **decoy** site, so probing learns nothing.
- **Obfuscation:** TLS 1.3 with a real browser ClientHello (uTLS), frame-length
  padding, and multiplexing many streams over one connection.
- **Transports:** TLS (default) and WebSocket (CDN-friendly); more are pluggable.

Full design: [docs/DESIGN.md](docs/DESIGN.md).

---

## 1. Install the panel (foreign server)

One line, as root, on Ubuntu/Debian/CentOS:

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh)
```

It builds Rahro (installing Go if needed), writes `/etc/rahro/panel.json`,
creates an admin, and starts the `rahro-panel` systemd service. At the end it
prints your **panel URL** and **admin credentials**.

Open the panel in a browser:

- `https://<server-ip>:2053` — self-signed TLS (default; accept the warning), **or**
- `http://<server-ip>:2053` — set `"tls_mode": "off"`, **or**
- `https://panel.example.com:2053` — set `"tls_mode": "domain"` + `"domain"` for a free Let's Encrypt cert.

Edit `/etc/rahro/panel.json` then `systemctl restart rahro-panel`.

**Windows Server** (PowerShell as Administrator, Go installed):

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

## 2. Add nodes (locations) and Iran tunnels

In the panel → **Nodes** → *Add location node* (or **Tunnel nodes** → *Add
tunnel node*). You get a **connection code**. On that server, run:

```bash
# Foreign egress location (adds a location to every subscription):
sudo bash <(curl -sL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh) \
  node <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure

# Iran relay (tunnels to the panel/upstream over the Rahro tunnel):
sudo bash <(curl -sL .../install.sh) \
  tunnel <CONNECTION-CODE> -panel https://<panel-ip>:2053 -insecure
```

`-insecure` skips TLS verification of the panel (needed when the panel uses a
self-signed cert / an IP). Drop it when the panel has a real domain cert.

The node enrolls over its secret, pulls its config, and starts as a systemd
service (`journalctl -u rahro-node -f`).

---

## 3. Create users & share subscriptions

Panel → **Users** → *Add user* (set quota in GB and days). Each user gets **one
subscription link that lists every enabled location**:

```
https://<panel>/sub/<token>
```

Paste it into v2rayNG / NekoBox / sing-box / Clash-Meta. Quotas and expiry are
enforced centrally; "copy" in the Users table copies the link.

---

## 4. Connect a Telegram sales bot (API token)

Panel → **API tokens** → *Create token* (shown once). Your bot calls the panel
with `Authorization: Bearer <token>`:

```bash
# Create a user for a sale (50 GB, 30 days) — returns the subscription link:
curl -s https://<panel>/botapi/users \
  -H "Authorization: Bearer rahro_xxx" \
  -d '{"username":"buyer1","quota_gb":50,"days":30}'

# Look up a user + usage:
curl -s https://<panel>/botapi/users/<uuid> -H "Authorization: Bearer rahro_xxx"

# Renew / top up (add days & GB, optionally reset usage):
curl -s https://<panel>/botapi/users/<uuid>/renew \
  -H "Authorization: Bearer rahro_xxx" \
  -d '{"add_days":30,"add_gb":50,"reset_usage":true}'

# List locations the sale covers:
curl -s https://<panel>/botapi/nodes -H "Authorization: Bearer rahro_xxx"
```

The create/renew responses include `sub_link`, so the bot can send it straight
to the customer.

---

## CLI

```bash
rahro-panel run        -config /etc/rahro/panel.json   # run the panel (service does this)
rahro-panel admin create -u admin -p 'pass'            # create / reset admin
rahro-panel admin passwd -u admin -p 'newpass'
rahro-panel token create -name telegram-bot            # mint an API token
rahro-server -genkey                                   # generate an X25519 keypair
rahro-node   enroll <code> -panel https://panel:2053   # enroll a node
rahro-node   run                                       # run an enrolled node
```

---

## Build from source

```bash
git clone https://github.com/AwmiresGg/rahro-tunnel && cd rahro-tunnel
make build      # all binaries into ./ (go build ./...)
make test       # full test suite
make race       # tests under the race detector
make dist       # cross-compiled Linux (amd64/arm64) + Windows binaries into ./dist
```

Requires Go 1.26+. Everything is pure Go (CGO disabled), so it cross-compiles
cleanly to Linux and Windows.

---

## Configuration reference (`panel.json`)

```jsonc
{
  "log_level": "info",                 // debug|info|warn|error
  "panel": {
    "enabled": true,
    "listen": "0.0.0.0:2053",
    "tls_mode": "self-signed",         // off | self-signed | domain
    "domain": "panel.example.com",     // required when tls_mode = domain
    "db_path": "/etc/rahro/rahro-panel.db",
    "public_url": "https://1.2.3.4:2053", // used to build subscription links
    "base_path": "/x7f3a9"             // optional secret path prefix
  }
}
```

See [docs/DEPLOY.md](docs/DEPLOY.md) for production deployment and
[docs/SECURITY.md](docs/SECURITY.md) for the threat model and hardening.

---

## Status

**Implemented and tested** (all packages pass `go test`; concurrency-sensitive
ones pass `-race`):

- Crypto core (X25519 / AEAD / HKDF / replay window / REALITY-style authenticator)
- Rahro protocol + stream multiplexer with flow control
- TLS transport with REALITY-style probe → decoy fallback, uTLS fingerprinting,
  WebSocket transport, frame-length padding
- Client inbounds (SOCKS5, HTTP/HTTPS proxy) + server egress, proven end-to-end
- Panel: SQLite store, admin API, SPA, CLI, subscription endpoint
- Node control plane + connection-code enrollment; Iran tunnel-relay data path
  (user → tunnel node → Rahro tunnel → location egress → origin), proven e2e
- Telegram bot API (token auth): create/renew users, usage, nodes

**Roadmap / not yet implemented (honest limitations):**

- **Stock-client standard inbounds (VLESS / Trojan / Shadowsocks).** Today a
  tunnel node's user ingress is a **SOCKS5/HTTP proxy** relayed over the Rahro
  tunnel, and the fully-native path is the Rahro protocol. Implementing the
  VLESS/Trojan/SS wire protocols so unmodified v2rayNG/sing-box clients connect
  directly is the next milestone; until then the `vless://` lines in a
  subscription are placeholders for that integration, and the working user path
  is the local SOCKS5/HTTP proxy (or a future Rahro client app).
- **Full REALITY** (ClientHello key-share embedding + raw-TCP decoy forwarding
  that preserves the decoy's real certificate) — see docs/SECURITY.md. Use
  `tls_mode: domain` on user-facing nodes for a trusted cert in the meantime.
- **gRPC / QUIC transports** — the transport layer is pluggable; TLS and
  WebSocket ship now.
- Client **GUI / mobile apps**.

These are called out so nothing here is oversold: the tunnel, obfuscation,
panel, nodes, enrollment, Iran relay path, and bot API are real and tested; the
stock-client protocol front-ends are the remaining work.
