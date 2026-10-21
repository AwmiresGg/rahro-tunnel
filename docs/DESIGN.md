# Rahro — Design Document

> **Rahro** (رهرو, "wayfarer") is a censorship-circumvention tunnel designed to
> carry traffic through networks that deploy Deep Packet Inspection (DPI),
> active probing, and aggressive blocking. It is built to interoperate with the
> management panels people already run (3x-ui / Xray, Pasargard) and to be easy
> to operate while being hard to detect and block.

This document is the single source of truth for the architecture. It is written
**before** the code so that every component below has a clear contract, a threat
rationale, and a test plan. We build it piece by piece; each milestone has an
explicit "done when" definition.

---

## 0. Honest framing & scope

**What this is.** A privacy / anti-censorship tool. Its purpose is to let users
in heavily-filtered networks reach the open internet. This is the same category
of tool as Xray (VLESS/REALITY/Trojan), sing-box, Shadowsocks, and Tor's
pluggable transports (obfs4, meek, Snowflake). Circumventing censorship to reach
information is a legitimate, widely-recognized use.

**What it is NOT, and cannot be.**

- It is **not** "unbreakable in wartime." Censorship circumvention is a
  continuous cat-and-mouse game. A censor with enough resources can always
  *degrade* a connection (throttling, total internet shutdowns, allow-listing).
  Our realistic goal is to **raise the cost and difficulty of detection** so that
  blocking us has unacceptable collateral damage (i.e. we look enough like normal
  HTTPS that blocking us means blocking normal web traffic).
- It does **not** rely on hand-written assembly or "layer 1" tricks. DPI inspects
  *traffic on the wire*, not the machine code of your binary, so the
  implementation language is irrelevant to detectability. Detectability is a
  function of protocol design, cryptography, and traffic shape — that is where
  all our effort goes. (Performance-critical crypto uses the Go standard
  library's vetted, hardware-accelerated primitives — never bespoke crypto.)

**Non-goals.**
- We do not implement our own cryptographic primitives.
- We do not provide anonymity against a global passive adversary (that is Tor's
  job, with a very different design). We provide *unobservability of purpose* and
  *resistance to blocking* against a network-level censor.
- We do not help attack, DoS, or compromise any third party. This is strictly a
  client↔your-own-server tunnel.

---

## 1. Threat model

The adversary is a **national / ISP-level network censor** sitting on the path
between the user and our server. We assume it can:

| Capability | Adversary can… | Our defense |
|---|---|---|
| **Passive DPI** | Read every byte of every packet, match signatures, fingerprint TLS ClientHello (JA3/JA4), flag non-standard handshakes | Tunnel inside a *real* TLS 1.3 session; mimic a popular browser's TLS fingerprint (uTLS); no plaintext protocol markers |
| **Active probing** | Connect to our server itself and send probes to see if it "behaves like a VPN" | REALITY-style: steal the handshake of a real decoy site; unauthenticated clients get proxied to a real website and see a genuine response |
| **Statistical / flow analysis** | Measure packet sizes, inter-arrival timing, flow duration, up/down ratio | Length padding to common distributions; optional timing jitter; multiplexing many logical streams over one TLS flow |
| **SNI / endpoint blocking** | Block by destination IP, by SNI, by cert | Pluggable transports (WebSocket/gRPC/HTTP2/QUIC); optional CDN fronting; SNI set to a plausible allowed domain |
| **Protocol allow-listing** | Permit only TLS/443 (+ maybe QUIC/443) | Default transport *is* TLS/443 and QUIC/443 — indistinguishable from HTTPS/HTTP3 |
| **Throttling** | Slow down suspected circumvention flows | Nothing fully defeats this; we minimize distinguishability so there's nothing specific to throttle. Multi-path/transport failover helps |
| **Total shutdown** | Cut the internet entirely | Out of scope — no on-path tool can defeat a full shutdown |

**Trust assumptions.**
- The user controls both ends: the client device and the server (a VPS they rent).
- The server's private keys are secret. If the server is seized, past traffic is
  protected by forward secrecy (ephemeral X25519 per session).
- We do **not** trust the network between them at all.

---

## 2. High-level architecture

```
          ┌────────────────────────────────────────────────────────────┐
          │                        USER DEVICE                          │
          │                                                             │
          │   apps ──► local inbound (SOCKS5 / HTTP / tun)              │
          │                     │                                       │
          │                     ▼                                       │
          │             rahro client core                               │
          │        (session mux + obfuscation)                          │
          └─────────────────────┬───────────────────────────────────────┘
                                │  looks like ordinary HTTPS / HTTP3
                                │  (TLS1.3 on :443, QUIC on :443)
             ~~~~ hostile network w/ DPI + active probing ~~~~
                                │
          ┌─────────────────────▼───────────────────────────────────────┐
          │                      YOUR SERVER (VPS)                       │
          │                                                             │
          │   rahro server  ──► authenticated?                          │
          │        │              ├─ yes ─► decrypt, mux-demux ─► egress │
          │        │              └─ no  ─► reverse-proxy to a REAL      │
          │        │                        decoy website (fallback)     │
          │        ▼                                                     │
          │   web panel (admin API + UI, users, configs, metrics)       │
          └─────────────────────────────────────────────────────────────┘
```

### Component inventory
1. **`core/transport`** — pluggable transports (TLS, WebSocket, gRPC, HTTP/2, QUIC). Each turns a hostile network into a reliable byte stream that looks like benign traffic.
2. **`core/obfs`** — the handshake authenticator (REALITY-style), length padding, and timing shaping.
3. **`core/mux`** — multiplexes many logical connections over one transport flow (reduces the number of TLS sessions → less fingerprintable, better perf).
4. **`core/crypto`** — thin wrappers over Go stdlib: X25519 key agreement, ChaCha20-Poly1305 / AES-128-GCM AEAD, HKDF. **No custom primitives.**
5. **`core/proto`** — the Rahro wire framing (the "new dedicated method"): session establishment, stream frames, flow control.
6. **`client`** — local inbounds (SOCKS5, HTTP proxy, and later TUN), config, failover between transports.
7. **`server`** — accepts transports, authenticates, demuxes, egresses to the real internet, and runs the **fallback decoy** for unauthenticated/probing connections.
8. **`panel`** — web admin: user CRUD, per-user keys & quotas, live config generation (incl. share links/QR), metrics, and a compatibility exporter for 3x-ui / Pasargard.

---

## 3. The Rahro protocol (the "dedicated method")

The core idea borrows the proven ideas from REALITY + VLESS + modern AEAD and
combines them with mandatory padding and mux. It is NOT a from-scratch crypto
protocol; it is a *composition* of vetted pieces.

### 3.1 Why it resists DPI and active probing
- **To passive DPI**, a Rahro connection is a normal TLS 1.3 session to port 443.
  The ClientHello carries a real browser fingerprint (via uTLS). There is no
  Rahro-specific byte visible in cleartext — the authenticator is hidden *inside*
  fields that are already random-looking in TLS 1.3 (the client key share /
  session id), exactly like REALITY.
- **To an active prober**, the server only reveals "I am Rahro" to a client that
  proves knowledge of the server's public key via an authenticator the prober
  cannot forge. Everyone else — including the censor's probe — is transparently
  reverse-proxied to a **real decoy website** (e.g. a real `www.example.com`), so
  the probe sees a genuine site with a genuine certificate and learns nothing.

### 3.2 Handshake (conceptual)

```
Client                                             Server
  │  TLS1.3 ClientHello (browser-mimicked via uTLS)   │
  │  key_share = X25519 ephemeral  E_c                │
  │  + embedded authenticator  A = AEAD_seal(         │
  │        key = HKDF(X25519(e_c, S_pub)),            │
  │        nonce = f(ClientHello),                     │
  │        plaintext = {proto_ver, user_id, ts, nonce})│
  │ ────────────────────────────────────────────────► │
  │                                                    │  derive shared secret with server static key S_priv:
  │                                                    │  ss = X25519(S_priv, E_c)
  │                                                    │  try AEAD_open(A). 
  │                                                    │   ├─ ok  → this is a real Rahro client:
  │                                                    │   │        complete TLS as the tunnel, switch to data plane
  │                                                    │   └─ fail → treat as ordinary visitor:
  │                                                    │            proxy the whole TCP stream to the DECOY site
  │ ◄──────────────────────────────────────────────── │
```

- `S_pub / S_priv`: server's long-term X25519 keypair. `S_pub` is distributed to
  clients (it's in the config/share-link). `S_priv` never leaves the server.
- `ts` (timestamp) + replay cache defeat replay probing (reject stale or
  duplicate authenticators within a window).
- Forward secrecy comes from the ephemeral `E_c` plus the TLS 1.3 session keys.

### 3.3 Data plane framing
Once authenticated, both sides speak the Rahro frame format over the AEAD-secured
channel (which itself rides inside the TLS record layer):

```
RahroFrame:
  ┌───────────┬───────────┬──────────────┬───────────────┬──────────┐
  │ stream_id │  type (1) │  length (2)  │   payload     │ padding  │
  │   (4,var) │           │              │   (length)    │  (var)   │
  └───────────┴───────────┴──────────────┴───────────────┴──────────┘
  types: SYN, DATA, WND_UPDATE, FIN, RST, PING (keepalive/timing-cover)
```
- **Padding is mandatory** and sized so the *encrypted record length* lands on a
  distribution resembling real HTTPS (small control frames padded up; large
  transfers chunked to typical MTU-ish sizes). This breaks naive length-based
  classifiers.
- **Mux**: many `stream_id`s share one transport flow with per-stream flow
  control (sliding window). Fewer TLS sessions = fewer handshakes to fingerprint
  and lower latency for new app connections.

### 3.4 Transports (pluggable)
All transports present the *same* authenticated byte stream to the layers above;
they differ only in what they look like on the wire:
- **`tls`** (default): raw TLS 1.3 to :443. Lowest overhead, looks like HTTPS.
- **`ws`**: WebSocket over TLS — survives many CDNs, enables domain fronting.
- **`grpc`**: gRPC over HTTP/2 — looks like a normal API, multiplexing-friendly.
- **`h2`**: raw HTTP/2 streams.
- **`quic`**: QUIC/HTTP3 to :443/udp — looks like HTTP3, good on lossy mobile links.

Client does **failover**: try the primary transport; on failure or active
blocking, rotate to the next. Config can pin an order per region.

---

## 4. Cryptography (what we actually use)

| Purpose | Primitive | Source |
|---|---|---|
| Key agreement | X25519 (ephemeral + static) | `crypto/ecdh` (stdlib) |
| AEAD | ChaCha20-Poly1305 (default), AES-128-GCM (when HW AES available) | `golang.org/x/crypto/chacha20poly1305`, `crypto/aes` |
| KDF | HKDF-SHA256 | `golang.org/x/crypto/hkdf` |
| TLS | TLS 1.3 with browser-mimicked ClientHello | `crypto/tls` + `utls` |
| Randomness | CSPRNG | `crypto/rand` |

Rules: no nonce reuse (counter + random prefix per session), constant-time
comparisons for the authenticator tag, keys zeroized where practical, replay
window with monotonic timestamp + seen-cache.

---

## 5. Web panel (3x-ui-style single binary)

Architecture mirrors the tool family the user already runs (3x-ui is a single Go
binary that embeds a web SPA; Smite is FastAPI + React + Docker). We follow the
**3x-ui model**: one self-contained Go binary that embeds the compiled SPA and
serves both the API and the UI. This keeps deployment to "drop one binary, run
the install script" on **both Linux Server and Windows Server**.

- **Backend**: Go HTTP server (`gin` or stdlib `net/http`) in the same binary as
  (or a sidecar to) the tunnel server. SQLite by default (zero external deps,
  survives restarts) via a pure-Go driver (`modernc.org/sqlite`, so no cgo →
  trivial cross-compile to Windows). Optional Postgres later.
- **Reachability (as requested):** the panel is configurable to come up in a
  browser in all of these ways, chosen at install/config time:
  - **IP + self-signed TLS**: `https://<server-ip>:<port>` with an auto-generated
    self-signed cert (browser warning accepted) — works with no domain.
  - **IP over plain HTTP**: `http://<server-ip>:<port>` for quick setup / LAN.
  - **Domain + real TLS**: `https://panel.example.com:<port>` with an automatic
    Let's Encrypt cert (ACME) or a user-supplied cert/key.
  - Panel **port is configurable** (like 3x-ui's panel port), with a random
    secret path prefix option to reduce scanning.
- **AuthN/Z**: admin login (argon2id password hash), session cookies + CSRF,
  optional TOTP 2FA. Rate-limited login. First-run creates an admin (CLI:
  `rahro admin create`, mirroring `smite admin create`).
- **Features**:
  - User management: create/disable users, per-user X25519 identity, quotas
    (traffic cap, expiry date), concurrent-connection limits.
  - Config/share-link generation + QR, per transport.
  - Live metrics: active sessions, throughput, per-user usage, transport health.
  - **Compatibility exporters** so it slots into existing workflows:
    - import/export users to/from **3x-ui** (Xray inbound JSON),
    - export **Pasargard**-compatible subscription links.
- **Frontend**: a full **SPA (React + TypeScript + Vite)**, built to static
  assets and embedded into the Go binary with `go:embed`. Dark/light theme,
  responsive, i18n-ready (English + Persian).
- **CLI** (`rahro` on Linux, `rahro.exe` on Windows): `admin create/update`,
  `status`, `restart`, `update`, `logs` — modeled on the Smite CLI the user knows.
- **Install**: one-line bash installer for Linux
  (`bash -c "$(curl -sL …/install.sh)"`, like Smite/3x-ui) that fetches the
  binary, writes a config, installs a `systemd` unit, and prints the panel URL +
  admin credentials. On Windows Server, a PowerShell installer that registers a
  Windows **Service** (via `sc.exe` / NSSM or Go's `svc` package).

---

## 6. Interop with 3x-ui and Pasargard

Rahro does **not** try to replace these panels; it complements them.
- **Phase A (fast win):** ship Rahro's transports/obfs as an *additional inbound*
  that 3x-ui/Xray users can point to, plus a subscription exporter that produces
  links their existing clients understand where protocols overlap (VLESS/Trojan
  over our transports).
- **Phase B:** native Rahro protocol client + the panel's own exporter so a user
  managing things in 3x-ui or Pasargard can mint Rahro configs without leaving
  their panel.

The exact mapping is pinned down in `docs/INTEROP.md` during the interop
milestone (M6), after the core protocol is stable.

---

## 7. Build roadmap (piece by piece, each independently tested)

Each milestone is small, compiles, and ships with tests before we move on.

| # | Milestone | Done when |
|---|---|---|
| **M0** | Repo skeleton: go.mod, module layout, CI-style `make test`, logging, config loader | `go build ./...` and `go test ./...` pass on an empty-but-wired tree |
| **M1** | `core/crypto`: X25519 handshake keys, AEAD seal/open, HKDF, replay window | Unit tests: round-trip seal/open, tamper detection, replay rejection, KAT vectors |
| **M2** | `core/proto`: Rahro frame codec + mux with flow control | Fuzz/round-trip tests: encode→decode identity, interleaved streams, backpressure |
| **M3** | `core/transport/tls` + server fallback decoy | Integration test: real client authenticates & echoes data; a *wrong* client gets proxied to the decoy and sees the decoy's response |
| **M4** | `client` SOCKS5 inbound + `server` egress, end-to-end over loopback | `curl --socks5 ... https://example.invalid-local` flows through tunnel in a local 2-process test |
| **M5** | Padding + timing shaping; uTLS browser fingerprint; additional transports (ws, grpc, quic) | Tests assert ClientHello matches a target JA3; length distribution tests; each transport passes the M4 e2e test |
| **M6** | Web panel (users, quotas, configs, metrics) + 3x-ui/Pasargard exporters | Panel CRUD + auth tests; exporter golden-file tests; manual smoke of the UI |
| **M7** | Hardening: load test, memory/leak checks, docs, deployment (systemd + container), ops runbook | Soak test stable; `docs/DEPLOY.md` + `docs/SECURITY.md` complete |

We are at **M0 next**.

---

## 8. Repository layout (target)

```
rahro/
├── go.mod
├── Makefile
├── cmd/
│   ├── rahro-server/      # server entrypoint
│   ├── rahro-client/      # client entrypoint
│   └── rahro-panel/       # panel entrypoint (may merge into server)
├── core/
│   ├── crypto/            # M1
│   ├── proto/             # M2 (framing + mux)
│   ├── transport/         # M3, M5 (tls, ws, grpc, h2, quic)
│   └── obfs/              # M5 (padding, timing, uTLS)
├── client/                # M4
├── server/                # M3/M4 (incl. fallback decoy)
├── panel/                 # M6 (api + ui + exporters)
├── internal/
│   ├── config/            # M0 config loader
│   └── logx/              # M0 logging
└── docs/
    ├── DESIGN.md          # this file
    ├── INTEROP.md         # M6
    ├── DEPLOY.md          # M7
    └── SECURITY.md        # M7
```

---

## 9. Testing philosophy

- **Every milestone gates on `go test ./...`** before we move on. The user asked
  for "piece by piece, test it, fix the problems" — this is how we honor that.
- Unit tests for crypto and codecs; integration tests spin up real
  client+server over loopback; golden-file tests for exporters.
- Where behavior faces the network adversary (fingerprint, padding), we write
  tests that *assert the observable property* (e.g. "ClientHello JA3 == target",
  "control frame ciphertext length ∈ expected set").
- No milestone is "done" on my say-so; it's done when its tests pass and I show
  you the output.

---

## 10. Resolved decisions (settled with the user)
1. **Server platforms**: the Rahro **server + panel run on both Linux Server and
   Windows Server**. We use pure-Go deps (no cgo) so one codebase cross-compiles
   to both. The end-user *client* (what connects through the tunnel) targets
   Linux/Windows/macOS CLI first; mobile is a later, separate effort.
2. **Decoy strategy**: **REALITY-style** — the server borrows the TLS handshake
   of a real decoy site; unauthenticated/probing connections are transparently
   proxied there. (Choosing the specific decoy "steal target" is a config value,
   decided during M3.)
3. **Panel**: full **SPA (React + TypeScript + Vite)** embedded in the Go binary,
   reachable via IP+self-signed TLS, IP over HTTP, or domain+Let's Encrypt, on a
   configurable port — with a **one-line install script** (bash on Linux,
   PowerShell/Service on Windows) in the style of the Smite / 3x-ui panels.

### Reference: the user's Smite panel (for style/UX parity)
`awmiresgg/smite` is the user's existing tunnel panel: FastAPI + React/TS +
Docker + Nginx + SQLite, with a one-line installer, a `smite` CLI, dual-node
(Iran/Foreign) reverse-tunnel architecture, and a Telegram bot for stats/backups.
Rahro's panel should feel familiar to a Smite/3x-ui user: one-line install, clean
SPA, CLI parity (`rahro admin create`, `status`, `update`, `restart`, `logs`),
and (later) an optional Telegram bot for stats/backups.

These are all settled; none blocks M0–M2.
```
