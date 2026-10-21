# Security model

## What Rahro defends against

A **network-level censor** between the user and the server that can:

| Capability | Defense |
|---|---|
| Passive DPI / signature matching | Tunnel inside real TLS 1.3; no plaintext protocol markers |
| TLS fingerprinting (JA3/JA4) | uTLS presents a real browser ClientHello |
| Active probing | REALITY-style auth: an unauthenticated prober is proxied to a real decoy and learns nothing |
| Length/flow analysis | Mandatory frame-length padding + stream multiplexing |
| SNI / endpoint blocking | Pluggable transports (TLS, WebSocket); CDN-frontable WS |
| Replay of a captured handshake | Per-handshake nonce + timestamp replay window |

## What it does **not** do

- It is not anonymity against a global passive adversary (that is Tor's job).
- It cannot defeat a total internet shutdown or aggressive allow-listing.
- It is a continuous cat-and-mouse game; keep it updated.

## Cryptography

Only vetted primitives, no bespoke crypto:

- **X25519** key agreement (`crypto/ecdh`)
- **ChaCha20-Poly1305** (default) / **AES-256-GCM** AEAD
- **HKDF-SHA256** key derivation
- **TLS 1.3** transport; **uTLS** for fingerprint mimicry
- **argon2id** for admin passwords; API/subscription tokens are random and
  stored only as SHA-256 hashes

Forward secrecy comes from ephemeral X25519 per session plus TLS 1.3 session
keys. The handshake authenticator is bound to the server's public key, so a
wrong-key client (or prober) is routed to the decoy.

## Operational hardening

- Restrict the panel port to your IP; prefer `tls_mode: domain` with a real
  cert, or keep the panel on localhost and reach it over SSH.
- Use a `base_path` secret prefix to reduce drive-by scanning.
- Create a strong admin password; rotate API tokens; delete unused ones.
- Keep server keys backed up and secret (they live in the panel DB).
- Run nodes as the provided systemd service (non-interactive, auto-restart).

## Reporting

This is anti-censorship / privacy software. If you find a vulnerability, open a
private security advisory on the repository rather than a public issue.

## Staging notes (current limitations)

- The probe fallback currently detects **after** TLS termination and proxies at
  the application layer; full REALITY (ClientHello key_share embedding + raw-TCP
  forwarding that preserves the decoy's real certificate) is the next hardening
  step. Until then, use `tls_mode: domain` on user-facing nodes for a trusted
  certificate, or a real CDN in front of the WebSocket transport.
- Node control-plane auth uses a shared secret over TLS (not yet client-cert
  mTLS). Keep `-insecure` only for self-signed panels on trusted networks.
