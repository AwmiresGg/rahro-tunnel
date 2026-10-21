# Deploying Rahro

## Topology

1. **Main panel** on a foreign VPS (Germany, Netherlands, …). It is the control
   plane and can also egress.
2. **Location nodes** — more foreign VPSes for multi-location subscriptions.
3. **Tunnel nodes** — Iran servers that serve users on a domestic IP and relay
   to a foreign node over the Rahro tunnel.

## Panel

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh)
```

Then set, in `/etc/rahro/panel.json`:

- `public_url` — the exact URL users/bots reach the panel at. Subscription links
  are built from it, so get this right (domain or public IP + port).
- `tls_mode`:
  - `self-signed` (default) — HTTPS on the IP, browser warning on first visit.
  - `off` — plain HTTP (put it behind your own TLS/an SSH tunnel; don't expose raw).
  - `domain` — point a DNS A record at the server, open :80 and :443, set
    `"domain"`; Rahro fetches a Let's Encrypt cert automatically.

`systemctl restart rahro-panel` after edits. Create/rotate the admin with
`rahro-panel admin create|passwd`.

### Firewall

- Panel port (default `2053/tcp`) — restrict to your IP where possible.
- Location nodes: `443/tcp` (tunnel) open to the world.
- Domain mode also needs `80/tcp` (ACME) + `443/tcp` on the panel host.

## Nodes

Create the node in the panel to get a connection code, then on the node server:

```bash
# foreign egress
sudo bash <(curl -sL .../scripts/install.sh) node   <code> -panel https://PANEL:2053 -insecure
# Iran relay
sudo bash <(curl -sL .../scripts/install.sh) tunnel <code> -panel https://PANEL:2053 -insecure
```

Each node runs as the `rahro-node` systemd service. Check it with
`systemctl status rahro-node` and `journalctl -u rahro-node -f`.

## Windows Server

Install Go, then from an elevated PowerShell:

```powershell
irm https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.ps1 | iex
```

Services are registered as `RahroPanel` / `RahroNode` (manage with
`Get-Service`, `Restart-Service`).

## Docker

```bash
docker compose up -d --build
docker compose exec panel rahro-panel admin create -config /data/panel.json -u admin -p 'PASS'
```

Config and the SQLite DB live in `./data`. `network_mode: host` lets the panel
bind low ports and see real client IPs.

## Backups

Back up `/etc/rahro/` (the SQLite DB + config). The panel's Rahro server key is
stored in the DB; losing it invalidates every node and client, so keep backups.

## Upgrades

Re-run the installer (it rebuilds and restarts the service) or, from a clone,
`git pull && make build && sudo systemctl restart rahro-panel`.
