#!/usr/bin/env bash
# Rahro one-line installer (Linux).
#
# Most compatible (works on every terminal — download then run):
#   curl -fsSL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh -o rahro-install.sh
#   sudo bash rahro-install.sh                 # panel
#   sudo bash rahro-install.sh node   <code> -panel https://PANEL:2053 -insecure
#   sudo bash rahro-install.sh tunnel <code> -panel https://PANEL:2053 -insecure
#
# Or pipe:  curl -fsSL .../install.sh | sudo bash
# (Avoid `bash <(curl ...)` — some mobile/SSH terminals fail with /dev/fd/63.)
#
# It builds Rahro from source (installing Go if needed), installs the binaries
# to /usr/local/bin, writes a config, and registers a systemd service.
set -euo pipefail

REPO="${RAHRO_REPO:-https://github.com/AwmiresGg/rahro-tunnel}"
REF="${RAHRO_REF:-HEAD}"
PREFIX="/usr/local/bin"
ETC="/etc/rahro"
GO_FALLBACK="go1.27.3"   # used only if go.dev/VERSION can't be queried

c_green='\033[0;32m'; c_cyan='\033[0;36m'; c_red='\033[0;31m'; c_reset='\033[0m'
info(){ echo -e "${c_cyan}==>${c_reset} $*"; }
ok(){ echo -e "${c_green}✓${c_reset} $*"; }
die(){ echo -e "${c_red}✗ $*${c_reset}" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "please run as root (sudo)"

ARCH="$(uname -m)"; case "$ARCH" in
  x86_64|amd64) GOARCH=amd64;;
  aarch64|arm64) GOARCH=arm64;;
  *) die "unsupported arch: $ARCH";;
esac

ensure_go(){
  if command -v go >/dev/null 2>&1; then GO=go; return; fi
  if [ -x /usr/local/go/bin/go ]; then GO=/usr/local/go/bin/go; export PATH="/usr/local/go/bin:$PATH"; return; fi
  # Use the current stable Go so the download always exists on the CDN.
  local gv; gv="$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1)"
  case "$gv" in go*) ;; *) gv="$GO_FALLBACK";; esac
  info "installing ${gv}"
  local tgz="${gv}.linux-${GOARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tgz}" -o "/tmp/${tgz}" || die "download Go failed (${tgz}); retry, or install Go manually from https://go.dev/dl/ and re-run"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${tgz}" || die "extract Go failed"
  export PATH="/usr/local/go/bin:$PATH"
  GO=/usr/local/go/bin/go
  ok "Go installed (${gv})"
}

fetch_src(){
  # If we are already inside a Rahro checkout (e.g. you cloned a PRIVATE repo
  # and ran this script from it), build from here — no network fetch needed.
  if [ -f go.mod ] && grep -q 'module github.com/awmiresgg/rahro' go.mod 2>/dev/null; then
    SRC="$PWD"; info "building from local checkout ($SRC)"; return
  fi
  SRC="$(mktemp -d)"
  info "fetching source ($REPO@$REF)"
  local url="$REPO"
  # For a private repo, export RAHRO_TOKEN=<github PAT> before running.
  if [ -n "${RAHRO_TOKEN:-}" ]; then
    url="https://${RAHRO_TOKEN}@${REPO#https://}"
  fi
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 "$url" "$SRC" >/dev/null 2>&1 \
      || die "git clone failed. If the repo is private: clone it manually with a GitHub token and re-run 'sudo bash scripts/install.sh' from inside it, or set RAHRO_TOKEN=<token>."
  else
    curl -fsSL "${url}/archive/${REF}.tar.gz" | tar -xz -C "$SRC" --strip-components=1 \
      || die "tarball fetch failed (private repo? see the README's private-repo install)"
  fi
}

build(){
  info "building $1"
  ( cd "$SRC" && CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o "$PREFIX/$1" "./cmd/$1" ) || die "build $1 failed"
  ok "installed $PREFIX/$1"
}

install_panel(){
  ensure_go; fetch_src; build rahro-panel
  mkdir -p "$ETC"
  local cfg="$ETC/panel.json"
  local ip; ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  if [ ! -f "$cfg" ]; then
    cat > "$cfg" <<EOF
{
  "log_level": "info",
  "panel": {
    "enabled": true,
    "listen": "0.0.0.0:2053",
    "tls_mode": "self-signed",
    "db_path": "$ETC/rahro-panel.db",
    "public_url": "https://${ip}:2053"
  }
}
EOF
    ok "wrote $cfg"
  fi

  local user="admin" pass; pass="$(head -c9 /dev/urandom | base64 | tr -d '/+=' | head -c12)"
  "$PREFIX/rahro-panel" admin create -config "$cfg" -u "$user" -p "$pass" 2>/dev/null \
    && ok "admin created" || info "admin already exists (skipping)"

  cat > /etc/systemd/system/rahro-panel.service <<EOF
[Unit]
Description=Rahro Panel
After=network.target
[Service]
ExecStart=$PREFIX/rahro-panel run -config $cfg
Restart=always
RestartSec=3
WorkingDirectory=$ETC
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now rahro-panel >/dev/null 2>&1 || true

  echo
  ok "Rahro panel is up."
  echo -e "   URL:      ${c_green}https://${ip}:2053${c_reset}  (self-signed cert — accept the browser warning)"
  echo -e "   Login:    ${c_green}${user}${c_reset} / ${c_green}${pass}${c_reset}"
  echo    "   Logs:     journalctl -u rahro-panel -f"
}

install_node(){
  local role="$1"; shift
  local code="${1:-}"; shift || true
  [ -n "$code" ] || die "usage: install.sh $role <connection-code> -panel <url> [-insecure]"
  ensure_go; fetch_src; build rahro-node
  mkdir -p "$ETC"
  info "enrolling node"
  ( cd "$ETC" && "$PREFIX/rahro-node" enroll "$code" "$@" -out "$ETC/node.json" ) || die "enrollment failed"

  cat > /etc/systemd/system/rahro-node.service <<EOF
[Unit]
Description=Rahro Node ($role)
After=network.target
[Service]
ExecStart=$PREFIX/rahro-node run -config $ETC/node.json
Restart=always
RestartSec=3
WorkingDirectory=$ETC
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now rahro-node >/dev/null 2>&1 || true
  ok "Rahro node ($role) enrolled and started. Logs: journalctl -u rahro-node -f"
}

case "${1:-panel}" in
  panel) install_panel;;
  node)  shift; install_node location "$@";;
  tunnel) shift; install_node tunnel "$@";;
  *) die "unknown mode '$1' (panel|node|tunnel)";;
esac
