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
  # Resolve the current stable Go version (fall back if go.dev is unreachable).
  local gv; gv="$(curl -fsSL --max-time 15 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1)"
  case "$gv" in go*) ;; *) gv="$GO_FALLBACK";; esac
  local tgz="${gv}.linux-${GOARCH}.tar.gz"
  info "installing ${gv}"
  # Try multiple official mirrors — some networks reach one but not another.
  local got=0 base
  for base in "https://go.dev/dl" "https://dl.google.com/go" "https://golang.google.cn/dl"; do
    if curl -fsSL --max-time 300 "$base/$tgz" -o "/tmp/$tgz" 2>/dev/null; then
      got=1; info "fetched Go from $base"; break
    fi
  done
  [ "$got" = 1 ] || die "could not download Go from any mirror. Install Go 1.26+ manually (https://go.dev/dl/) so 'go' is on PATH, then re-run this script."
  rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/$tgz" || die "extract Go failed"
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

# try_prebuilt downloads a ready-made binary from GitHub (no Go, no compile).
# This is the fast path and the only one that works where go.dev is blocked.
try_prebuilt(){ # $1 = binary name
  local name="$1"
  local url="https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/${REF}/bin/linux-${GOARCH}/${name}"
  info "downloading prebuilt ${name} (linux-${GOARCH})"
  if curl -fsSL --max-time 180 "$url" -o "$PREFIX/$name" 2>/dev/null && [ -s "$PREFIX/$name" ]; then
    chmod +x "$PREFIX/$name"
    ok "installed prebuilt $PREFIX/$name"
    return 0
  fi
  rm -f "$PREFIX/$name"
  return 1
}

# provide installs a binary: prebuilt from GitHub first, else build from source.
provide(){ # $1 = binary name
  if try_prebuilt "$1"; then return; fi
  info "prebuilt unavailable for linux-${GOARCH}; building from source"
  ensure_go; fetch_src; build "$1"
}

# setup_service installs and starts a systemd unit, degrading gracefully when
# systemd is unavailable (containers, minimal images). It never aborts.
setup_service(){ # $1=service name  $2=ExecStart command
  local name="$1" exec="$2"
  if [ -d /etc/systemd/system ]; then
    cat > "/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=Rahro ($name)
After=network.target
[Service]
ExecStart=$exec
Restart=always
RestartSec=3
WorkingDirectory=$ETC
[Install]
WantedBy=multi-user.target
EOF
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1; then
    systemctl enable "$name" >/dev/null 2>&1
    # restart (not just --now) so re-running the installer applies binary updates
    if systemctl restart "$name" >/dev/null 2>&1; then
      ok "service '$name' (re)started  (logs: journalctl -u $name -f)"
      return
    fi
  fi
  info "systemd not usable here — start it manually (or in your own supervisor):"
  echo "     $exec"
}

detect_ip(){
  local ip; ip="$(curl -fsSL --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$ip" ] || ip="YOUR_SERVER_IP"
  printf '%s' "$ip"
}

install_panel(){
  provide rahro-panel
  mkdir -p "$ETC"
  local cfg="$ETC/panel.json"
  local ip; ip="$(detect_ip)"
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

  local user="admin" pass created=0
  pass="$(head -c9 /dev/urandom | base64 | tr -d '/+=' | head -c12)"
  if "$PREFIX/rahro-panel" admin create -config "$cfg" -u "$user" -p "$pass" >/dev/null 2>&1; then
    created=1
  fi

  setup_service rahro-panel "$PREFIX/rahro-panel run -config $cfg"

  # 'rahro' management menu (x-ui style).
  cat > "$PREFIX/rahro" <<EOF
#!/usr/bin/env bash
exec $PREFIX/rahro-panel menu -config $cfg "\$@"
EOF
  chmod +x "$PREFIX/rahro"

  echo
  ok "Rahro panel installed."
  echo -e "   URL:    ${c_green}https://${ip}:2053${c_reset}   (self-signed cert — accept the browser warning)"
  echo -e "   Manage: type ${c_green}rahro${c_reset} for the terminal menu (port, SSL, admin, update, …)"
  if [ "$created" = "1" ]; then
    echo -e "   Login: ${c_green}${user}${c_reset} / ${c_green}${pass}${c_reset}    ← save this now"
  else
    echo    "   Admin already existed. Reset its password with:"
    echo    "     $PREFIX/rahro-panel admin passwd -config $cfg -u admin -p 'NEWPASS'"
  fi
  echo    "   Config: $cfg   (edit, then: systemctl restart rahro-panel)"
}

install_node(){
  local role="$1"; shift
  local code="${1:-}"; shift || true
  [ -n "$code" ] || die "usage: install.sh $role <connection-code> -panel <url> [-insecure]"
  provide rahro-node
  mkdir -p "$ETC"
  info "enrolling node"
  ( cd "$ETC" && "$PREFIX/rahro-node" enroll "$code" "$@" -out "$ETC/node.json" ) || die "enrollment failed"

  setup_service rahro-node "$PREFIX/rahro-node run -config $ETC/node.json"
  echo
  ok "Rahro node ($role) enrolled."
  echo    "   Config: $ETC/node.json"
}

case "${1:-panel}" in
  panel) install_panel;;
  node)  shift; install_node location "$@";;
  tunnel) shift; install_node tunnel "$@";;
  *) die "unknown mode '$1' (panel|node|tunnel)";;
esac
