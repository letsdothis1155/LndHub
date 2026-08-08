#!/usr/bin/env bash
set -euo pipefail

# Safe helper for macOS: installs Docker Desktop if needed, creates an MTProto proxy
# compose file, generates a local secret, and prints the Telegram connection values.
# It does NOT touch Bitcoin/LND data, wallets, channels, seeds, or credentials.

say() { printf '\n==> %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*"; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is intended for macOS."
  exit 1
fi

WORKDIR="$HOME/telegram-mtproto-proxy"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

if ! command -v docker >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    say "Docker CLI not found. Installing Docker Desktop with Homebrew Cask..."
    brew install --cask docker || true
  else
    warn "Docker is not installed and Homebrew is unavailable."
    echo "Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and rerun this script."
    exit 2
  fi
fi

say "Opening Docker Desktop..."
open -a Docker || true

# Wait briefly for Docker to become available.
for i in {1..30}; do
  if docker info >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! docker info >/dev/null 2>&1; then
  warn "Docker Desktop is not ready yet. Finish any macOS approval prompts, then rerun this script."
  exit 3
fi

SECRET_FILE="$WORKDIR/secret.txt"
if [[ ! -f "$SECRET_FILE" ]]; then
  # Telegram MTProxy classic secret: 16 random bytes => 32 hex chars.
  openssl rand -hex 16 > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
fi
SECRET="$(tr -d '\n' < "$SECRET_FILE")"

cat > docker-compose.yml <<EOF
services:
  mtproto-proxy:
    image: telegrammessenger/proxy:latest
    container_name: telegram-mtproto-proxy
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - SECRET=${SECRET}
      - TAG=
EOF

say "Starting Telegram MTProto proxy on TCP port 443..."
docker compose up -d

say "Local proxy container status"
docker ps --filter name=telegram-mtproto-proxy --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

TAILSCALE_IP=""
if command -v tailscale >/dev/null 2>&1; then
  TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
elif [[ -x "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
  TAILSCALE_IP="$(/Applications/Tailscale.app/Contents/MacOS/Tailscale ip -4 2>/dev/null | head -n1 || true)"
fi

cat <<EOF

===============================================
Telegram MTProto proxy is prepared.

Port:   443
Secret: ${SECRET}
EOF

if [[ -n "$TAILSCALE_IP" ]]; then
  cat <<EOF
Server (Tailscale): ${TAILSCALE_IP}

On Android Telegram:
Settings > Data and Storage > Proxy Settings > Add Proxy > MTProto
Server: ${TAILSCALE_IP}
Port: 443
Secret: ${SECRET}
EOF
else
  cat <<EOF

Tailscale IP was not detected yet.
After Tailscale is installed and connected, run:
  tailscale ip -4

Use that 100.x.x.x address as the Telegram MTProto Server value.
EOF
fi

cat <<'EOF'

Important: a Tailscale-only IP works only from devices on the same tailnet.
If you want a public Telegram proxy usable without Tailscale, you will need a
publicly reachable server/IP and TCP 443 forwarded to this Mac.
===============================================
EOF
