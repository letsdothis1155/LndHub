#!/usr/bin/env bash
set -euo pipefail

echo "== Node private-network setup for macOS =="

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is for macOS only."
  exit 1
fi

if command -v tailscale >/dev/null 2>&1; then
  echo "Tailscale CLI is already installed."
  tailscale status || true
  exit 0
fi

if [[ -d "/Applications/Tailscale.app" ]]; then
  echo "Tailscale is already installed. Opening it..."
  open -a Tailscale
  exit 0
fi

if command -v brew >/dev/null 2>&1; then
  echo "Installing Tailscale with Homebrew..."
  brew install --cask tailscale
  open -a Tailscale
else
  echo "Homebrew is not installed. Opening the official Tailscale download page..."
  open "https://tailscale.com/download/mac"
fi

echo
echo "Finish the Tailscale sign-in window, then rerun this script or run: tailscale status"
echo "Do not place Telegram proxy secrets, wallet credentials, seed phrases, or macaroons in this repository."
