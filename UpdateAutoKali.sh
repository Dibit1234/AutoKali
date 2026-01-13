#!/bin/bash
set -e

AUTOKALI_DIR="$HOME/AutoKali"
AUTOKALI_BIN="/usr/local/bin/autokali"

echo "[*] Updating AutoKali..."

# 1. Go to AutoKali directory
if [ ! -d "$AUTOKALI_DIR" ]; then
  echo "[!] AutoKali directory not found: $AUTOKALI_DIR"
  exit 1
fi

cd "$AUTOKALI_DIR"

echo "[*] Fetching latest code..."
git fetch origin

echo "[*] Resetting local branch to origin/main..."
git reset --hard origin/main

# 2. Reinstall global binary
if [ ! -f "autokali.py" ]; then
  echo "[!] autokali.py not found in $AUTOKALI_DIR"
  exit 1
fi

echo "[*] Installing autokali globally..."
sudo install -m 0755 autokali.py "$AUTOKALI_BIN"

# 3. Clear shell command cache
hash -r

echo "[+] AutoKali updated successfully."
echo "[+] Run: autokali -h"
autokali -h
