#!/bin/bash

echo "[*] Phase-1 Setup Started..."

# -------------------------------
# 1. System package update
# -------------------------------
echo "[*] Updating system..."
sudo apt update -y

# -------------------------------
# 2. Required system tools
# -------------------------------
echo "[*] Installing required system packages..."
sudo apt install -y \
    nmap \
    nuclei \
    exploitdb \
    python3 \
    python3-pip \
    jq

# -------------------------------
# 3. Update nuclei templates
# -------------------------------
echo "[*] Updating nuclei templates..."
nuclei -update-templates >/dev/null 2>&1

# -------------------------------
# 4. Python dependencies
# -------------------------------
echo "[*] Installing Python dependencies..."
pip install google-generativeai --break-system-packages

# -------------------------------
# 5. Project permissions
# -------------------------------
echo "[*] Fixing permissions..."
chmod +x v2.2.sh
chmod +x phase1_setup.sh

# -------------------------------
# 6. Directory sanity check
# -------------------------------
if [ ! -d "scan_results" ]; then
    mkdir scan_results
fi

echo "[âœ”] Phase-1 Setup Completed Successfully!"