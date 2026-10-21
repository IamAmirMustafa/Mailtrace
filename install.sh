#!/usr/bin/env bash
# MailTrax installer for Kali / Debian / Ubuntu
set -e
cd "$(dirname "$0")"

if [ ! -f mailtrax.py ]; then
  echo "mailtrax.py must be in the same folder as install.sh"; exit 1
fi

echo "[*] Installing mailtrax to /usr/local/bin/mailtrax"
sudo install -m 755 mailtrax.py /usr/local/bin/mailtrax

echo "[*] Installing optional helpers (faster DNS, DKIM signature verification)"
sudo apt-get install -y python3-dnspython python3-dkim \
  || echo "[!] Optional packages not installed - MailTrax still works without them"

echo
echo "[+] Done. Try:  mailtrax --help"
echo "    Optional API keys:  mailtrax --set-key abuseipdb YOUR_KEY"
