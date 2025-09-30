#!/bin/bash
# scripts/updatecrs.sh
# Update to the latest CRS release (idempotent)
# - Detects nginx/apache automatically
# - Skips download if the latest version directory already exists
# - Always points main.conf to the latest version and reloads the server

set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

detect_server() {
  if systemctl is-active --quiet nginx; then echo nginx; return; fi
  if systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then echo apache; return; fi
  if command -v nginx >/dev/null 2>&1; then echo nginx; return; fi
  if command -v apache2ctl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then echo apache; return; fi
  echo none
}

latest_tag() {
  # returns e.g. v4.18.0
  curl -fsSL "https://api.github.com/repos/coreruleset/coreruleset/releases/latest" \
    | grep -oP '"tag_name":\s*"\K[^"]+'
}

SERVER="$(detect_server)"
if [[ "$SERVER" == "none" ]]; then
  echo "[✗] No web server (nginx/apache) detected."
  exit 1
fi
echo "[+] Detected server: $SERVER"

TAG="$(latest_tag || true)"
if [[ -z "${TAG:-}" ]]; then
  echo "[✗] Failed to retrieve latest CRS version tag from GitHub."
  exit 1
fi
NUM_VER="${TAG#v}"
echo "[+] Latest CRS version: $TAG"

# Paths per server, unify main.conf for both
if [[ "$SERVER" == "nginx" ]]; then
  CRS_PARENT_DIR="/etc/nginx/modsec"
  MAIN_CONF="$CRS_PARENT_DIR/main.conf"
  TEST_CMD=(nginx -t)
  RELOAD_CMD=(nginx -s reload)
else
  CRS_PARENT_DIR="/etc/modsecurity"
  [[ -d "$CRS_PARENT_DIR" ]] || CRS_PARENT_DIR="/etc/modsecurity.d"
  MAIN_CONF="$CRS_PARENT_DIR/main.conf"
  if command -v apache2ctl >/dev/null 2>&1; then
    TEST_CMD=(apache2ctl configtest)
    RELOAD_CMD=(systemctl reload apache2)
  else
    TEST_CMD=(httpd -t)
    RELOAD_CMD=(systemctl reload httpd)
  fi
fi

TARGET_DIR="$CRS_PARENT_DIR/coreruleset-${NUM_VER}"
CRS_RULE_DIR="$TARGET_DIR/rules"
TMP_DIR="/tmp/crs_update.$$"

mkdir -p "$CRS_PARENT_DIR"

# Install only if not present
if [[ -d "$TARGET_DIR" ]]; then
  echo "[=] CRS $TAG already present at $TARGET_DIR. Skipping download."
else
  echo "[+] Downloading CRS $TAG ..."
  mkdir -p "$TMP_DIR"
  cd "$TMP_DIR"
  wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${TAG}.tar.gz" -O crs.tar.gz
  tar -xzf crs.tar.gz
  SRC_DIR="coreruleset-${NUM_VER}"
  if [[ ! -d "$SRC_DIR" ]]; then
    echo "[✗] Extracted directory not found: $SRC_DIR"
    exit 1
  fi
  echo "[+] Installing into $TARGET_DIR"
  mv "$SRC_DIR" "$TARGET_DIR"
fi

# Ensure crs-setup.conf exists
if [[ -f "$TARGET_DIR/crs-setup.conf.example" && ! -f "$TARGET_DIR/crs-setup.conf" ]]; then
  echo "[+] Creating crs-setup.conf from example"
  cp -n "$TARGET_DIR/crs-setup.conf.example" "$TARGET_DIR/crs-setup.conf"
fi

# Activate optional exclusions if example exists
EXCL_900="$CRS_RULE_DIR/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
EXCL_900_EX="$CRS_RULE_DIR/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example"
if [[ -f "$EXCL_900_EX" && ! -f "$EXCL_900" ]]; then
  echo "[+] Activating REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
  cp "$EXCL_900_EX" "$EXCL_900"
fi

EXCL_999="$CRS_RULE_DIR/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
EXCL_999_EX="$CRS_RULE_DIR/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example"
if [[ -f "$EXCL_999_EX" && ! -f "$EXCL_999" ]]; then
  echo "[+] Activating RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
  cp "$EXCL_999_EX" "$EXCL_999"
fi

# Inject WAF dashboard exclusions into 900-file
if [[ -f "$EXCL_900" ]]; then
  if ! grep -q '/crs/rules/save/' "$EXCL_900"; then
    cat >> "$EXCL_900" <<'EOR'

# Exclude WAF dashboard endpoints
SecRule REQUEST_URI "@beginsWith /crs/rules/save/" "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
    echo "[✓] Dashboard exclusions added to REQUEST-900."
  else
    echo "[=] Dashboard exclusions already present."
  fi
fi

# Rewrite main.conf to point to THIS version
echo "[+] Updating $MAIN_CONF"
mkdir -p "$(dirname "$MAIN_CONF")"
touch "$MAIN_CONF"
sed -i '/Include .*crs-setup.conf/d' "$MAIN_CONF" || true
sed -i '/Include .*rules\/\*.conf/d' "$MAIN_CONF" || true
{
  echo "Include $TARGET_DIR/crs-setup.conf"
  echo "Include $TARGET_DIR/rules/*.conf"
} >> "$MAIN_CONF"

# Test & reload
echo "[+] Testing web server configuration..."
if ! "${TEST_CMD[@]}" >/dev/null 2>&1; then
  echo "[✗] Config test failed:"
  "${TEST_CMD[@]}"
  exit 1
fi

echo "[+] Reloading $SERVER..."
if "${RELOAD_CMD[@]}" >/dev/null 2>&1; then
  echo "[✓] Updated to $TAG and $SERVER reloaded."
else
  echo "[!] Updated to $TAG but reload failed. Check server logs."
fi

# Cleanup if we downloaded
[[ -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
