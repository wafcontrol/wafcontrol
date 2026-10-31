#!/usr/bin/env bash
# switch_crs_version.sh
# Usage: ./switch_crs_version.sh <version-tag>   (e.g. v4.18.0 or 4.18.0)
set -euo pipefail

VERSION="${1:-}"; [[ -n "$VERSION" ]] || { echo "Usage: $0 <version-tag>"; exit 1; }
[[ "$VERSION" == v* ]] || VERSION="v$VERSION"
VERSION_NUM="${VERSION#v}"

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

# detect server
SERVER="none"
if systemctl is-active --quiet nginx; then SERVER="nginx"
elif systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then SERVER="apache"
elif command -v nginx >/dev/null 2>&1; then SERVER="nginx"
elif command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then SERVER="apache"
fi
[[ "$SERVER" != "none" ]] || { echo "[!] No nginx/apache found."; exit 1; }

# tools
need() { for t in "$@"; do command -v "$t" >/dev/null 2>&1 || M+=("$t"); done; [[ -z "${M[*]-}" ]] || (apt-get update -y && apt-get install -y "${M[@]}"); }
M=(); need curl jq tar gzip

TMP_DIR="$(mktemp -d -t crs-switch-XXXXXX)"; trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$SERVER" == "nginx" ]]; then
  CRS_PARENT="/etc/nginx/modsec"
  MAIN_CONF="${CRS_PARENT}/main.conf"
  TEST_CMD=(nginx -t)
  RELOAD_CMD=(nginx -s reload)
  TARGET_DIR="${CRS_PARENT}/coreruleset-${VERSION_NUM}"
else
  MODSEC_ETC="/etc/modsecurity"
  CRS_ROOT="${MODSEC_ETC}/crs"
  CRS_VERSIONS="${CRS_ROOT}/versions"
  CRS_CURRENT="${CRS_ROOT}/current"
  mkdir -p "$CRS_VERSIONS"
  TEST_CMD=(apache2ctl configtest)
  RELOAD_CMD=(systemctl reload apache2)
  TARGET_DIR="${CRS_VERSIONS}/coreruleset-${VERSION_NUM}"
fi

echo "[+] Server: $SERVER"
echo "[+] Target CRS: $VERSION -> $TARGET_DIR"

# download if missing
if [[ ! -d "$TARGET_DIR/rules" ]]; then
  echo "[+] Downloading $VERSION …"
  URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz"
  if ! ERR="$(curl -fsSL --retry 2 --connect-timeout 15 -o "$TMP_DIR/crs.tgz" "$URL" 2>&1)"; then
    echo "[!] Download failed: ${ERR:-unknown error}" >&2
    echo "[!] Check that this server can reach github.com (DNS / firewall), or set HTTPS_PROXY in .env and restart the panel." >&2
    exit 1
  fi
  tar -xzf "$TMP_DIR/crs.tgz" -C "$TMP_DIR" || { echo "[!] Downloaded archive is not valid." >&2; exit 1; }
  mv "$TMP_DIR/coreruleset-${VERSION_NUM}" "$TARGET_DIR"
fi

# ensure setup & optional files
if [[ -f "$TARGET_DIR/crs-setup.conf.example" && ! -f "$TARGET_DIR/crs-setup.conf" ]]; then
  cp "$TARGET_DIR/crs-setup.conf.example" "$TARGET_DIR/crs-setup.conf"
fi
if [[ -f "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example" && ! -f "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" ]]; then
  cp "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example" "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
fi
if [[ -f "$TARGET_DIR/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example" && ! -f "$TARGET_DIR/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf" ]]; then
  cp "$TARGET_DIR/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example" "$TARGET_DIR/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
fi
# Dashboard exclusions are scoped to the panel vhost (scripts/panel_waf_exclusions.sh), never global:
# a global REQUEST_URI exclusion turned the WAF off for those paths on every protected site.
sed -i -E '/id:15000(10|11)\b/d; /^# (WAF dashboard exclusions|Exclude WAF dashboard endpoints)$/d' "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" 2>/dev/null || true

# wire in (keep a backup so a failed config test can be rolled back)
if [[ "$SERVER" == "nginx" ]]; then
  mkdir -p "$(dirname "$MAIN_CONF")"
  touch "$MAIN_CONF"
  cp -p "$MAIN_CONF" "$TMP_DIR/main.conf.bak"
  sed -i '/Include .*crs-setup\.conf/d' "$MAIN_CONF" || true
  sed -i '/Include .*rules\/\*\.conf/d' "$MAIN_CONF" || true
  {
    echo "Include $TARGET_DIR/crs-setup.conf"
    echo "Include $TARGET_DIR/rules/*.conf"
  } >> "$MAIN_CONF"
else
  # Apache: just switch "current" and keep modsecurity.conf pointing to current/*
  PREV_CURRENT="$(readlink "$CRS_CURRENT" 2>/dev/null || true)"
  MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
  cp -p "$MODSEC_CONF" "$TMP_DIR/modsecurity.conf.bak"
  ln -sfn "$TARGET_DIR" "$CRS_CURRENT"
  chown -h root:root "$CRS_CURRENT"
  find "$TARGET_DIR" -type d -exec chmod 755 {} \;
  find "$TARGET_DIR" -type f -exec chmod 644 {} \;

  # replace any existing includes to always use /etc/modsecurity/crs/current/*
  if grep -q 'crs-setup.conf' "$MODSEC_CONF"; then
    sed -i -E 's#^[[:space:]]*Include(Optional)?[[:space:]]+.*/crs-setup\.conf#IncludeOptional /etc/modsecurity/crs/current/crs-setup.conf#' "$MODSEC_CONF"
  else
    echo 'IncludeOptional /etc/modsecurity/crs/current/crs-setup.conf' >> "$MODSEC_CONF"
  fi
  if grep -q '/rules/\*\.conf' "$MODSEC_CONF"; then
    sed -i -E 's#^[[:space:]]*Include(Optional)?[[:space:]]+.*/rules/\*\.conf#IncludeOptional /etc/modsecurity/crs/current/rules/*.conf#' "$MODSEC_CONF"
  else
    echo 'IncludeOptional /etc/modsecurity/crs/current/rules/*.conf' >> "$MODSEC_CONF"
  fi
fi

# test & reload
echo "[+] Testing config…"
if ! TEST_OUT="$("${TEST_CMD[@]}" 2>&1)"; then
  echo "[!] Config test failed with $VERSION, rolling back:" >&2
  echo "$TEST_OUT" >&2
  if [[ "$SERVER" == "nginx" ]]; then
    cp -p "$TMP_DIR/main.conf.bak" "$MAIN_CONF"
  else
    cp -p "$TMP_DIR/modsecurity.conf.bak" "$MODSEC_CONF"
    if [[ -n "$PREV_CURRENT" ]]; then ln -sfn "$PREV_CURRENT" "$CRS_CURRENT"; fi
  fi
  exit 1
fi
echo "[+] Reloading…"
"${RELOAD_CMD[@]}" || true
echo "[✓] Switched to $VERSION."
