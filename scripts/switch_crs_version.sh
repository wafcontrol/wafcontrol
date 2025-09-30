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
M=(); need curl jq wget tar gzip

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
  wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz" -O "$TMP_DIR/crs.tgz"
  tar -xzf "$TMP_DIR/crs.tgz" -C "$TMP_DIR"
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
if [[ -f "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" ]] && \
   ! grep -q 'id:1500010' "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"; then
  cat >> "$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" <<'EOR'
# WAF dashboard exclusions
SecRule REQUEST_URI "@beginsWith /crs/rules/save/"        "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
fi

# wire in
if [[ "$SERVER" == "nginx" ]]; then
  mkdir -p "$(dirname "$MAIN_CONF")"
  touch "$MAIN_CONF"
  sed -i '/Include .*crs-setup\.conf/d' "$MAIN_CONF" || true
  sed -i '/Include .*rules\/\*\.conf/d' "$MAIN_CONF" || true
  {
    echo "Include $TARGET_DIR/crs-setup.conf"
    echo "Include $TARGET_DIR/rules/*.conf"
  } >> "$MAIN_CONF"
else
  # Apache: just switch "current" and keep modsecurity.conf pointing to current/*
  ln -sfn "$TARGET_DIR" "$CRS_CURRENT"
  chown -h root:root "$CRS_CURRENT"
  find "$TARGET_DIR" -type d -exec chmod 755 {} \;
  find "$TARGET_DIR" -type f -exec chmod 644 {} \;

  MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
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
"${TEST_CMD[@]}"
echo "[+] Reloading…"
"${RELOAD_CMD[@]}" || true
echo "[✓] Switched to $VERSION."
