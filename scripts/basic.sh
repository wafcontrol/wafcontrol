#!/bin/bash
# scripts/basic.sh
set -e

get_nginx_version() {
  if command -v nginx >/dev/null 2>&1; then nginx -v 2>&1 | awk -F/ '{print $2}'; fi
}
get_apache_version() {
  if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl -v 2>/dev/null | awk -F/ '/Server version/ {print $2}' | awk '{print $1}'
  elif command -v apache2 >/dev/null 2>&1; then
    apache2 -v 2>/dev/null | awk -F/ '/Server version/ {print $2}' | awk '{print $1}'
  fi
}
is_active() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then systemctl is-active --quiet "$svc"; return $?; fi
  pgrep -f "$svc" >/dev/null 2>&1
}
detect_server() {
  is_active nginx && { echo nginx; return; }
  is_active apache2 && { echo apache; return; }
  command -v nginx >/dev/null 2>&1 && { echo nginx; return; }
  (command -v apache2ctl >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1) && { echo apache; return; }
  echo none
}
get_crs_version_nginx() {
  local conf="/etc/nginx/modsec/main.conf"
  [[ -f "$conf" ]] && grep -Eo 'coreruleset-[0-9]+\.[0-9]+(\.[0-9]+)?' "$conf" | head -n1 | sed 's/coreruleset-//'
}
get_crs_version_apache() {
  local setup="/etc/modsecurity/crs-setup.conf"
  if [[ -L "$setup" ]]; then
    readlink -f "$setup" | grep -Eo 'modsecurity-crs-([0-9]+\.[0-9]+(\.[0-9]+)?)' | sed 's/.*modsecurity-crs-//'
    return
  fi
  local conf="/etc/modsecurity/modsecurity.conf"
  [[ -f "$conf" ]] && grep -Eo 'modsecurity-crs[-/][0-9]+\.[0-9]+(\.[0-9]+)?' "$conf" | head -n1 | sed -E 's/.*(modsecurity-crs[-/])//'
}

NGX_VER="$(get_nginx_version || true)"
APC_VER="$(get_apache_version || true)"
SERVER="$(detect_server)"

WAF_EXIT=1
WAF_VER=""
if [[ "$SERVER" == "nginx" ]]; then
  [[ -f /etc/nginx/modsec/main.conf ]] && WAF_EXIT=0
  WAF_VER="$(get_crs_version_nginx || true)"
elif [[ "$SERVER" == "apache" ]]; then
  [[ -f /etc/modsecurity/modsecurity.conf ]] && WAF_EXIT=0
  WAF_VER="$(get_crs_version_apache || true)"
fi

cat <<EOF
{
  "server": "$SERVER",
  "nginx": {"exit_code": $( [[ -n "$NGX_VER" ]] && echo 0 || echo 1 ), "version": "${NGX_VER:-}"},
  "apache": {"exit_code": $( [[ -n "$APC_VER" ]] && echo 0 || echo 1 ), "version": "${APC_VER:-}"},
  "waf": {"exit_code": $WAF_EXIT, "version": "${WAF_VER:-}"}
}
EOF
