#!/usr/bin/env bash
# scripts/panel_waf_exclusions.sh
#
# Lets WafControl admins save configuration through the panel without ModSecurity/CRS
# blocking them (config text such as "proxy_pass http://...", "/var/log/...", SecRule or
# <VirtualHost> looks like an attack to CRS and the save returns 403).
#
# The exclusion is scoped to the panel's own virtual host and to POST requests on the
# panel's editing endpoints. Every other site behind the WAF, and the panel's login page,
# stay fully protected. Django enforces login + CSRF on those endpoints.
#
# It also removes the old global exclusions (ids 1500010/1500011) from the CRS
# REQUEST-900 files: being global, they disabled the WAF for those paths on every site.
#
# Idempotent. Usage: sudo bash scripts/panel_waf_exclusions.sh
# WAFC_NO_RELOAD=1 validates the config but does not reload (installer / image build).
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

say()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

read -r -d '' PANEL_RULES <<'EOR' || true
# Managed by WafControl (scripts/panel_waf_exclusions.sh) - included only in the panel's vhost.
# Saving configuration posts text that CRS treats as attacks; skip the WAF for those POSTs only.
SecRule REQUEST_METHOD "@streq POST" "id:1500020,phase:1,pass,nolog,chain"
    SecRule REQUEST_URI "@rx ^/(?:crs/rules/save/|dashboard/crs/settings/|dashboard/crs/rules/(?:update|toggle)/|dashboard/crs/custom-rules/|custom-rules/(?:edit|delete)/|dashboard/(?:nginx|apache)/conf/|(?:nginx|apache)/conf/save/|dashboard/ip-lists/|dashboard/syslog/|dashboard/settings/|dashboard/users/|dashboard/profile/)" "ctl:ruleEngine=Off"
EOR

BACKUP_DIR="$(mktemp -d -t wafc-panel-excl-XXXXXX)"
trap 'rm -rf "$BACKUP_DIR"' EXIT
declare -a BACKED_UP=()

backup() {  # backup <file>
  local f="$1" b
  [[ -f "$f" ]] || return 0
  b="$BACKUP_DIR/$(echo "$f" | tr '/' '_')"
  cp -p "$f" "$b"
  BACKED_UP+=("$f")
}

restore_all() {
  local f
  for f in "${BACKED_UP[@]}"; do cp -p "$BACKUP_DIR/$(echo "$f" | tr '/' '_')" "$f"; done
}

remove_global_exclusions() {  # remove_global_exclusions <dir>...
  local f
  while IFS= read -r f; do
    if grep -qE 'id:15000(10|11)\b' "$f"; then
      backup "$f"
      sed -i -E '/id:15000(10|11)\b/d; /^# (WAF dashboard exclusions|Exclude WAF dashboard endpoints)$/d' "$f"
      say "Removed global dashboard exclusions from $f"
    fi
  done < <(find "$@" -name 'REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf' 2>/dev/null)
}

configure_nginx() {
  local vhost="/etc/nginx/conf.d/wafcontrol.conf" rules="/etc/nginx/modsec/wafcontrol-panel.conf"
  [[ -f "$vhost" ]] || return 1
  say "nginx panel vhost: $vhost"
  backup "$rules"; backup "$vhost"
  mkdir -p "$(dirname "$rules")"
  printf '%s\n' "$PANEL_RULES" > "$rules"
  if ! grep -q "wafcontrol-panel.conf" "$vhost"; then
    # Server level: applies to every location of the panel (rules merge with the http-level set).
    sed -i -E "s|^([[:space:]]*server[[:space:]]*\{)[[:space:]]*$|\1\n    modsecurity_rules_file ${rules};  # WAFCONTROL-PANEL|" "$vhost"
  fi
  remove_global_exclusions /etc/nginx/modsec
  if ! OUT="$(nginx -t 2>&1)"; then
    warn "nginx -t failed, reverting:"; echo "$OUT" >&2
    restore_all; [[ -f "$BACKUP_DIR/$(echo "$rules" | tr '/' '_')" ]] || rm -f "$rules"
    return 2
  fi
  reload_server nginx
  say "nginx config applied: panel config saves are no longer blocked."
}

configure_apache() {
  # Kept out of /etc/modsecurity/*.conf: Debian's stock security2.conf includes that glob for
  # every site, which would turn these panel-only exclusions into global ones.
  local vhost="/etc/apache2/sites-available/wafcontrol.conf" rules="/etc/modsecurity/wafcontrol/panel.conf"
  local legacy="/etc/modsecurity/wafcontrol-panel.conf"
  [[ -f "$vhost" ]] || return 1
  say "Apache panel vhost: $vhost"
  backup "$rules"; backup "$vhost"; backup "$legacy"
  mkdir -p "$(dirname "$rules")"
  printf '%s\n' "$PANEL_RULES" > "$rules"
  if grep -q "$legacy" "$vhost"; then
    sed -i "s|$legacy|$rules|" "$vhost"
  fi
  rm -f "$legacy"
  if ! grep -q "$rules" "$vhost"; then
    # Apache only allows whole-line comments.
    sed -i -E "s|^([[:space:]]*<VirtualHost[^>]*>)[[:space:]]*$|\1\n    # WAFCONTROL-PANEL: panel-only WAF exclusions\n    <IfModule security2_module>\n        Include ${rules}\n    </IfModule>|" "$vhost"
  fi
  remove_global_exclusions /etc/modsecurity
  if ! OUT="$(apache2ctl configtest 2>&1)"; then
    warn "apache2ctl configtest failed, reverting:"; echo "$OUT" >&2
    restore_all; [[ -f "$BACKUP_DIR/$(echo "$rules" | tr '/' '_')" ]] || rm -f "$rules"
    return 2
  fi
  reload_server apache2
  say "Apache config applied: panel config saves are no longer blocked."
}

reload_server() {  # reload_server nginx|apache2
  [[ "${WAFC_NO_RELOAD:-0}" == "1" ]] && return 0
  if [[ -d /run/systemd/system ]] && systemctl is-active --quiet "$1" 2>/dev/null; then
    systemctl reload "$1"
  elif [[ "$1" == "nginx" ]]; then
    nginx -s reload
  else
    apache2ctl -k graceful
  fi
}

done_any=0
if command -v nginx >/dev/null 2>&1; then
  rc=0; configure_nginx || rc=$?
  [[ $rc -eq 0 ]] && done_any=1
  [[ $rc -eq 2 ]] && exit 1
fi
if command -v apache2ctl >/dev/null 2>&1; then
  rc=0; configure_apache || rc=$?
  [[ $rc -eq 0 ]] && done_any=1
  [[ $rc -eq 2 ]] && exit 1
fi
[[ $done_any -eq 1 ]] || { warn "WafControl panel vhost not found (nginx: /etc/nginx/conf.d/wafcontrol.conf, apache: /etc/apache2/sites-available/wafcontrol.conf)."; exit 1; }
