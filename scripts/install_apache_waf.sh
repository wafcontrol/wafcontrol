#!/usr/bin/env bash
set -euo pipefail

# ===== UI =====
is_tty=0; [ -t 1 ] && is_tty=1
if [ "$is_tty" -eq 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[1;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
say()  { printf "%b[+]%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$*"; }
err()  { printf "%b[x]%b %s\n" "$RED" "$NC" "$*" >&2; }
line() { local ch="${1:-=}"; local w="${2:-72}"; printf '%*s\n' "$w" '' | tr ' ' "$ch"; }
banner(){ local title="$1"; local ch="${2:-=}"; local w="${3:-72}"; line "$ch" "$w"; printf "%b%s%b\n" "$BLUE" "$title" "$NC"; line "$ch" "$w"; }

trap 'err "Failed on line $LINENO"' ERR
[[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive

# ===== STATE =====
STATE_DIR="${STATE_DIR:-/var/lib/wafcontrol-installer}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/state.env}"
mkdir -p "$STATE_DIR"; touch "$STATE_FILE"
state_append_array() { printf '%s+=(%q)\n' "$1" "$2" >> "$STATE_FILE"; }
state_put_map()      { printf '%s[%q]=%q\n' "$1" "$2" "$3" >> "$STATE_FILE"; }
# shellcheck disable=SC1090
source "$STATE_FILE" 2>/dev/null || true

# ===== INPUTS =====
APP_DIR="${APP_DIR:?}"
VENV_DIR="${VENV_DIR:?}"
RUNTIME_DIR="${RUNTIME_DIR:?}"
HTTP_PORT="${HTTP_PORT:-7000}"
MODE="${MODE:?}"
DOMAIN="${DOMAIN:-}"
SSL_ENABLE="${SSL_ENABLE:-0}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
STATIC_DIR="${APP_DIR}/frontend"

BASIC_AUTH_ENABLE="${BASIC_AUTH_ENABLE:-0}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-}"

banner "Apache + ModSecurity2 + CRS"

# 1) Apache presence
if ! command -v apache2ctl >/dev/null 2>&1; then
  banner "Installing Apache"
  apt update -y
  apt install -y apache2
  systemctl enable --now apache2
  say "Apache installed and started."
else
  say "Apache detected; reusing existing installation."
fi

# 2) ModSecurity2 + CRS prep
banner "Installing ModSecurity2 and preparing CRS"
apt update -y
apt install -y libapache2-mod-security2 libmodsecurity3 curl jq wget tar gzip || true
a2enmod security2 >/dev/null 2>&1 || true
install -d -m 0750 /var/cache/modsecurity || true

MDIR="/etc/modsecurity"
CRS_ROOT="${MDIR}/crs"
CRS_VERSIONS="${CRS_ROOT}/versions"
CRS_CURRENT="${CRS_ROOT}/current"
mkdir -p "$MDIR" "$CRS_VERSIONS"

if [[ ! -f "$MDIR/modsecurity.conf" ]]; then
  if [[ -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
    cp /etc/modsecurity/modsecurity.conf-recommended "$MDIR/modsecurity.conf"
  elif [[ -f /usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended ]]; then
    cp /usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended "$MDIR/modsecurity.conf"
  elif [[ -f /usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended.gz" ]]; then
    zcat /usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended.gz > "$MDIR/modsecurity.conf"
  else
    wget -qO "$MDIR/modsecurity.conf" "https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended" || true
  fi
  state_append_array CREATED_FILES "$MDIR/modsecurity.conf"
fi
sed -i 's/^\s*SecRuleEngine\s\+DetectionOnly/SecRuleEngine On/' "$MDIR/modsecurity.conf" || true
grep -qE '^\s*SecRuleEngine\s+' "$MDIR/modsecurity.conf" || echo "SecRuleEngine On" >> "$MDIR/modsecurity.conf"

# 3) Fetch latest CRS
banner "Fetching Core Rule Set (CRS)"
TAG="$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name' || true)"
if [[ -n "$TAG" && "$TAG" != "null" ]]; then
  NUM="${TAG#v}"
  TGT="${CRS_VERSIONS}/coreruleset-${NUM}"
  if [[ ! -d "$TGT/rules" ]]; then
    TMPD="$(mktemp -d -t crs-XXXXXX)"
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${TAG}.tar.gz" -O "$TMPD/crs.tgz"
    tar -xzf "$TMPD/crs.tgz" -C "$TMPD"
    mv "$TMPD/coreruleset-${NUM}" "$TGT"
    rm -rf "$TMPD"
    say "CRS downloaded: ${TAG}"
  else
    say "CRS already present: $(basename "$TGT")"
  fi
else
  if [[ -d /usr/share/modsecurity-crs/rules ]]; then
    TGT="${CRS_VERSIONS}/coreruleset-packaged"
    [[ -d "$TGT" ]] || cp -a /usr/share/modsecurity-crs "$TGT"
    say "CRS fallback to packaged copy."
  elif compgen -G "/usr/share/modsecurity-crs-*/rules" >/dev/null; then
    PKG="$(ls -d /usr/share/modsecurity-crs-* | head -n1)"
    NUM="${PKG##*-}"
    TGT="${CRS_VERSIONS}/coreruleset-${NUM}"
    [[ -d "$TGT" ]] || cp -a "$PKG" "$TGT"
    say "CRS fallback to packaged variant: $(basename "$TGT")"
  else
    err "CRS download failed and no packaged CRS found."
  fi
fi

RULES="${TGT}/rules"
[[ -d "$RULES" ]] || { err "CRS rules dir not found: $RULES"; }
[[ -f "${TGT}/crs-setup.conf" ]] || cp "${TGT}/crs-setup.conf.example" "${TGT}/crs-setup.conf"
for f in REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf; do
  [[ -f "${RULES}/${f}" ]] || { [[ -f "${RULES}/${f}.example" ]] && cp "${RULES}/${f}.example" "${RULES}/${f}" || true; }
done
if [[ -f "${RULES}/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" ]] && ! grep -q '/crs/rules/save/' "${RULES}/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"; then
  cat >> "${RULES}/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" <<'EOR'
# WAF dashboard exclusions
SecRule REQUEST_URI "@beginsWith /crs/rules/save/"        "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
fi

ln -sfn "$TGT" "$CRS_CURRENT"
chmod -R a+rX "$CRS_ROOT"
state_append_array CREATED_FILES "$CRS_CURRENT"

# 4) Wire into Apache (security2.conf)
banner "Wiring ModSecurity into Apache"
SEC2="/etc/apache2/mods-available/security2.conf"
TS="$(date +%s)"
if [[ -f "$SEC2" ]]; then
  cp -a "$SEC2" "${SEC2}.bak.${TS}" || true
  state_put_map BACKUPS "$SEC2" "${SEC2}.bak.${TS}"
fi
cat > "$SEC2" <<CONF
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional ${CRS_CURRENT}/crs-setup.conf
    IncludeOptional ${CRS_CURRENT}/rules/*.conf
</IfModule>
CONF

apache2ctl configtest
systemctl reload apache2
say "Apache WAF ready (CRS: $(basename "$TGT"))."

# 5) App vhost
banner "Creating Apache vhost for WafControl"
APACHE_CONF="/etc/apache2/sites-available/wafcontrol.conf"

AUTH_BLOCK=""
if [[ "${BASIC_AUTH_ENABLE}" = "1" && -n "${BASIC_AUTH_USER}" && -n "${BASIC_AUTH_PASS}" ]]; then
  HTPASS="/etc/apache2/.htpasswdwaf"
  HASH="$(openssl passwd -apr1 "${BASIC_AUTH_PASS}")"
  printf '%s:%s\n' "${BASIC_AUTH_USER}" "${HASH}" > "${HTPASS}"
  chown root:www-data "${HTPASS}" 2>/dev/null || true
  chmod 640 "${HTPASS}" || true
  AUTH_BLOCK=$'<Location "/">\n    AuthType Basic\n    AuthName "Restricted WAF Dashboard"\n    AuthUserFile /etc/apache2/.htpasswdwaf\n    Require valid-user\n\n    ProxyPreserveHost On\n    ProxyRequests Off\n    ProxyPass        / unix:/run/wafcontrol/gunicorn.sock|http://localhost/\n    ProxyPassReverse / http://localhost/\n</Location>'
fi

if [[ "$MODE" == "domain" ]]; then
  a2enmod proxy proxy_http headers rewrite >/dev/null 2>&1 || true
  a2enmod ssl >/dev/null 2>&1 || true
  echo "ServerName ${DOMAIN}" > /etc/apache2/conf-available/servername.conf
  a2enconf servername >/dev/null 2>&1 || true

  cat > "$APACHE_CONF" <<APX
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}

    Alias /static/ "${STATIC_DIR}/static/"
    <Directory "${STATIC_DIR}/static/">
        Require all granted
        Options FollowSymLinks
        AllowOverride None
    </Directory>

    ProxyPass /static/ !
$( [[ -n "$AUTH_BLOCK" ]] && echo "$AUTH_BLOCK" || cat <<'NOAUTH'
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass        / unix:/run/wafcontrol/gunicorn.sock|http://localhost/
    ProxyPassReverse / http://localhost/
NOAUTH
)

    ErrorLog ${APACHE_LOG_DIR}/wafcontrol_error.log
    CustomLog ${APACHE_LOG_DIR}/wafcontrol_access.log combined
</VirtualHost>
APX

  a2ensite wafcontrol.conf >/dev/null 2>&1 || true
  apache2ctl configtest
  systemctl reload apache2

  if [[ "$SSL_ENABLE" -eq 1 ]]; then
    say "Installing certbot and enabling SSL for $DOMAIN"
    apt install -y certbot python3-certbot-apache
    EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
    certbot --apache -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || warn "Certbot failed"
  fi
else
  if ! grep -qE "^\s*Listen\s+${HTTP_PORT}\b" /etc/apache2/ports.conf 2>/dev/null; then
    echo "Listen ${HTTP_PORT}" >> /etc/apache2/ports.conf
  fi
  echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
  a2enconf servername >/dev/null 2>&1 || true

  cat > "$APACHE_CONF" <<APX
<VirtualHost *:${HTTP_PORT}>
    ServerName localhost

    Alias /static/ "${STATIC_DIR}/static/"
    <Directory "${STATIC_DIR}/static/">
        Require all granted
        Options FollowSymLinks
        AllowOverride None
    </Directory>

    ProxyPass /static/ !
$( [[ -n "$AUTH_BLOCK" ]] && echo "$AUTH_BLOCK" || cat <<'NOAUTH'
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass        / unix:/run/wafcontrol/gunicorn.sock|http://localhost/
    ProxyPassReverse / http://localhost/
NOAUTH
)

    ErrorLog ${APACHE_LOG_DIR}/wafcontrol_error.log
    CustomLog ${APACHE_LOG_DIR}/wafcontrol_access.log combined
</VirtualHost>
APX

  a2enmod proxy proxy_http headers rewrite >/dev/null 2>&1 || true
  a2ensite wafcontrol.conf >/dev/null 2>&1 || true
  apache2ctl configtest
  systemctl reload apache2
fi

state_append_array CREATED_FILES "$APACHE_CONF"
say "Apache vhost ready."
