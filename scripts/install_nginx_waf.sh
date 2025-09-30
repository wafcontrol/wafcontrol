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

banner "Nginx + ModSecurity v3 + CRS" "=" 72

# 1) Nginx presence
if ! command -v nginx >/dev/null 2>&1; then
  say "Installing Nginx from nginx.org..."
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  . /etc/os-release
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${ID} ${VERSION_CODENAME} nginx" > /etc/apt/sources.list.d/nginx.list
  apt update -y
  apt install -y nginx
  systemctl enable --now nginx
else
  say "Nginx detected."
fi

NGX_MAIN="/etc/nginx/nginx.conf"
[[ -f "$NGX_MAIN" ]] || { err "nginx.conf not found"; }

# Detect nginx user/group
detect_from_file() {
  local file="$1"
  [ -r "$file" ] || return 1
  grep -E '^[[:space:]]*user[[:space:]]+' "$file" \
    | sed -E 's/#.*$//' \
    | head -n1 \
    | sed -E 's/^[[:space:]]*user[[:space:]]+([^;[:space:]]+).*/\1/' \
    | tr -d '\n'
}
detect_nginx_user() {
  local u=""
  u="$(detect_from_file "$NGX_MAIN" || true)"
  if [ -z "$u" ] && command -v nginx >/dev/null 2>&1; then
    if timeout 3s nginx -T >/dev/null 2>&1; then
      u="$(nginx -T 2>/dev/null | grep -E '^[[:space:]]*user[[:space:]]+' | sed -E 's/#.*$//' | head -n1 | sed -E 's/^[[:space:]]*user[[:space:]]+([^;[:space:]]+).*/\1/' | tr -d '\n')" || true
    fi
  fi
  if [ -z "$u" ]; then
    u="$(ps -o user= -C nginx 2>/dev/null | head -n1 || true)"
  fi
  [ -n "$u" ] || u="nginx"
  echo "$u"
}
NGX_USER="$(detect_nginx_user)"
NGX_GROUP="$(id -gn "$NGX_USER" 2>/dev/null || echo "$NGX_USER")"
say "Detected nginx user: $NGX_USER (group: $NGX_GROUP)"

# 2) libmodsecurity
apt update -y
apt install -y libmodsecurity3 libmodsecurity-dev || true

if ! pkg-config --exists libmodsecurity; then
  say "Building libmodsecurity from source..."
  . /etc/os-release 2>/dev/null || true
  PCRE_PKGS="libpcre3 libpcre3-dev"
  if { [ "${ID:-}" = "debian" ] && [ "${VERSION_CODENAME:-}" = "trixie" ]; } || \
     { [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_CODENAME:-}" = "noble" ]; }; then
    PCRE_PKGS="libpcre2-dev"
  elif [ "${ID:-}" = "debian" ] && [ "${VERSION_CODENAME:-}" = "bookworm" ]; then
    PCRE_PKGS="libpcre3 libpcre3-dev libpcre2-dev"
  fi
  apt install -y make gcc autoconf automake libtool gettext pkg-config \
    libcurl4-openssl-dev liblua5.3-dev $PCRE_PKGS \
    libxml2 libxml2-dev libyajl-dev doxygen libgeoip-dev libssl-dev \
    zlib1g-dev libxslt1-dev liblmdb-dev libgd-dev git uuid-dev

  cd /usr/local/src
  test -d ModSecurity || git clone --depth 1 -b v3/master https://github.com/SpiderLabs/ModSecurity
  cd ModSecurity
  git submodule update --init
  ./build.sh
  ./configure
  make -j"$(nproc)"
  make install
  ldconfig
  say "libmodsecurity built and installed."
else
  say "libmodsecurity present via packages."
fi

# 3) Build dynamic module
test -d /usr/local/src/ModSecurity-nginx || git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx
NVER="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')" || NVER=""
[[ -n "$NVER" ]] || { err "Cannot detect Nginx version."; }

mkdir -p /usr/local/src/nginx && cd /usr/local/src/nginx
if [[ ! -d "nginx-${NVER}" ]]; then
  say "Fetching nginx source: ${NVER}"
  wget -q "http://nginx.org/download/nginx-${NVER}.tar.gz"
  tar -xzf "nginx-${NVER}.tar.gz"
fi

apt-get build-dep -y nginx || true
cd "nginx-${NVER}"
./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx
make modules
install -d /usr/share/nginx/modules
cp -f objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/
state_append_array CREATED_FILES "/usr/share/nginx/modules/ngx_http_modsecurity_module.so"
say "Dynamic module built."

# 4) Enable module + http directives
TS="$(date +%s)"
if ! grep -q 'ngx_http_modsecurity_module.so' "$NGX_MAIN" 2>/dev/null; then
  cp -a "$NGX_MAIN" "${NGX_MAIN}.bak.${TS}"
  state_put_map BACKUPS "$NGX_MAIN" "${NGX_MAIN}.bak.${TS}"
  sed -i '1iload_module /usr/share/nginx/modules/ngx_http_modsecurity_module.so;' "$NGX_MAIN"
  say "Injected load_module into nginx.conf"
fi

find_http_file() {
  if grep -q '^[[:space:]]*http[[:space:]]*{' "$NGX_MAIN"; then
    echo "$NGX_MAIN"; return
  fi
  awk 'BEGIN{h=0}/^[[:space:]]*http[[:space:]]*$/ {h=1} h && /^[[:space:]]*{/ {print FILENAME; exit}' "$NGX_MAIN" >/dev/null 2>&1 && { echo "$NGX_MAIN"; return; }
  local f
  f="$(grep -RIl --include='*.conf' '^[[:space:]]*http[[:space:]]*{' /etc/nginx 2>/dev/null | head -n1 || true)"
  [[ -n "$f" ]] && { echo "$f"; return; }
  f="$(awk 'FNR==1{fname=FILENAME}/^[[:space:]]*http[[:space:]]*$/ {h=1} h && /^[[:space:]]*{/ {print fname; exit}' /etc/nginx/*.conf /etc/nginx/*/*.conf 2>/dev/null | head -n1 || true)"
  [[ -n "$f" ]] && { echo "$f"; return; }
  echo ""
}
HTTP_FILE="$(find_http_file)"
[[ -n "$HTTP_FILE" ]] || { err "Could not locate a file containing the http { } block."; }

MDIR="/etc/nginx/modsec"
mkdir -p "$MDIR"

# Robust creation of modsecurity.conf from a recommended template when available
copy_recommended_modsec_conf() {
  local c
  for c in \
    "/etc/modsecurity/modsecurity.conf-recommended" \
    "/usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended" \
    "/usr/share/doc/modsecurity-crs/examples/modsecurity.conf-recommended.gz" \
    "/usr/local/src/ModSecurity/modsecurity.conf-recommended"
  do
    if [[ -f "$c" ]]; then
      if [[ "$c" == *.gz ]]; then
        zcat "$c" > "$MDIR/modsecurity.conf"
      else
        cp -f "$c" "$MDIR/modsecurity.conf"
      fi
      return 0
    fi
  done
  return 1
}

if [[ ! -f "$MDIR/modsecurity.conf" ]]; then
  if copy_recommended_modsec_conf; then
    say "modsecurity.conf created from recommended template."
  else
    cat > "$MDIR/modsecurity.conf" <<'CONF'
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
CONF
    warn "Using minimal modsecurity.conf fallback."
  fi
fi

# Ensure unicode.mapping if available
for um in \
  "/etc/modsecurity/unicode.mapping" \
  "/usr/share/doc/modsecurity-crs/examples/unicode.mapping" \
  "/usr/local/src/ModSecurity/unicode.mapping"
do
  if [[ -f "$um" ]]; then
    cp -f "$um" "$MDIR/unicode.mapping"
    break
  fi
done

# Enforce SecRuleEngine On
sed -i -E 's/^\s*SecRuleEngine\s+DetectionOnly/SecRuleEngine On/i' "$MDIR/modsecurity.conf" || true
grep -qE '^\s*SecRuleEngine\s+' "$MDIR/modsecurity.conf" || echo "SecRuleEngine On" >> "$MDIR/modsecurity.conf"

MAIN="$MDIR/main.conf"
if [[ ! -f "$MAIN" ]]; then
  { echo "# WAFCONTROL main config"; echo "Include $MDIR/modsecurity.conf"; } > "$MAIN"
fi
state_append_array CREATED_FILES "$MAIN"
state_append_array CREATED_FILES "$MDIR/modsecurity.conf"

if ! grep -q 'WAFCONTROL-BEGIN' "$HTTP_FILE"; then
  cp -a "$HTTP_FILE" "${HTTP_FILE}.bak.${TS}"
  state_put_map BACKUPS "$HTTP_FILE" "${HTTP_FILE}.bak.${TS}"
  awk '
  BEGIN{done=0; seen_http=0}
  {
    if (done) { print; next }
    if ($0 ~ /^[[:space:]]*http[[:space:]]*{/ && !done) {
      print
      print "    # WAFCONTROL-BEGIN"
      print "    modsecurity on;"
      print "    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
      print "    # WAFCONTROL-END"
      done=1; next
    }
    if (!done && $0 ~ /^[[:space:]]*http[[:space:]]*$/) { print; seen_http=1; next }
    if (!done && seen_http && $0 ~ /^[[:space:]]*{/ ) {
      print
      print "    # WAFCONTROL-BEGIN"
      print "    modsecurity on;"
      print "    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
      print "    # WAFCONTROL-END"
      done=1; seen_http=0; next
    }
    print
  }' "$HTTP_FILE" > "${HTTP_FILE}.new"
  mv "${HTTP_FILE}.new" "$HTTP_FILE"
  say "Inserted WAF block into: $HTTP_FILE"
else
  warn "WAF block already present in $HTTP_FILE; skipping insert."
fi

# 5) CRS
say "Fetching latest CRS..."
TAG="$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name' || true)"
CRS_DIR=""
if [[ -n "$TAG" && "$TAG" != "null" ]]; then
  NUM="${TAG#v}"
  CRS_DIR="$MDIR/coreruleset-${NUM}"
  if [[ ! -d "$CRS_DIR" ]]; then
    TMPD="$(mktemp -d -t crs-XXXXXX)"
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${TAG}.tar.gz" -O "$TMPD/crs.tgz"
    tar -xzf "$TMPD/crs.tgz" -C "$TMPD"
    mv "$TMPD/coreruleset-${NUM}" "$CRS_DIR"
    rm -rf "$TMPD"
    say "CRS downloaded: ${TAG}"
  else
    say "CRS already present: ${CRS_DIR}"
  fi
else
  if [[ -d /usr/share/modsecurity-crs/rules ]]; then
    CRS_DIR="$MDIR/coreruleset-packaged"
    [[ -d "$CRS_DIR" ]] || cp -a /usr/share/modsecurity-crs "$CRS_DIR"
    say "CRS fallback to packaged copy."
  else
    err "Failed to resolve latest CRS and no packaged CRS found."
  fi
fi
[[ -d "$CRS_DIR" ]] || { err "CRS directory missing: $CRS_DIR"; }
[[ -f "$CRS_DIR/crs-setup.conf" ]] || { [[ -f "$CRS_DIR/crs-setup.conf.example" ]] && cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"; }
for f in REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf; do
  [[ -f "$CRS_DIR/rules/$f" ]] || { [[ -f "$CRS_DIR/rules/${f}.example" ]] && cp "$CRS_DIR/rules/$f.example" "$CRS_DIR/rules/${f}" || true; }
done
EXCL="$CRS_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
if ! grep -q '/crs/rules/save/' "$EXCL" 2>/dev/null; then
  cat >> "$EXCL" <<'EOR'
# WAF dashboard exclusions
SecRule REQUEST_URI "@beginsWith /crs/rules/save/"        "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
fi
sed -i '/Include .*crs-setup.conf/d' "$MAIN" || true
sed -i '/Include .*rules\/\*.conf/d' "$MAIN" || true
{
  echo "Include $CRS_DIR/crs-setup.conf"
  echo "Include $CRS_DIR/rules/*.conf"
} >> "$MAIN"
state_append_array CRS_DIRS "$CRS_DIR"
say "CRS wired: $(basename "$CRS_DIR")"

# 6) App vhost (+ optional Basic Auth)
VHOST="/etc/nginx/conf.d/wafcontrol.conf"
AUTH_SNIPPET=""
if [[ "${BASIC_AUTH_ENABLE}" = "1" && -n "${BASIC_AUTH_USER}" && -n "${BASIC_AUTH_PASS}" ]]; then
  HTPASS="/etc/nginx/.htpasswdwaf"
  HASH="$(openssl passwd -apr1 "${BASIC_AUTH_PASS}")"
  printf '%s:%s\n' "${BASIC_AUTH_USER}" "${HASH}" > "${HTPASS}"
  chown root:"$NGX_GROUP" "${HTPASS}" || true
  chmod 640 "${HTPASS}" || true
  AUTH_SNIPPET=$'    auth_basic "Restricted WAF Dashboard";\n    auth_basic_user_file /etc/nginx/.htpasswdwaf;'
fi

if [[ "$MODE" == "domain" ]]; then
  cat > "$VHOST" <<NGX
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};

    access_log /var/log/nginx/wafcontrol_access.log;
    error_log  /var/log/nginx/wafcontrol_error.log;

    location /static/ {
        alias ${STATIC_DIR}/static/;
        autoindex off;
    }

    location / {
${AUTH_SNIPPET}
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_pass http://unix:${RUNTIME_DIR}/gunicorn.sock;
    }
}
NGX
  state_append_array CREATED_FILES "$VHOST"
  say "App vhost written: $VHOST (port 80)"

  if [[ "$SSL_ENABLE" -eq 1 ]]; then
    say "Installing certbot and enabling SSL for ${DOMAIN}"
    apt install -y certbot python3-certbot-nginx
    EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || warn "Certbot failed"
  fi
else
  cat > "$VHOST" <<NGX
server {
    listen ${HTTP_PORT};
    server_name _;

    access_log /var/log/nginx/wafcontrol_access.log;
    error_log  /var/log/nginx/wafcontrol_error.log;

    location /static/ {
        alias ${STATIC_DIR}/static/;
        autoindex off;
    }

    location / {
${AUTH_SNIPPET}
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_pass http://unix:${RUNTIME_DIR}/gunicorn.sock;
    }
}
NGX
  state_append_array CREATED_FILES "$VHOST"
  say "App vhost written: $VHOST (port ${HTTP_PORT})"
fi

# 7) Test & reload
if nginx -t; then
  systemctl reload nginx
  say "Nginx WAF ready (ModSecurity v3 + CRS)."
else
  err "nginx -t failed. Check the configuration."
fi
