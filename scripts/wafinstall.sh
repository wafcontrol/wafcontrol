#!/bin/bash
# scripts/wafinstall.sh
set -e
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

detect_server() {
  if systemctl is-active --quiet nginx; then echo nginx; return; fi
  if systemctl is-active --quiet apache2; then echo apache; return; fi
  if command -v nginx >/dev/null 2>&1; then echo nginx; return; fi
  if command -v apache2ctl >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1; then echo apache; return; fi
  echo none
}

SERVER="$(detect_server)"

if [[ "$SERVER" == "nginx" ]]; then
  echo "[+] Detected Nginx. Installing WAF for Nginx..."
  exec /bin/bash "$(dirname "$0")/install_nginx_waf.sh"
elif [[ "$SERVER" == "apache" ]]; then
  echo "[+] Detected Apache. Installing WAF for Apache..."
  exec /bin/bash "$(dirname "$0")/install_apache_waf.sh"
else
  echo "[?] No web server detected."
  echo "Choose web server to install WAF for:"
  select opt in "Nginx" "Apache" "Cancel"; do
    case "$opt" in
      Nginx) exec /bin/bash "$(dirname "$0")/install_nginx_waf.sh";;
      Apache) exec /bin/bash "$(dirname "$0")/install_apache_waf.sh";;
      Cancel) echo "Cancelled."; exit 1;;
      *) echo "Invalid choice";;
    esac
  done
fi
