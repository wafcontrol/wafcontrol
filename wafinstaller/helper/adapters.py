import os
import re
import json
import subprocess
from dataclasses import dataclass

@dataclass
class Paths:
    name: str
    modsec_conf: str
    rules_dir_tmpl: str
    custom_after_tmpl: str
    audit_log: str
    test_cmd: list
    reload_cmd: list

NGINX_PATHS = Paths(
    name="nginx",
    modsec_conf="/etc/nginx/modsec/modsecurity.conf",
    rules_dir_tmpl="/etc/nginx/modsec/coreruleset-{ver}/rules",
    custom_after_tmpl="/etc/nginx/modsec/coreruleset-{ver}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
    audit_log="/var/log/modsec_audit.log",
    test_cmd=["nginx", "-t"],
    reload_cmd=["nginx", "-s", "reload"],
)

APACHE_PATHS = Paths(
    name="apache",
    modsec_conf="/etc/modsecurity/modsecurity.conf",
    rules_dir_tmpl="/usr/share/modsecurity-crs-{ver}/rules",
    custom_after_tmpl="/usr/share/modsecurity-crs-{ver}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
    audit_log="/var/log/modsec_audit.log",
    test_cmd=["apache2ctl", "configtest"],
    reload_cmd=["apache2ctl", "-k", "graceful"],
)

def _run_basic_script():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(base_dir, "../../scripts", "basic.sh")
    try:
        out = subprocess.check_output(["/bin/bash", script], text=True, stderr=subprocess.STDOUT)
        return json.loads(out)
    except Exception:
        return {"server": "none", "waf": {"version": ""}}

def detect_server():
    info = _run_basic_script()
    return info.get("server") or "none"

def get_paths():
    server = detect_server()
    return NGINX_PATHS if server == "nginx" else (APACHE_PATHS if server == "apache" else NGINX_PATHS)

def detect_crs_version():
    info = _run_basic_script()
    ver = (info.get("waf") or {}).get("version")
    if ver:
        return ver.strip()
    # Fallback Nginx
    try:
        with open("/etc/nginx/modsec/main.conf", "r") as f:
            m = re.search(r'coreruleset-([0-9]+\.[0-9]+(?:\.[0-9]+)?)', f.read())
            if m:
                return m.group(1)
    except Exception:
        pass
    # Fallback Apache
    try:
        setup = os.path.realpath("/etc/modsecurity/crs-setup.conf")
        m = re.search(r'modsecurity-crs-([0-9]+\.[0-9]+(?:\.[0-9]+)?)', setup)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def rules_dir(ver: str) -> str:
    p = get_paths()
    return p.rules_dir_tmpl.format(ver=ver)

def custom_after_path(ver: str) -> str:
    p = get_paths()
    return p.custom_after_tmpl.format(ver=ver)
