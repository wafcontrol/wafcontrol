# Detect Attack When Nginx Webserver in Enabled
import os, re, io, glob, stat, json, hashlib, time
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple

JSON_TXN_KEYS = ("transaction", "messages")

SECTION_A_HEADER = re.compile(r'^\[(?P<ts>[^]]+)\]\s+(?P<uid>\S+)\s+(?P<src>[0-9A-Fa-f:.]+)\s+(?P<src_port>\d+)\s+(?P<dst>[0-9A-Fa-f:.]+)\s+(?P<dst_port>\d+)\s*$')
UID_RE   = re.compile(r'\[unique_id "([^"]+)"\]')
URI_RE   = re.compile(r'\[uri "([^"]+)"\]')
MSG_RE   = re.compile(r'\[msg "([^"]+)"\]')
RID_RE   = re.compile(r'\[id "(\d+)"\]')
VER_RE   = re.compile(r'\[ver "([^"]+)"\]')
REFERER_RE = re.compile(r'REQUEST_HEADERS:Referer:\s*([^\]\n]+)')
TAGS_RE  = re.compile(r'\[tag "([^"]+)"\]')
REQ_LINE_RE = re.compile(r'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)', re.I)
H_LINE_RE = re.compile(r'^ModSecurity:.*$', re.M)

ERR_UID_IP_PATTERNS = [
    re.compile(r'\[unique_id "([^"]+)"\].*?client:\s*(\d{1,3}(?:\.\d{1,3}){3})', re.I),
    re.compile(r'\bunique_id[" ]+([^"\s]+).*?\bclient(?:\s+IP)?:\s*(\d{1,3}(?:\.\d{1,3}){3})', re.I),
]
IP_FALLBACKS = [
    re.compile(r'Client IP:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', re.I),
    re.compile(r'"client_ip"\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"', re.I),
    re.compile(r'"src_ip"\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"', re.I),
    re.compile(r'client:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', re.I),
]

STATIC_EXT_RE = re.compile(r'\.(?:js|css|png|jpg|jpeg|gif|ico|svg|webp|woff2?|ttf|eot|map|mp4|mp3|avi|mov|zip|tar|gz|7z|rar)$', re.I)
STATIC_PATH_HINTS = ("/static/", "/assets/", "/media/", "/favicon.ico")

IMPORTANT_FAMILIES = ("942","930","932","941","931","933")
SUPPRESS_FAMILIES = ("920","949")
IMPORTANT_KEYWORDS = ["sql","xss","rce","command injection","os command","traversal","lfi","rfi","injection","path traversal","php injection","remote code","eval","system(","cmd=","base64_decode"]

ACCESS_LINE_RE = re.compile(r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<m>\S+)\s+(?P<target>\S+)\s+(?P<p>\S+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
ACCESS_SEL_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3} ')

NGX_LOG_RE = re.compile(r'^\s*(access_log|error_log)\s+([^ \t;]+)', re.I)
AP_LOG_ERR_RE = re.compile(r'^\s*ErrorLog\s+("?)([^"\s]+)\1', re.I)
AP_LOG_ACC_RE = re.compile(r'^\s*CustomLog\s+("?)([^"\s]+)\1\s+(\S+)', re.I)
SEC_AUDIT_RE = re.compile(r'^\s*SecAuditLog\s+("?)([^"\s]+)\1', re.I)
SEC_AUDIT_DIR_RE = re.compile(r'^\s*SecAuditLogStorageDir\s+("?)([^"\s]+)\1', re.I)

HOSTNAME_TAG_RE = re.compile(r'\[hostname "([^"]+)"\]')
HOST_HEADER_RE  = re.compile(r'REQUEST_HEADERS:Host:\s*([^\]\s]+)', re.I)
SECTION_A_LINE  = re.compile(r'^\[(?P<ts>[^]]+)\]\s+(?P<uid>\S+)\s+(?P<src>[0-9A-Fa-f:.]+)\s+(?P<src_port>\d+)\s+(?P<dst>[0-9A-Fa-f:.]+)\s+(?P<dst_port>\d+)\s*$', re.M)

# Apache double-dash markers (Serial audit without Z)
MARKER_A_DBL = re.compile(r'^--([A-Za-z0-9+/=_-]+)-A--\s*$')
MARKER_ANY_DBL = re.compile(r'^--([A-Za-z0-9+/=_-]+)-([A-Z])--\s*$')

ERROR_H_LINE = re.compile(r'ModSecurity:\s.*\[id\s*"(\d+)"\].*?(\[msg\s*"([^"]+)"\])?.*?(\[uri\s*"([^"]+)"\])?.*?(\[unique_id\s*"([^"]+)"\])?', re.I)

def _file_tail_bytes(path: str, start: int) -> str:
    with open(path, "rb") as f:
        f.seek(start)
        buf = f.read()
    return buf.decode("utf-8", errors="ignore")

def _audit_ckpt_for(path: str, ckpt: dict):
    prev = ckpt.get("audit_files", {}).get(path, {})
    try:
        st = os.stat(path)
        return prev, st.st_ino, st.st_size, st.st_mode
    except Exception:
        return prev, None, 0, 0

def is_ip(v: Optional[str]) -> bool:
    try:
        ip_address(v or ""); return True
    except Exception:
        return False

def looks_static(uri: Optional[str]) -> bool:
    if not uri: return False
    return any(h in uri for h in STATIC_PATH_HINTS) or bool(STATIC_EXT_RE.search(uri))

def blocked_from_block_text(block: str) -> bool:
    return ("Access denied with code" in block) or ("Access denied" in block)

def extract_first(regex: re.Pattern, text: str, default: str = "") -> str:
    m = regex.search(text); return m.group(1) if m else default

def extract_all(regex: re.Pattern, text: str):
    return regex.findall(text)

def tail_lines(path: str, n: int) -> List[str]:
    try:
        with open(path, "rb") as f:
            avg = 220; size = n * avg
            try: f.seek(-size, io.SEEK_END)
            except Exception: f.seek(0)
            data = f.read().decode("utf-8", errors="ignore")
            return [ln for ln in data.splitlines() if ln]
    except Exception:
        return []

def map_uid_to_ip_from_errorlogs(paths: List[str], tail_n: int) -> Dict[str, str]:
    mapping = {}
    for p in paths:
        if not p or not os.path.exists(p): continue
        lines = tail_lines(p, tail_n)
        for line in lines:
            for pat in ERR_UID_IP_PATTERNS:
                m = pat.search(line)
                if m:
                    uid, ip = m.group(1), m.group(2)
                    if uid and is_ip(ip): mapping[uid] = ip
    return mapping

def split_sections(block: str):
    sections = {}; current_key = None
    for line in block.splitlines():
        m = re.match(r'^---[A-Za-z0-9+/=_-]+---([A-Z])--$', line.strip())
        if m: current_key = m.group(1); sections.setdefault(current_key, []); continue
        if current_key: sections[current_key].append(line.rstrip("\n"))
    return sections

def split_sections_lenient(block: str):
    sections = {}; cur_key = None
    for raw in block.splitlines():
        ln = raw.strip()
        m1 = re.match(r'^---[A-Za-z0-9+/=_-]+---([A-Z])--\s*$', ln)
        m2 = MARKER_ANY_DBL.match(ln)
        if m1 or m2:
            cur_key = (m1.group(1) if m1 else m2.group(2))
            sections.setdefault(cur_key, []); continue
        if cur_key: sections[cur_key].append(raw)
    return sections

def uid_ip_from_section_a(block: str):
    for line in block.splitlines():
        m = SECTION_A_HEADER.match(line.strip())
        if m:
            uid = m.group("uid"); src = m.group("src")
            return uid, (src if is_ip(src) else None)
    return None, None

def uid_ip_from_A_sections(sections: Dict[str, List[str]]):
    if "A" not in sections: return None, None
    for ln in sections["A"]:
        m = SECTION_A_HEADER.match(ln.strip())
        if m:
            uid = m.group("uid"); src = m.group("src")
            return uid, (src if is_ip(src) else None)
    return None, None

def uri_from_section_b(sec_b_lines: List[str]) -> Optional[str]:
    for ln in sec_b_lines:
        m = REQ_LINE_RE.match(ln.strip())
        if m: return m.group(2)
    return None

def uri_from_B_sections(sections: Dict[str, List[str]]) -> Optional[str]:
    if "B" not in sections: return None
    for ln in sections["B"]:
        m = REQ_LINE_RE.match(ln.strip())
        if m: return m.group(2)
    return None


def important_enough(msg: str, tags: List[str], blocked: bool, include_protocol_anomalies: bool) -> bool:
    if blocked:
        return True

    msg_lower = (msg or "").lower()
    tags_lower = [t.lower() for t in tags]
    tags_joined = " ".join(tags_lower)

    important_patterns = [
        "sql", "xss", "rce", "command injection", "os command",
        "traversal", "lfi", "rfi", "injection", "path traversal",
        "php injection", "remote code", "eval", "system(", "cmd=",
        "base64_decode", "libinjection"
    ]

    for pattern in important_patterns:
        if pattern in msg_lower or any(pattern in tag for tag in tags_lower):
            return True

    critical_tags = {"xss", "sqli", "lfi", "rfi", "injection", "rce"}
    if any(tag in tags_lower for tag in critical_tags):
        return True

    return True

    # return False

def parse_audit_blocks_incremental(audit_path: str, ckpt: dict, max_tail_bytes: int = 2_000_000, max_blocks_on_rotate: int = 400) -> List[str]:
    if not os.path.exists(audit_path): return []
    prev, inode, size, mode = _audit_ckpt_for(audit_path, ckpt)
    if inode is None or not stat.S_ISREG(mode): return []
    start = prev["offset"] if prev.get("inode") == inode and isinstance(prev.get("offset"), int) and prev["offset"] <= size else max(0, size - max_tail_bytes)
    text = _file_tail_bytes(audit_path, start)
    if re.search(r'^---[A-Za-z0-9+/=_-]+---[A-Z]--\s*$', text, re.M):
        blocks = []
        current_id, current_lines = None, []
        marker_re = re.compile(r'^---([A-Za-z0-9+/=_-]+)---([A-Z])--\s*$', re.M)
        for raw in text.splitlines():
            line = raw.rstrip("\n")
            m = marker_re.match(line)
            if m:
                rid, sec = m.group(1), m.group(2)
                if current_id is None:
                    current_id = rid; current_lines = [line]
                else:
                    if rid != current_id:
                        if current_lines: blocks.append("\n".join(current_lines))
                        current_id = rid; current_lines = [line]
                    else:
                        current_lines.append(line)
                if sec == "Z":
                    blocks.append("\n".join(current_lines)); current_id = None; current_lines = []
            else:
                if current_id is not None: current_lines.append(line)
        if current_id is not None and current_lines: blocks.append("\n".join(current_lines))
        if start != prev.get("offset") and max_blocks_on_rotate > 0: blocks = blocks[-max_blocks_on_rotate:]
    else:
        blocks = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s[0] not in "{[": continue
            try:
                obj = json.loads(s)
            except Exception:
                continue
            if not all(k in obj for k in JSON_TXN_KEYS):
                if "transaction" not in obj: continue
                obj.setdefault("messages", [])
            blk = _json_to_pseudoblock(obj)
            if blk: blocks.append(blk)
        if start != prev.get("offset") and max_blocks_on_rotate > 0: blocks = blocks[-max_blocks_on_rotate:]
    ck = ckpt.setdefault("audit_files", {}); ck[audit_path] = {"inode": inode, "offset": size}
    return blocks

def read_audit_blocks_serial_without_z(path: str, max_bytes: int = 8_000_000) -> List[str]:
    if not os.path.exists(path): return []
    try:
        size = os.path.getsize(path)
        start = max(0, size - max_bytes)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            if start: f.seek(start)
            lines = f.read().splitlines()
    except Exception:
        return []
    blocks, cur_id, cur_lines = [], None, []
    for ln in lines:
        mA = MARKER_A_DBL.match(ln)
        if mA:
            if cur_id is not None and cur_lines: blocks.append("\n".join(cur_lines))
            cur_id, cur_lines = mA.group(1), [ln]; continue
        if cur_id is not None: cur_lines.append(ln)
    if cur_id is not None and cur_lines: blocks.append("\n".join(cur_lines))
    return blocks

def _json_to_pseudoblock(obj: dict) -> str:
    t = obj.get("transaction", {}) or {}
    msgs = obj.get("messages", []) or []
    uid = t.get("id") or t.get("unique_id") or t.get("uniqueId") or f"{t.get('time','')}.{int(time.time()*1000)%100000}"
    src = t.get("client_ip") or t.get("remote_address") or ""
    dst = t.get("server_ip") or t.get("destination_address") or ""
    sport = str(t.get("client_port") or t.get("remote_port") or "")
    dport = str(t.get("server_port") or "")
    host = ""
    req = t.get("request", {}) or {}
    uri  = req.get("uri") or (req.get("request_line", "").split(" ")[1] if "request_line" in req else "")
    headers = req.get("headers", {}) or {}
    host = headers.get("Host") or headers.get("host") or ""
    ver = obj.get("producer", {}).get("version") or t.get("producer", {}).get("version") or ""
    ref = (t.get("referrer") or "") if isinstance(t.get("referrer"), str) else ""
    lines = []
    rid = hashlib.sha1(uid.encode()).hexdigest()[:8]
    lines.append(f"---{rid}---A--")
    lines.append(f"[{t.get('time','')}] {uid} {src or '-'} {sport or '0'} {dst or '-'} {dport or '0'}")
    lines.append(f"---{rid}---H--")
    for m in msgs:
        rule = m.get("details", {}) or {}
        mid = str(rule.get("ruleId") or rule.get("rule_id") or "")
        mver = rule.get("ver") or ver or ""
        mmsg = m.get("message") or rule.get("msg") or ""
        sev = str(rule.get("severity") or "")
        acc = str(rule.get("accuracy") or "")
        mat = str(rule.get("maturity") or "")
        parts = [
            "ModSecurity:", "Warning.",
            f'[id "{mid}"]' if mid else "",
            f'[msg "{mmsg}"]' if mmsg else "",
            f'[ver "{mver}"]' if mver else "",
            f'[severity "{sev}"]' if sev else "",
            f'[accuracy "{acc}"]' if acc else "",
            f'[maturity "{mat}"]' if mat else "",
            f'[hostname "{host}"]' if host else "",
            f'[uri "{uri}"]' if uri else "",
            f'[unique_id "{uid}"]',
        ]
        lines.append(" ".join(p for p in parts if p))
    if obj.get("intervention") or (t.get("response", {}).get("http_code") in (403, 406, 501)):
        lines.append(f'ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded"] [ver "{ver}"] [hostname "{host}"] [uri "{uri}"] [unique_id "{uid}"]')
    lines.append(f"---{rid}---Z--")
    return "\n".join(lines)

def parse_rule_hits(block: str) -> List[Tuple[str, str]]:
    hits = []
    for line in H_LINE_RE.findall(block):
        rid = extract_first(RID_RE, line); msg = extract_first(MSG_RE, line)
        if rid or msg: hits.append((rid or "", msg or ""))
    return hits

def extract_hits_from_sections(sections: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    hits = []
    for ln in sections.get("H", []):
        ids = extract_all(RID_RE, ln)
        if not ids: continue
        mmsg = MSG_RE.search(ln)
        msg = mmsg.group(1) if mmsg else ""
        for rid in ids:
            hits.append((rid, msg))
    return hits


def filter_rule_hits(hits: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    filtered_hits = []

    for rid, msg in hits:
        if not rid:
            continue

        family = rid[:3]

        if family in SUPPRESS_FAMILIES:
            continue

        filtered_hits.append((rid, msg))

    return filtered_hits

def build_sig(ip: str, uri: str, rid: str, msg: str, ver: str, status: str) -> str:
    return hashlib.sha1(f"{ip}|{uri}|{rid}|{msg}|{ver}|{status}".encode()).hexdigest()

def map_ip_to_recent_targets(paths: List[str], tail_n: int = 20000) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for p in paths:
        if not p or not os.path.exists(p): continue
        lines = tail_lines(p, tail_n)
        for ln in lines:
            if not ACCESS_SEL_RE.match(ln): continue
            m = ACCESS_LINE_RE.match(ln)
            if not m: continue
            ip = m.group("ip"); target = m.group("target")
            if not ip or not target: continue
            out.setdefault(ip, []).append(target)
    return out

def pick_best_target(ip: str, base_uri: str, candidates: List[str]) -> Optional[str]:
    if not candidates: return None
    for t in reversed(candidates):
        if base_uri and t.startswith(base_uri): return t
    for t in reversed(candidates):
        if base_uri and base_uri in t: return t
    return candidates[-1]

def _read(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f: return f.read().splitlines()
    except Exception:
        return []

def _resolve_vars(s: str) -> str:
    s = s.replace("${APACHE_LOG_DIR}", "/var/log/apache2")
    s = s.replace("$APACHE_LOG_DIR", "/var/log/apache2")
    s = s.replace("${NGINX_LOG_DIR}", "/var/log/nginx")
    s = s.replace("$NGINX_LOG_DIR", "/var/log/nginx")
    return s

def discover_nginx_logs() -> Tuple[List[str], List[str]]:
    files = []; roots = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*"]
    for pat in roots:
        if "*" in pat: files.extend(glob.glob(pat))
        elif os.path.exists(pat): files.append(pat)
    acc, err = set(), set()
    for p in files:
        for ln in _read(p):
            m = NGX_LOG_RE.match(ln)
            if not m: continue
            k, v = m.group(1).lower(), _resolve_vars(m.group(2))
            if v.startswith("syslog:"): continue
            if k == "access_log": acc.add(v)
            elif k == "error_log": err.add(v)
    return sorted(acc), sorted(err)

def discover_apache_logs() -> Tuple[List[str], List[str]]:
    files = []; roots = ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/sites-enabled/*", "/etc/apache2/conf-available/*.conf", "/etc/httpd/conf.d/*.conf", "/etc/apache2/mods-enabled/*.load", "/etc/apache2/mods-enabled/*.conf"]
    for pat in roots:
        if "*" in pat: files.extend(glob.glob(pat))
        elif os.path.exists(pat): files.append(pat)
    acc, err = set(), set()
    for p in files:
        for ln in _read(p):
            m1 = AP_LOG_ERR_RE.match(ln)
            if m1: err.add(_resolve_vars(m1.group(2))); continue
            m2 = AP_LOG_ACC_RE.match(ln)
            if m2: acc.add(_resolve_vars(m2.group(2))); continue
    return sorted(acc), sorted(err)

def discover_apache_audit_targets() -> Tuple[List[str], List[str]]:
    files = []; roots = ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/sites-enabled/*", "/etc/apache2/conf-available/*.conf", "/etc/httpd/conf.d/*.conf", "/etc/apache2/mods-enabled/*.conf", "/etc/modsecurity/*.conf", "/etc/apache2/modsecurity.d/*.conf"]
    confs = []
    for pat in roots:
        if "*" in pat: confs.extend(glob.glob(pat))
        elif os.path.exists(pat): confs.append(pat)
    audit_files, audit_dirs = set(), set()
    for p in confs:
        for ln in _read(p):
            m1 = SEC_AUDIT_RE.match(ln)
            if m1: audit_files.add(_resolve_vars(m1.group(2)))
            m2 = SEC_AUDIT_DIR_RE.match(ln)
            if m2: audit_dirs.add(_resolve_vars(m2.group(2)))
    for g in glob.glob("/var/log/apache2/*modsec*.log"): audit_files.add(g)
    for g in glob.glob("/var/log/apache2/*audit*.log"): audit_files.add(g)
    return sorted(audit_files), sorted(audit_dirs)

def extract_host(block: str) -> str:
    h = extract_first(HOSTNAME_TAG_RE, block)
    if h: return h
    h = extract_first(HOST_HEADER_RE, block)
    if h: return h
    m = SECTION_A_LINE.search(block)
    if m:
        dst = m.group("dst"); dport = m.group("dst_port")
        if dport and dport not in ("80","443"): return f"{dst}:{dport}"
        return dst
    return ""

def read_concurrent_audit_dir(dir_path: str, ckpt: dict, max_new: int = 400) -> List[str]:
    if not os.path.isdir(dir_path): return []
    seen = set(ckpt.get("concurrent_seen", {}).get(dir_path, []))
    all_files = sorted([p for p in glob.glob(os.path.join(dir_path, "*")) if os.path.isfile(p)], key=os.path.getmtime)
    new_files = [p for p in all_files if os.path.basename(p) not in seen][-max_new:]
    blocks = []
    for p in new_files:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            if data.strip().startswith("{"):
                try:
                    obj = json.loads(data)
                    blk = _json_to_pseudoblock(obj)
                    if blk: blocks.append(blk)
                except Exception:
                    pass
            else:
                blocks.append(data)
        except Exception:
            continue
    s = ckpt.setdefault("concurrent_seen", {})
    s[dir_path] = list((seen | set(os.path.basename(p) for p in new_files)))[-5000:]
    return blocks

def blocks_from_errorlogs(paths: List[str], tail_n: int = 12000) -> List[str]:
    out = []
    for p in paths:
        if not p or not os.path.exists(p): continue
        lines = tail_lines(p, tail_n)
        group = {}
        for ln in lines:
            if "ModSecurity:" not in ln: continue
            m = ERROR_H_LINE.search(ln)
            if not m: continue
            rid = m.group(1) or ""
            msg = m.group(3) or ""
            uri = m.group(5) or ""
            uid = m.group(7) or hashlib.sha1(ln.encode()).hexdigest()[:10]
            key = uid
            group.setdefault(key, []).append((rid, msg, uri, uid, ln))
        for uid, items in group.items():
            rid = hashlib.sha1(uid.encode()).hexdigest()[:8]
            lines_out = [f"---{rid}---H--"]
            uri = ""
            for r, mmsg, u, u2, raw in items:
                uri = uri or u
                # avoid f-string backslash in expression
                if uri:
                    lines_out.append('ModSecurity: Warning. [id "%s"] [msg "%s"] [uri "%s"] [unique_id "%s"]' % (r, mmsg, uri, uid))
                else:
                    lines_out.append('ModSecurity: Warning. [id "%s"] [msg "%s"] [unique_id "%s"]' % (r, mmsg, uid))
            lines_out.append(f"---{rid}---Z--")
            out.append("\n".join(lines_out))
    return out

def discover_all_paths():
    ngx_acc, ngx_err = discover_nginx_logs()
    ap_acc, ap_err = discover_apache_logs()
    ap_audit_files, ap_audit_dirs = discover_apache_audit_targets()
    defaults = ["/var/log/modsec_audit.log", "/var/log/nginx/modsec_audit.log", "/var/log/apache2/modsec_audit.log"]
    audit_files = [p for p in (defaults + ap_audit_files) if os.path.exists(p)]
    audit_dirs = [d for d in ap_audit_dirs if os.path.isdir(d)]
    error_logs = [p for p in ("/var/log/nginx/error.log", "/var/log/apache2/error.log", *ngx_err, *ap_err) if os.path.exists(p)]
    access_logs = [p for p in ("/var/log/nginx/access.log", "/var/log/apache2/access.log", *ngx_acc, *ap_acc) if os.path.exists(p)]
    return {
        "audit_files": sorted(set(audit_files)),
        "audit_dirs": sorted(set(audit_dirs)),
        "error_logs": sorted(set(error_logs)),
        "access_logs": sorted(set(access_logs)),
    }


def extract_severity_from_log(block: str, rid: str) -> int:
    """Extract severity number from ModSecurity log block."""
    severity_pattern = re.compile(r'\[severity\s+"(\d+)"\]')
    match = severity_pattern.search(block)
    if match:
        return int(match.group(1))

    # Fallback based on Rule ID family
    if rid:
        family = rid[:3]
        if family in ("942", "932", "941"):  # SQLi, RCE, XSS
            return 3
        elif family == "930":  # LFI
            return 2
        elif family == "920":  # Protocol anomalies
            return 1
        elif family == "949":  # Anomaly score rules
            return 0

    return 2  # Default medium

def extract_anomaly_score(block: str) -> int:
    """Extract CRS anomaly score from log block."""
    score_pattern = re.compile(r'Total Score:\s*(\d+)')
    match = score_pattern.search(block)
    if match:
        return int(match.group(1))

    # fallback for 949 rules
    if "949110" in block and "Total Score:" in block:
        for line in block.splitlines():
            if "Total Score:" in line:
                parts = line.split("Total Score:")
                if len(parts) > 1:
                    try:
                        return int(parts[1].strip().split(')')[0])
                    except ValueError:
                        pass
    return 0

def determine_status(severity: int, anomaly_score: int, blocked: bool) -> str:
    """Determine final attack status based on severity, score, and blocked flag."""
    if blocked:
        return "Blocked"
    if severity >= 3 or anomaly_score >= 10:
        return "Critical"
    elif severity == 2 or anomaly_score >= 5:
        return "High"
    elif severity == 1:
        return "Medium"
    else:
        return "Low"