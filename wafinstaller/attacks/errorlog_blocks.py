"""Rebuild audit-log-like blocks from web server error logs (fallback when no audit log is readable)."""
import hashlib
import re
from typing import Dict, List

UID_RE = re.compile(r'\[unique_id "([^"]+)"\]')
# nginx: "[client 1.2.3.4]" / ", client: 1.2.3.4"; Apache: "[client 1.2.3.4:5678]" (or [::1]:port)
CLIENT_RES = [
    re.compile(r'\[client ([0-9a-fA-F:.]+?)(?::\d+)?\]'),
    re.compile(r', client: ([0-9a-fA-F:.]+)'),
]
NGX_REQUEST_RE = re.compile(r', request: "((?:[^"\\]|\\.)*)"')
NGX_HOST_RE = re.compile(r', host: "((?:[^"\\]|\\.)*)"')
NGX_REFERRER_RE = re.compile(r', referrer: "((?:[^"\\]|\\.)*)"')


def _client_ip(line: str) -> str:
    for regex in CLIENT_RES:
        m = regex.search(line)
        if m:
            return m.group(1)
    return ""


def _request_head(line: str) -> List[str]:
    """Request line + Host/Referer from the context nginx appends to error log lines."""
    m = NGX_REQUEST_RE.search(line)
    if not m:
        return []
    head = [m.group(1)]
    for regex, name in ((NGX_HOST_RE, "Host"), (NGX_REFERRER_RE, "Referer")):
        hm = regex.search(line)
        if hm:
            head.append(f"{name}: {hm.group(1)}")
    return head


def blocks_from_error_lines(lines: List[str]) -> List[str]:
    """Group ModSecurity error-log lines by unique_id into A (client) / B (request) / H (messages) blocks.

    The full "ModSecurity: ..." text is kept so rule id, msg, severity, version and
    "Access denied" are parsed exactly as for audit logs.
    """
    groups: Dict[str, dict] = {}
    for line in lines:
        pos = line.find("ModSecurity:")
        if pos < 0:
            continue
        m = UID_RE.search(line)
        uid = m.group(1) if m else hashlib.sha1(line.encode()).hexdigest()[:16]
        g = groups.setdefault(uid, {"ip": "", "head": [], "msgs": []})
        g["msgs"].append(line[pos:])
        g["ip"] = g["ip"] or _client_ip(line)
        g["head"] = g["head"] or _request_head(line)

    blocks = []
    for uid, g in groups.items():
        marker = hashlib.sha1(uid.encode()).hexdigest()[:8]
        out = [f"---{marker}---A--", f"[-] {uid} {g['ip'] or '-'} 0 0.0.0.0 0"]
        if g["head"]:
            out.append(f"---{marker}---B--")
            out.extend(g["head"])
        out.append(f"---{marker}---H--")
        out.extend(g["msgs"])
        out.append(f"---{marker}---Z--")
        blocks.append("\n".join(out))
    return blocks
