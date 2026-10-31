"""Extract the HTTP request (method, headers, cookies, user-agent, body) from a ModSecurity audit block."""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

REQUEST_LINE_RE = re.compile(r'^([A-Z][A-Z-]{1,15})\s+(\S+)(?:\s+(HTTP/[\d.]+))?\s*$')
HEADER_RE = re.compile(r'^([!#$%&\'*+.^_`|~0-9A-Za-z-]+):\s?(.*)$')


@dataclass
class RequestDetails:
    method: str = ""
    protocol: str = ""
    user_agent: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_truncated: bool = False

    @property
    def is_empty(self) -> bool:
        return not (self.method or self.headers or self.body)

    # ---------- parsing ----------

    @classmethod
    def from_sections(cls, sections: Dict[str, List[str]], max_body: int = 16384,
                      store_body: bool = True, store_cookies: bool = True) -> "RequestDetails":
        """Section B = request line + headers; C (or I) = request body."""
        details = cls()
        details._parse_head(sections.get("B") or [])
        if store_body:
            body_lines = sections.get("C") or sections.get("I") or []
            body = "\n".join(body_lines).strip("\r\n")
            if len(body) > max_body:
                body, details.body_truncated = body[:max_body], True
            details.body = body
        if not store_cookies:
            details.cookies = {}
        return details

    def _parse_head(self, lines: List[str]) -> None:
        cookie_values = []
        for raw in lines:
            line = raw.rstrip("\r")
            if not line.strip():
                continue
            if not self.method:
                m = REQUEST_LINE_RE.match(line.strip())
                if m:
                    self.method, self.protocol = m.group(1), m.group(3) or ""
                    continue
            m = HEADER_RE.match(line)
            if not m:
                continue
            name, value = m.group(1), m.group(2).strip()
            if name.lower() == "cookie":
                cookie_values.append(value)  # kept only in `cookies`, never duplicated in headers
                continue
            # Repeated headers are joined, as HTTP allows.
            self.headers[name] = f"{self.headers[name]}, {value}" if name in self.headers else value
            if name.lower() == "user-agent":
                self.user_agent = value[:1024]
        self.cookies = self.parse_cookies("; ".join(cookie_values))

    @staticmethod
    def parse_cookies(header: str) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        for part in (header or "").split(";"):
            name, sep, value = part.strip().partition("=")
            if name and sep:
                cookies[name] = value
        return cookies


def json_request_sections(request: dict, body: Optional[str] = None) -> List[str]:
    """Render a JSON audit-log request as serial-format B (+ C) section lines."""
    lines = []
    method = request.get("method") or ""
    uri = request.get("uri") or ""
    line = request.get("request_line") or (f"{method} {uri} HTTP/{request.get('http_version', '1.1')}" if method else "")
    if line:
        lines.append(line)
    for name, value in (request.get("headers") or {}).items():
        values = value if isinstance(value, list) else [value]
        lines.extend(f"{name}: {v}" for v in values)
    return lines
