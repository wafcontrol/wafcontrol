import json
import os
import queue
import socket
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from wafinstaller.models import AppSetting


# Syslog severities (RFC 5424)
EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG = range(8)

FACILITIES = {
    "user": 1, "auth": 4, "daemon": 3, "authpriv": 10,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
PROTOCOLS = ("udp", "tcp")
FORMATS = ("rfc5424", "rfc3164")

# Attack.severity (0=Info, 1=Low, 2=Medium, 3=High) -> syslog severity
ATTACK_SEVERITY = {0: INFO, 1: NOTICE, 2: WARNING, 3: ERR}


@dataclass
class SyslogConfig:
    enabled: bool = False
    host: str = ""
    port: int = 514
    protocol: str = "udp"
    facility: str = "local0"
    format: str = "rfc5424"
    app_name: str = "wafcontrol"
    send_attacks: bool = True
    send_audit: bool = True

    # AppSetting key <-> field
    KEYS = {
        "enabled": "SyslogEnabled",
        "host": "SyslogHost",
        "port": "SyslogPort",
        "protocol": "SyslogProtocol",
        "facility": "SyslogFacility",
        "format": "SyslogFormat",
        "app_name": "SyslogAppName",
        "send_attacks": "SyslogSendAttacks",
        "send_audit": "SyslogSendAudit",
    }

    @classmethod
    def load(cls) -> "SyslogConfig":
        stored = dict(AppSetting.objects.filter(key__in=cls.KEYS.values()).values_list("key", "value"))
        cfg = cls()
        for field, key in cls.KEYS.items():
            if key not in stored:
                continue
            raw = stored[key]
            default = getattr(cfg, field)
            if isinstance(default, bool):
                value = raw == "1"
            elif isinstance(default, int):
                value = int(raw) if raw.isdigit() else default
            else:
                value = raw
            setattr(cfg, field, value)
        return cfg

    def save(self) -> None:
        for field, key in self.KEYS.items():
            value = getattr(self, field)
            if isinstance(value, bool):
                value = "1" if value else "0"
            AppSetting.objects.update_or_create(key=key, defaults={"value": str(value)})

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SyslogSender:
    """Formats and delivers a single syslog message over UDP or TCP."""

    TIMEOUT = 3

    def __init__(self, config: SyslogConfig):
        self.config = config
        self.hostname = socket.gethostname() or "-"

    def format(self, severity: int, msgid: str, payload: Dict[str, Any]) -> bytes:
        pri = FACILITIES.get(self.config.facility, 16) * 8 + severity
        msg = json.dumps(payload, default=str, ensure_ascii=False)
        app = self.config.app_name or "wafcontrol"
        if self.config.format == "rfc3164":
            ts = datetime.now().strftime("%b %d %H:%M:%S")
            line = f"<{pri}>{ts} {self.hostname} {app}: {msg}"
        else:
            ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            line = f"<{pri}>1 {ts} {self.hostname} {app} {os.getpid()} {msgid} - {msg}"
        return line.encode("utf-8")

    def send(self, data: bytes) -> None:
        host, port = self.config.host, int(self.config.port)
        if self.config.protocol == "tcp":
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as sock:
                sock.sendall(data + b"\n")
            return
        family, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.TIMEOUT)
            sock.sendto(data, addr)


class SyslogService:
    """Facade used by the app: cached config + non-blocking delivery.

    Events are queued and sent by a per-process background thread so a slow or
    unreachable syslog server never delays a panel request. Delivery errors are
    swallowed: logging must never break the application.
    """

    CACHE_TTL = 30

    _config: Optional[SyslogConfig] = None
    _loaded_at = 0.0
    _queue: Optional["queue.Queue"] = None
    _worker_pid: Optional[int] = None
    _lock = threading.Lock()

    # ---------- config ----------

    @classmethod
    def config(cls) -> SyslogConfig:
        if cls._config is None or time.monotonic() - cls._loaded_at > cls.CACHE_TTL:
            try:
                cls._config = SyslogConfig.load()
            except Exception:
                cls._config = SyslogConfig()
            cls._loaded_at = time.monotonic()
        return cls._config

    @classmethod
    def save_config(cls, config: SyslogConfig) -> None:
        config.save()
        cls._config, cls._loaded_at = config, time.monotonic()

    # ---------- events ----------

    @classmethod
    def emit(cls, msgid: str, severity: int, payload: Dict[str, Any],
             config: Optional[SyslogConfig] = None, sync: bool = False) -> None:
        cfg = config or cls.config()
        if not cfg.enabled or not cfg.host:
            return
        try:
            sender = SyslogSender(cfg)
            data = sender.format(severity, msgid, payload)
            if sync:
                sender.send(data)
            else:
                cls._get_queue().put((sender, data))
        except Exception:
            pass

    @classmethod
    def attack(cls, attack) -> None:
        cfg = cls.config()
        if not cfg.send_attacks:
            return
        cls.emit("WAF_ATTACK", ATTACK_SEVERITY.get(attack.severity, WARNING), {
            "event": "waf_attack",
            "time": attack.timestamp,
            "ip": attack.ip,
            "country": attack.country,
            "host": attack.host,
            "uri": attack.uri,
            "referer": attack.referer,
            "rule_id": attack.rule_id,
            "message": attack.message,
            "severity": attack.severity,
            "anomaly_score": attack.anomaly_score,
            "status": attack.status,
            "crs_version": attack.version,
            "method": attack.request.method if attack.request else "",
            "user_agent": attack.request.user_agent if attack.request else "",
        }, config=cfg)

    @classmethod
    def audit(cls, action: str, username: str = "", ip: str = "", severity: int = NOTICE,
              config: Optional[SyslogConfig] = None, sync: bool = False, **details) -> None:
        cfg = config or cls.config()
        if not cfg.send_audit:
            return
        payload = {"event": "user_action", "action": action, "user": username or "-", "ip": ip or "-"}
        payload.update(details)
        cls.emit("AUDIT", severity, payload, config=cfg, sync=sync)

    @classmethod
    def test(cls, config: SyslogConfig) -> None:
        """Send a test message synchronously; raises OSError on delivery failure."""
        sender = SyslogSender(config)
        sender.send(sender.format(INFO, "TEST", {
            "event": "test", "message": "WafControl syslog test message",
        }))

    # ---------- background delivery ----------

    @classmethod
    def _get_queue(cls) -> "queue.Queue":
        # Re-create the worker after a fork (gunicorn / celery prefork).
        if cls._queue is None or cls._worker_pid != os.getpid():
            with cls._lock:
                if cls._queue is None or cls._worker_pid != os.getpid():
                    cls._queue = queue.Queue(maxsize=10000)
                    cls._worker_pid = os.getpid()
                    threading.Thread(target=cls._worker, args=(cls._queue,),
                                     name="syslog-sender", daemon=True).start()
        return cls._queue

    @staticmethod
    def _worker(q: "queue.Queue") -> None:
        while True:
            sender, data = q.get()
            try:
                sender.send(data)
            except Exception:
                pass
            finally:
                q.task_done()


def client_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "") if request is not None else ""
