import fcntl
import os
import json
import time
import logging
import subprocess
from datetime import datetime, timedelta, timezone as pytimezone
from typing import Dict, List, Tuple

import requests
from celery import shared_task
from django.db import IntegrityError
from django.conf import settings
from django.utils import timezone  # <-- use Django timezone
from pathlib import Path

from .attacks.attack_nginx import determine_status
from .models import Attack, AttackRequest, CrsVersion, DashboardStat
from .attacks.request_details import RequestDetails
from wafinstaller.helper.utils import get_country_info
from wafinstaller.helper.crs import load_app_settings
from wafinstaller.helper.tasks_helpers import detect_server_kind  # ensure filename matches!
from .attacks import attack_apache as ap_mod, attack_nginx as ngx_mod

logger = logging.getLogger(__name__)


# ---------- Script path helpers ----------

def _scripts_dir() -> Path:

    base_scripts = (Path(settings.BASE_DIR) / "scripts").resolve()
    if base_scripts.exists():
        return base_scripts
    app_root = Path(__file__).resolve().parents[1]  # .../wafinstaller
    return (app_root.parent / "scripts").resolve()


# ---------- Streaming runner (for long-running installers) ----------

@shared_task(bind=True)
def run_waf_install(self):
    script_path = _scripts_dir() / "wafinstall.sh"
    log: List[str] = []
    try:
        p = subprocess.Popen(
            ["/bin/bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )
        assert p.stdout is not None
        for line in iter(p.stdout.readline, ""):
            clean = line.strip()
            log.append(clean)
            # Update Celery task state so UI can stream logs
            self.update_state(state="PROGRESS", meta={"line": clean})
        p.stdout.close()
        p.wait()
        return {"status": "done", "exit_code": p.returncode, "log": log}
    except Exception as e:
        logger.exception("run_waf_install error")
        return {"status": "error", "message": str(e)}


# ---------- System stats ----------

@shared_task
def update_dashboard_stats():
    script_path = _scripts_dir() / "sysstats.sh"
    try:
        res = subprocess.run(
            ["/bin/bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=45,
        )
        try:
            data = json.loads((res.stdout or "{}").strip() or "{}")
        except Exception:
            data = {}
        DashboardStat.objects.create(
            fetched_at=timezone.now(),
            cpu_usage=data.get("cpu_usage", "0"),
            cpu_load=data.get("cpu_load", "0"),
            ram_usage=data.get("ram_usage", "0"),
            disk_usage=data.get("disk_usage", "0"),
            storage_free=data.get("storage_free", "0"),
            total_processes=data.get("total_processes", "0"),
            total_threads=data.get("total_threads", "0"),
            total_handles=data.get("total_handles", "0"),
        )
    except Exception as e:
        logger.error("update_dashboard_stats error: %s", e)


# ---------- Core updater shared by Apache/Nginx ----------

def _try_lock(path: str):
    """Non-blocking exclusive lock; returns the fd to keep, or None if another run holds it."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        os.close(fd)
        return None


def _release_lock(fd) -> None:
    try:
        os.close(fd)  # closing the fd releases the flock
    except OSError:
        pass


def _update_waf_attacks_core(mod, backend: str) -> str:
    if backend == "apache":
        AUDIT_CANDIDATES = ["/var/log/apache2/modsec_audit.log", "/var/log/modsec_audit.log"]
        ERROR_CANDIDATES = ["/var/log/apache2/error.log", "/var/log/apache2/wafcontrol_error.log"]
        ACCESS_CANDIDATES = ["/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log"]
        STATE_DIR = "/var/lib/wafparser/apache"
    else:
        AUDIT_CANDIDATES = ["/var/log/nginx/modsec_audit.log", "/var/log/modsec_audit.log"]
        ERROR_CANDIDATES = ["/var/log/nginx/error.log"]
        ACCESS_CANDIDATES = ["/var/log/nginx/access.log"]
        STATE_DIR = "/var/lib/wafparser/nginx"

    os.makedirs(STATE_DIR, exist_ok=True)
    CKPT_FILE = os.path.join(STATE_DIR, "audit.ckpt.json")

    def load_ckpt() -> Dict:
        try:
            with open(CKPT_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_ckpt(data: dict):
        tmp = CKPT_FILE + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, CKPT_FILE)
        except Exception:
            pass

    AUDIT_LOG = next((p for p in AUDIT_CANDIDATES if os.path.exists(p)), None)
    ERROR_LOGS = [p for p in ERROR_CANDIDATES if os.path.exists(p)]
    ACCESS_LOGS = [p for p in ACCESS_CANDIDATES if os.path.exists(p)]

    created = 0
    failed = 0

    # One parser run at a time. A kernel lock is released automatically when the process ends
    # (even if killed), unlike a marker file that blocked runs for 15 minutes after a crash.
    lock_fd = _try_lock(os.path.join(STATE_DIR, "update.lock"))
    if lock_fd is None:
        return "locked"
    # Everything after taking the lock runs inside try/finally: an exception anywhere (e.g. the
    # database briefly down) must release it, or this worker process would hold it until restarted.
    try:
        ckpt = load_ckpt()
        capture = RequestCaptureSettings.load()

        if not _attack_schema_ready():
            # Keep the checkpoint where it is: once `migrate` is run, these attacks are picked up.
            logger.error("Attack tables are out of date: run 'python manage.py makemigrations wafinstaller "
                         "&& python manage.py migrate', then restart Celery. Attacks are not being stored.")
            return "migration required"

        blocks = []
        if AUDIT_LOG:
            blocks = mod.read_audit_blocks_serial_without_z(AUDIT_LOG, max_bytes=8000000)

        if not blocks and AUDIT_LOG:
            blocks = mod.parse_audit_blocks_incremental(
                AUDIT_LOG, ckpt, max_tail_bytes=2000000, max_blocks_on_rotate=400
            )

        if not blocks and ERROR_LOGS:
            blocks = mod.blocks_from_errorlogs(ERROR_LOGS, tail_n=12000)

        if not blocks and not ERROR_LOGS:
            save_ckpt(ckpt)
            return "no data"

        uid_to_ip = mod.map_uid_to_ip_from_errorlogs(ERROR_LOGS, 8000)
        ip_targets = mod.map_ip_to_recent_targets(ACCESS_LOGS, tail_n=20000)
        geo_cache = {}
        inrun_seen = set()

        for blk in reversed(blocks):
            sections = mod.split_sections_lenient(blk)
            uid_a, ip_a = mod.uid_ip_from_A_sections(sections)
            uid = mod.extract_first(mod.UID_RE, blk)

            ip = None
            if uid and uid in uid_to_ip:
                ip = uid_to_ip[uid]
            elif mod.is_ip(ip_a):
                ip = ip_a
            else:
                for pat in mod.IP_FALLBACKS:
                    m = pat.search(blk)
                    if m and mod.is_ip(m.group(1)):
                        ip = m.group(1)
                        break

            if not mod.is_ip(ip):
                continue

            uri = mod.uri_from_B_sections(sections) or mod.extract_first(mod.URI_RE, blk) or ""
            if not uri or mod.looks_static(uri):
                continue

            ver = mod.extract_first(mod.VER_RE, blk)
            ref = mod.extract_first(mod.REFERER_RE, blk)
            tags = mod.extract_all(mod.TAGS_RE, blk)
            blocked = mod.blocked_from_block_text(blk)

            severity = mod.extract_severity_from_log(blk, mod.extract_first(mod.RID_RE, blk) or "")
            anomaly_score = mod.extract_anomaly_score(blk)

            status = determine_status(severity, anomaly_score, blocked)

            raw_hits = mod.extract_hits_from_sections(sections) or mod.parse_rule_hits(blk)
            hits = mod.filter_rule_hits(raw_hits)
            if not hits:
                continue

            host = mod.extract_host(blk) or ""
            # One AttackRequest per transaction, created only if at least one Attack row is stored.
            request_obj = None
            request_failed = False
            full_uri = uri
            if ip in ip_targets:
                cand = mod.pick_best_target(ip, uri, ip_targets[ip])
                if cand:
                    full_uri = cand

            # ModSecurity's unique_id identifies the request: the same log entry re-read later is a
            # duplicate, but the same attack sent again (new request, new id) must be stored again.
            txn = _no_nul(uid or uid_a or "")[:128]

            for rid, msg in hits:
                sig = mod.build_sig(ip or "", f"{host}|{full_uri}|{txn}", rid or "", msg or "", ver or "", status)
                if sig in inrun_seen:
                    continue
                inrun_seen.add(sig)

                if _already_stored(txn, ip, full_uri, host, rid, msg, ver, status):
                    continue

                country_info = geo_cache.get(ip)
                if country_info is None:
                    country_info = get_country_info(ip) or {}
                    geo_cache[ip] = country_info

                if request_obj is None and not request_failed:
                    # Request details are best effort: a failure here must never drop the attack itself.
                    try:
                        request_obj = capture.create_request(sections, uid or uid_a)
                    except Exception as e:
                        request_failed = True
                        logger.warning("%s: could not store request details (%s); storing attack without them.",
                                       backend, e)
                try:
                    Attack.objects.create(
                        txn_id=txn,
                        request=request_obj,
                        ip=ip,
                        country=country_info.get("country", "-"),
                        flag=country_info.get("iso_code", "-"),
                        rule_id=_no_nul(rid or ""),
                        message=_no_nul(msg or ""),
                        uri=_no_nul(full_uri or "")[:2048],
                        referer=_no_nul(ref or "")[:2048],
                        status=status,
                        severity=severity,
                        anomaly_score=anomaly_score,
                        version=ver or "-",
                        host=_no_nul(host)[:255] or None,
                    )
                    created += 1
                except IntegrityError:
                    continue
                except Exception as e:
                    failed += 1
                    if failed == 1:
                        logger.exception("%s: failed to store attack: %s", backend, e)
                    continue

        if failed:
            logger.error("%s: %d attack(s) could not be stored (first error logged above).", backend, failed)
        save_ckpt(ckpt)
        return f"{backend}: created={created}" + (f" failed={failed}" if failed else "")

    finally:
        _release_lock(lock_fd)

_SCHEMA_READY = False


def _attack_schema_ready() -> bool:
    """True once the attack tables have the columns this code writes (checked until it succeeds)."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return True
    from django.db import connection
    try:
        tables = connection.introspection.table_names()
        if AttackRequest._meta.db_table not in tables:
            return False
        with connection.cursor() as cursor:
            columns = {c.name for c in connection.introspection.get_table_description(cursor, Attack._meta.db_table)}
        _SCHEMA_READY = {"request_id", "txn_id"} <= columns
    except Exception:
        return False
    return _SCHEMA_READY


LEGACY_DEDUPE_WINDOW = timedelta(hours=24)


def _already_stored(txn, ip, uri, host, rid, msg, ver, status) -> bool:
    """True if this rule hit of this request is already in the database."""
    same_content = dict(ip=ip, uri=_no_nul(uri or "")[:2048], host=_no_nul(host)[:255] or None,
                        rule_id=_no_nul(rid or ""), message=_no_nul(msg or ""), version=ver or "-", status=status)
    if not txn:
        # No request id (e.g. error-log fallback): only the content can identify it.
        return Attack.objects.filter(**same_content).exists()
    if Attack.objects.filter(txn_id=txn, rule_id=same_content["rule_id"]).exists():
        return True
    # Rows stored before txn_id existed: avoid re-adding them when old log entries are re-read.
    return Attack.objects.filter(txn_id="", timestamp__gte=timezone.now() - LEGACY_DEDUPE_WINDOW,
                                 **same_content).exists()


def _no_nul(value):
    """PostgreSQL rejects NUL (\\x00) in text and JSON; attack payloads often contain it."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {_no_nul(k): _no_nul(v) for k, v in value.items()}
    return value


class RequestCaptureSettings:
    """Which parts of the attacking request are stored (Owc Setting page)."""

    def __init__(self, store_body: bool, store_cookies: bool, max_body: int):
        self.store_body = store_body
        self.store_cookies = store_cookies
        self.max_body = max_body

    @classmethod
    def load(cls) -> "RequestCaptureSettings":
        from wafinstaller.helper.crs import APP_KEYS
        cfg = load_app_settings()
        get = lambda k: str(cfg.get(k, APP_KEYS[k]["default"])).strip()
        on = lambda k: get(k).lower() in ("1", "true", "yes", "on")
        max_body = get("AttackMaxBodyBytes")
        return cls(on("AttackStoreRequestBody"), on("AttackStoreCookies"),
                   int(max_body) if max_body.isdigit() else 16384)

    def create_request(self, sections, unique_id: str):
        details = RequestDetails.from_sections(sections, max_body=self.max_body,
                                               store_body=self.store_body, store_cookies=self.store_cookies)
        if details.is_empty:
            return None  # e.g. error-log fallback: no request sections available
        return AttackRequest.objects.create(
            unique_id=_no_nul(unique_id or "")[:128],
            method=_no_nul(details.method)[:16],
            protocol=_no_nul(details.protocol)[:16],
            user_agent=_no_nul(details.user_agent)[:1024],
            headers=_no_nul(details.headers),
            cookies=_no_nul(details.cookies),
            body=_no_nul(details.body),
            body_truncated=details.body_truncated,
        )


# ---------- Per-backend public tasks ----------

@shared_task
def update_waf_attacks_apache():
    if detect_server_kind() != "apache":
        return "skipped: server is not apache"
    return _update_waf_attacks_core(ap_mod, backend="apache")


@shared_task
def update_waf_attacks_nginx():
    if detect_server_kind() != "nginx":
        return "skipped: server is not nginx"
    return _update_waf_attacks_core(ngx_mod, backend="nginx")


# ---------- Housekeeping ----------

@shared_task
def delete_old_attacks():
    app_settings = load_app_settings()
    days = int(app_settings.get("AttackRetentionDays", 15))
    cutoff = timezone.now() - timedelta(days=days)  # uses Django timezone
    deleted_count, _ = Attack.objects.filter(timestamp__lt=cutoff).delete()
    # Requests no longer referenced by any attack (bodies/headers can be large).
    AttackRequest.objects.filter(attacks__isnull=True).delete()
    return f"Deleted {deleted_count} old attacks."


# ---------- CRS version install (stream logs) ----------

@shared_task(bind=True)
def run_crs_version_install(self, version: str):
    script_path = _scripts_dir() / "updatecrs.sh"
    log: List[str] = []
    try:
        p = subprocess.Popen(
            ["/bin/bash", str(script_path), version],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        assert p.stdout is not None
        for line in iter(p.stdout.readline, ""):
            clean = line.strip()
            log.append(clean)
            self.update_state(state="PROGRESS", meta={"line": clean})
        p.stdout.close()
        p.wait()
        return {"status": "done", "exit_code": p.returncode, "log": log}
    except Exception as e:
        logger.exception("run_crs_version_install error")
        return {"status": "error", "message": str(e)}


# ---------- Fetch CRS versions from GitHub ----------

class CrsFetchError(Exception):
    """Raised with a human-readable reason when CRS releases cannot be fetched."""


CRS_RELEASES_URL = "https://api.github.com/repos/coreruleset/coreruleset/releases"


def fetch_crs_versions() -> int:
    """Fetch CRS releases from GitHub into CrsVersion. Returns the number saved.

    Raises CrsFetchError explaining why nothing could be fetched (network, rate limit...).
    Set GITHUB_TOKEN in .env to raise GitHub's limit of 60 anonymous requests/hour.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"WafControl/{getattr(settings, 'APP_VERSION', '1')}",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    saved = 0
    for page in (1, 2):
        try:
            resp = requests.get(CRS_RELEASES_URL, params={"per_page": 20, "page": page},
                                timeout=15, headers=headers)
        except requests.RequestException as e:
            if page == 1:
                raise CrsFetchError(f"Cannot reach api.github.com from this server: {e}") from e
            break
        if resp.status_code != 200:
            if page > 1:
                break
            if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
                reset = resp.headers.get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset), pytimezone.utc).strftime("%H:%M UTC") if reset else "later"
                raise CrsFetchError(f"GitHub API rate limit exceeded, try again after {when} "
                                    f"(or set GITHUB_TOKEN in .env).")
            raise CrsFetchError(f"GitHub responded with HTTP {resp.status_code}: {resp.text[:200]}")
        for r in resp.json() or []:
            tag = r.get("tag_name", "")
            published_at = r.get("published_at", "")
            if not tag or not published_at or r.get("draft"):
                continue
            dt = datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytimezone.utc)
            CrsVersion.objects.update_or_create(
                tag=tag,
                # fetched_at is auto_now_add: refresh it explicitly so "Last Fetched" is accurate.
                defaults={"published_at": dt, "zip_url": r.get("zipball_url", ""), "fetched_at": timezone.now()},
            )
            saved += 1
    if not saved:
        raise CrsFetchError("GitHub returned no CRS releases.")
    return saved


@shared_task
def fetch_crs_versions_task():
    try:
        count = fetch_crs_versions()
        logger.info("Fetched and saved %d CRS versions.", count)
        return count
    except CrsFetchError as e:
        logger.error("CRS fetch failed: %s", e)
    except Exception as e:
        logger.exception("CRS Fetch Error: %s", e)
