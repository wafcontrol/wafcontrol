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
from .models import Attack, CrsVersion, DashboardStat
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

def _update_waf_attacks_core(mod, backend: str) -> str:
    if backend == "apache":
        AUDIT_CANDIDATES = ["/var/log/apache2/modsec_audit.log", "/var/log/modsec_audit.log"]
        ERROR_CANDIDATES = ["/var/log/apache2/error.log", "/var/log/apache2/wafcontrol_error.log"]
        ACCESS_CANDIDATES = ["/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log"]
        LOCK_FILE = "/tmp/update_waf_attacks_apache.lock"
        STATE_DIR = "/var/lib/wafparser/apache"
    else:
        AUDIT_CANDIDATES = ["/var/log/nginx/modsec_audit.log", "/var/log/modsec_audit.log"]
        ERROR_CANDIDATES = ["/var/log/nginx/error.log"]
        ACCESS_CANDIDATES = ["/var/log/nginx/access.log"]
        LOCK_FILE = "/tmp/update_waf_attacks_nginx.lock"
        STATE_DIR = "/var/lib/wafparser/nginx"

    os.makedirs(STATE_DIR, exist_ok=True)
    CKPT_FILE = os.path.join(STATE_DIR, "audit.ckpt.json")

    if os.path.exists(LOCK_FILE):
        try:
            age = time.time() - os.path.getmtime(LOCK_FILE)
            if age < 900:
                return "locked"
            else:
                os.remove(LOCK_FILE)
        except Exception:
            pass
    open(LOCK_FILE, "w").close()

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
    ckpt = load_ckpt()

    try:
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
            full_uri = uri
            if ip in ip_targets:
                cand = mod.pick_best_target(ip, uri, ip_targets[ip])
                if cand:
                    full_uri = cand

            for rid, msg in hits:
                sig = mod.build_sig(ip or "", f"{host}|{full_uri}" or "", rid or "", msg or "", ver or "", status)
                if sig in inrun_seen:
                    continue
                inrun_seen.add(sig)

                if Attack.objects.filter(
                        ip=ip, uri=full_uri, host=host or None, rule_id=rid, message=msg, version=ver, status=status
                ).exists():
                    continue

                country_info = geo_cache.get(ip)
                if country_info is None:
                    country_info = get_country_info(ip) or {}
                    geo_cache[ip] = country_info

                try:
                    Attack.objects.create(
                        ip=ip,
                        country=country_info.get("country", "-"),
                        flag=country_info.get("iso_code", "-"),
                        rule_id=rid or "",
                        message=msg or "",
                        uri=full_uri or "",
                        referer=ref or "",
                        status=status,
                        severity=severity,
                        anomaly_score=anomaly_score,
                        version=ver or "-",
                        host=host or None,
                    )
                    created += 1
                except IntegrityError:
                    continue
                except Exception:
                    continue

        save_ckpt(ckpt)
        return f"{backend}: created={created}"

    finally:
        try:
            os.remove(LOCK_FILE)
        except Exception:
            pass

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

@shared_task
def fetch_crs_versions_task():
    try:
        all_versions: List[str] = []
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "WafControl/1.0",
        }
        for page in (1, 2):
            url = f"https://api.github.com/repos/coreruleset/coreruleset/releases?per_page=20&page={page}"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code != 200:
                logger.error("GitHub responded with status %s: %s", resp.status_code, resp.text[:200])
                break
            releases = resp.json() or []
            for r in releases:
                tag = r.get("tag_name", "")
                published_at = r.get("published_at", "")
                zip_url = r.get("zipball_url", "")
                if not tag or not published_at:
                    continue
                # Parse to aware datetime (UTC)
                dt = datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytimezone.utc)
                CrsVersion.objects.update_or_create(
                    tag=tag,
                    defaults={"published_at": dt, "zip_url": zip_url},
                )
                all_versions.append(tag)
        logger.info("Fetched and saved %d CRS versions.", len(all_versions))
    except Exception as e:
        logger.exception("CRS Fetch Error: %s", e)
