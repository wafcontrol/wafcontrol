import os
from pathlib import Path
from django.conf import settings
from wafinstaller.helper.adapters import detect_crs_version, rules_dir as _rules_dir


def _geo_db_path() -> Path:
    candidate = (Path(settings.BASE_DIR) / "geo" / "GeoLite2-Country.mmdb").resolve()
    if candidate.exists():
        return candidate

    app_root = Path(__file__).resolve().parents[1]  # .../wafinstaller
    fallback = (app_root.parent / "geo" / "GeoLite2-Country.mmdb").resolve()
    return fallback


def get_country_info(ip_address: str):

    try:
        import geoip2.database
        db_path = _geo_db_path()
        if not db_path.exists():
            return {"country": "Unknown", "iso_code": "xx"}
        with geoip2.database.Reader(str(db_path)) as reader:
            response = reader.country(ip_address)
            country_name = response.country.name or "Unknown"
            iso_code = response.country.iso_code.lower() if response.country.iso_code else "xx"
            return {"country": country_name, "iso_code": iso_code}
    except Exception:
        return {"country": "Unknown", "iso_code": "xx"}


def get_crs_full_version():
    """Return full CRS version string as detected by adapters.detect_crs_version()."""
    return detect_crs_version()


def get_rules_dir(version: str) -> str:
    """Return rules directory path for given CRS version."""
    return _rules_dir(version) if version else ""
