import fcntl
import ipaddress
import json
import os
import pickle
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from django.conf import settings

from wafinstaller.helper.utils import _geo_db_path


class GeoIndexError(Exception):
    """Raised when the GeoIP database is missing or the index cannot be built."""


class GeoIndex:
    """Country -> IP networks index built from the bundled GeoLite2-Country.mmdb.

    Walking the whole MaxMind tree takes ~20s, so it is done once per database
    version and cached on disk (networks as a pickle, country names as JSON).
    The cache is rebuilt automatically when the .mmdb file changes.
    """

    _lock = threading.Lock()
    _building: Optional[threading.Thread] = None
    _loaded_key: Optional[str] = None
    _loaded: Optional[Dict[str, list]] = None

    # ---------- paths ----------

    @staticmethod
    def db_path() -> Path:
        return _geo_db_path()

    @staticmethod
    def cache_dir() -> Path:
        return Path(settings.BASE_DIR) / "geo" / ".cache"

    @classmethod
    def _key(cls) -> str:
        st = cls.db_path().stat()
        return f"{int(st.st_mtime)}-{st.st_size}"

    @classmethod
    def _files(cls):
        key = cls._key()
        base = cls.cache_dir()
        return key, base / f"networks-{key}.pickle", base / f"names-{key}.json"

    # ---------- state ----------

    @classmethod
    def available(cls) -> bool:
        return cls.db_path().exists()

    @classmethod
    def is_ready(cls) -> bool:
        if not cls.available():
            return False
        _, nets, names = cls._files()
        return nets.exists() and names.exists()

    @classmethod
    def is_building(cls) -> bool:
        return cls._building is not None and cls._building.is_alive()

    # ---------- build ----------

    @classmethod
    def ensure_async(cls) -> None:
        """Start building the index in the background if it is missing."""
        if not cls.available() or cls.is_ready() or cls.is_building():
            return
        with cls._lock:
            if not cls.is_building():
                cls._building = threading.Thread(target=cls._safe_build, name="geo-index", daemon=True)
                cls._building.start()

    @classmethod
    def _safe_build(cls) -> None:
        try:
            cls.build()
        except Exception:
            pass

    @classmethod
    def build(cls) -> None:
        if not cls.available():
            raise GeoIndexError(f"GeoIP database not found: {cls.db_path()}")
        import maxminddb

        base = cls.cache_dir()
        base.mkdir(parents=True, exist_ok=True)
        # Cross-process lock: only one worker builds, the others wait for it.
        with open(base / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if cls.is_ready():
                return
            key, nets_path, names_path = cls._files()
            networks: Dict[str, list] = {}
            names: Dict[str, str] = {}
            with maxminddb.open_database(str(cls.db_path())) as reader:
                for net, record in reader:
                    country = (record or {}).get("country") or {}
                    iso = country.get("iso_code")
                    if not iso:
                        continue
                    networks.setdefault(iso, []).append(
                        (net.version, int(net.network_address), net.prefixlen))
                    if iso not in names:
                        names[iso] = (country.get("names") or {}).get("en", iso)
            cls._atomic_write(nets_path, pickle.dumps(networks, protocol=pickle.HIGHEST_PROTOCOL))
            cls._atomic_write(names_path, json.dumps(names, sort_keys=True).encode())
            for old in base.iterdir():
                if old.name.startswith(("networks-", "names-")) and key not in old.name:
                    old.unlink(missing_ok=True)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    # ---------- queries ----------

    @classmethod
    def country_names(cls) -> Optional[Dict[str, str]]:
        """ISO code -> English name, or None while the index is not built yet."""
        if not cls.is_ready():
            return None
        _, _, names = cls._files()
        return json.loads(names.read_text())

    @classmethod
    def networks(cls, countries: Iterable[str]) -> List[ipaddress._BaseNetwork]:
        """Collapsed IPv4 + IPv6 networks of the given countries (builds the index if needed)."""
        countries = [c for c in countries if c]
        if not countries:
            return []
        if not cls.is_ready():
            cls.build()
        data = cls._load()
        v4, v6 = [], []
        for iso in countries:
            for version, addr, prefix in data.get(iso, ()):
                if version == 4:
                    v4.append(ipaddress.IPv4Network((addr, prefix)))
                else:
                    v6.append(ipaddress.IPv6Network((addr, prefix)))
        return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))

    @classmethod
    def _load(cls) -> Dict[str, list]:
        key, nets, _ = cls._files()
        if cls._loaded_key != key:
            with open(nets, "rb") as f:
                cls._loaded = pickle.load(f)
            cls._loaded_key = key
        return cls._loaded
