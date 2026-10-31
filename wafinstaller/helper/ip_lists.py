import ipaddress
import os
from typing import Dict, List, Optional, Tuple, Type

from wafinstaller.helper.geo_index import GeoIndex, GeoIndexError
from wafinstaller.helper.server_conf import ApacheConfManager, NginxConfManager, ServerConfManager


class IpListError(Exception):
    """Raised when an IP list cannot be validated or published."""


Entry = Tuple[str, str]  # (normalized ip/cidr, comment)


def parse_entries(text: str) -> Tuple[List[Entry], List[str]]:
    """Parse 'one IP/CIDR per line, optional # comment'. Returns (entries, errors)."""
    entries: List[Entry] = []
    errors: List[str] = []
    seen = set()
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        value, _, comment = raw.partition("#")
        value, comment = value.strip(), comment.strip()
        if not value:
            continue
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as e:
            errors.append(f"Line {lineno}: '{value}' is not a valid IP or CIDR ({e}).")
            continue
        single = net.num_addresses == 1
        normalized = str(net.network_address) if single else str(net)
        if normalized in seen:
            continue
        seen.add(normalized)
        entries.append((normalized, comment))
    return entries, errors


def normalize_entries(entries: List[Entry]) -> str:
    return "\n".join(f"{ip}  # {c}" if c else ip for ip, c in entries)


# -------------------------
# Writers: one per web server
# -------------------------

class IpListWriter:
    """Renders an IpList into the include files of one web server.

    `files()` returns {path: content} for everything the list needs on that server;
    `paths()` returns every path the list may own (used for removal).
    """

    manager_cls: Type[ServerConfManager] = ServerConfManager
    BASE_DIR = ""

    def __init__(self):
        self.manager = self.manager_cls()

    @classmethod
    def is_available(cls) -> bool:
        return cls.manager_cls.is_installed()

    @classmethod
    def base_dir(cls) -> str:
        return cls.BASE_DIR

    @classmethod
    def path_for(cls, ip_list) -> str:
        return os.path.join(cls.base_dir(), f"{ip_list.name}.conf")

    def paths(self, ip_list) -> List[str]:
        return [self.path_for(ip_list)]

    def files(self, ip_list, entries: List[Entry], geo_networks: List) -> Dict[str, str]:
        raise NotImplementedError

    def header(self, ip_list) -> str:
        kind = f"geo list: {', '.join(ip_list.country_list)}" if ip_list.is_geo else "IP list"
        lines = [
            "# Managed by OWASP WafControl - do not edit by hand, changes will be overwritten.",
            f"# {ip_list.name} ({ip_list.action}) - {kind}",
        ]
        if ip_list.description:
            # Single line only: a newline would turn the rest of the text into a directive.
            lines.append("# " + " ".join(ip_list.description.split()))
        return "\n".join(lines) + "\n"

    @staticmethod
    def _line(directive: str, comment: str) -> str:
        return f"{directive}  # {comment}" if comment else directive

    @staticmethod
    def _join(header: str, body: List[str]) -> str:
        return header + "\n".join(body) + ("\n" if body else "")


class NginxIpListWriter(IpListWriter):
    """IP lists -> `allow/deny` include file.

    Geo lists -> `geo` variable: data file of `<cidr> 1;` lines plus a small conf.d
    file declaring `geo $wafc_geo_<name> { ... }` in the http context. nginx stores
    geo ranges in a radix tree, so whole countries stay fast to match.
    """

    key = "nginx"
    label = "Nginx"
    manager_cls = NginxConfManager
    BASE_DIR = "/etc/nginx/wafcontrol/iplists"

    @classmethod
    def geo_data_path(cls, ip_list) -> str:
        return os.path.join(cls.base_dir(), f"{ip_list.name}.geo")

    @classmethod
    def geo_stub_path(cls, ip_list) -> str:
        return os.path.join(NginxConfManager.CONF_DIR, f"wafcontrol-geo-{ip_list.name}.conf")

    def paths(self, ip_list):
        return [self.path_for(ip_list), self.geo_data_path(ip_list), self.geo_stub_path(ip_list)]

    def files(self, ip_list, entries, geo_networks):
        header = self.header(ip_list)
        if not ip_list.is_geo:
            body = [self._line(f"{ip_list.action} {ip};", c) for ip, c in entries]
            return {self.path_for(ip_list): self._join(header, body)}

        data = [self._line(f"{ip} 1;", c) for ip, c in entries]
        data += [f"{net} 1;" for net in geo_networks]
        stub = [
            f"geo ${ip_list.nginx_variable} {{",
            "    default 0;",
            f"    include {self.geo_data_path(ip_list)};",
            "}",
        ]
        return {
            self.geo_data_path(ip_list): self._join(header, data),
            self.geo_stub_path(ip_list): self._join(header, stub),
        }


class ApacheIpListWriter(IpListWriter):
    """IP and geo lists -> `Require ip` / `Require not ip` include file.

    Apache has no built-in geo matching, so countries are expanded to their ranges,
    grouped many per line to keep the file compact.
    """

    key = "apache"
    label = "Apache"
    manager_cls = ApacheConfManager
    GROUP = 100

    @classmethod
    def base_dir(cls) -> str:
        root = "/etc/httpd" if not os.path.isdir("/etc/apache2") and os.path.isdir("/etc/httpd") else "/etc/apache2"
        return os.path.join(root, "wafcontrol", "iplists")

    @staticmethod
    def _line(directive: str, comment: str) -> str:
        # Apache only allows whole-line comments.
        return f"# {comment}\n{directive}" if comment else directive

    def files(self, ip_list, entries, geo_networks):
        keyword = "Require ip" if ip_list.is_allow else "Require not ip"
        body = [self._line(f"{keyword} {ip}", c) for ip, c in entries]
        nets = [str(n) for n in geo_networks]
        for i in range(0, len(nets), self.GROUP):
            body.append(f"{keyword} " + " ".join(nets[i:i + self.GROUP]))
        if not body and ip_list.is_allow:
            # An empty <RequireAny> is a config error; an empty allow list means nobody is allowed.
            body = ["# list is empty", "Require all denied"]
        return {self.path_for(ip_list): self._join(self.header(ip_list), body)}


WRITERS: List[Type[IpListWriter]] = [NginxIpListWriter, ApacheIpListWriter]

# Above this many ranges, Apache's linear `Require ip` matching gets noticeably slow.
APACHE_GEO_WARN_RANGES = 20000


# -------------------------
# Service
# -------------------------

class IpListService:
    """Publishes IP lists as include files for every installed web server.

    Writes are transactional across servers: all files are written, each server's
    config is tested, and on any failure every file is restored before raising.
    """

    def __init__(self, writers: Optional[List[IpListWriter]] = None):
        self.writers = writers if writers is not None else [w() for w in WRITERS if w.is_available()]

    def publish(self, ip_list) -> List[str]:
        entries, errors = parse_entries(ip_list.entries)
        if errors:
            raise IpListError("\n".join(errors))
        geo_networks = []
        if ip_list.is_geo:
            try:
                geo_networks = GeoIndex.networks(ip_list.country_list)
            except (GeoIndexError, OSError) as e:
                raise IpListError(f"GeoIP lookup failed: {e}") from e
        changes: Dict[str, Optional[str]] = {}
        for writer in self.writers:
            changes.update(writer.files(ip_list, entries, geo_networks))
        results = self._apply(changes)
        if ip_list.is_geo:
            results.insert(0, f"{len(geo_networks)} ranges for {', '.join(ip_list.country_list)}.")
            if len(geo_networks) > APACHE_GEO_WARN_RANGES and any(w.key == "apache" for w in self.writers):
                results.append(f"Warning: {len(geo_networks)} ranges is a lot for Apache "
                               f"(checked one by one on every request).")
        return results

    def remove(self, ip_list) -> List[str]:
        return self._apply({p: None for w in self.writers for p in w.paths(ip_list)})

    def refresh_geo(self, ip_lists) -> Tuple[List[str], List[str]]:
        """Re-publish geo lists, e.g. after the GeoIP database was updated."""
        done, failed = [], []
        for ip_list in ip_lists:
            try:
                self.publish(ip_list)
                done.append(ip_list.name)
            except IpListError as e:
                failed.append(f"{ip_list.name}: {e}")
        return done, failed

    # ---------- internals ----------

    def _apply(self, changes: Dict[str, Optional[str]]) -> List[str]:
        if not self.writers:
            return ["No web server detected: list saved but no include file was generated."]
        backups: Dict[str, Optional[str]] = {}
        try:
            for path, content in changes.items():
                backups[path] = self._read(path)
                self._write(path, content)
            for writer in self.writers:
                ok, output = writer.manager.test_config()
                if not ok:
                    raise IpListError(f"{writer.label} config test failed, changes reverted:\n{output}")
        except (IpListError, OSError) as e:
            for path, old in backups.items():
                try:
                    self._write(path, old)
                except OSError:
                    pass
            if isinstance(e, OSError):
                raise IpListError(f"Cannot write include file: {e}") from e
            raise
        return [w.manager.reload() for w in self.writers]

    @staticmethod
    def _read(path: str) -> Optional[str]:
        if not os.path.isfile(path):
            return None
        with open(path, "r") as f:
            return f.read()

    @staticmethod
    def _write(path: str, content: Optional[str]) -> None:
        if content is None:
            if os.path.isfile(path):
                os.remove(path)
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
