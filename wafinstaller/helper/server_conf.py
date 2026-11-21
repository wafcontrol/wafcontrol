import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Type


class ServerConfError(Exception):
    """Raised when a config-file operation cannot be completed."""



@dataclass
class ConfFile:
    name: str
    size: int
    modified: float
    enabled: bool = True


class ServerConfManager:
    """Base service for listing, creating and editing a web server's *.conf files.

    Every write is validated with the server's config test; on failure the previous
    content is restored (or the new file removed) so a bad edit never breaks the server.
    Subclasses define the directory, the test/reload commands and installation detection.
    """

    key = ""
    label = ""
    CONF_DIR = ""
    TEST_CMD: List[str] = []
    RELOAD_CMD: List[str] = []
    SUPPORTS_ENABLE = False
    NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.conf$")
    DEFAULT_TEMPLATE = ""

    def __init__(self, conf_dir: Optional[str] = None):
        self.conf_dir = conf_dir or self.default_conf_dir()

    # ---------- state ----------

    @classmethod
    def default_conf_dir(cls) -> str:
        return cls.CONF_DIR

    @staticmethod
    def is_installed() -> bool:
        raise NotImplementedError

    def dir_exists(self) -> bool:
        return os.path.isdir(self.conf_dir)

    def is_enabled(self, name: str) -> bool:
        return True

    # ---------- read ----------

    def list_files(self) -> List[ConfFile]:
        if not self.dir_exists():
            raise ServerConfError(f"Directory not found: {self.conf_dir}")
        files = []
        for name in sorted(os.listdir(self.conf_dir)):
            path = os.path.join(self.conf_dir, name)
            if name.endswith(".conf") and os.path.isfile(path):
                st = os.stat(path)
                files.append(ConfFile(name=name, size=st.st_size, modified=st.st_mtime,
                                      enabled=self.is_enabled(name)))
        return files

    def read(self, name: str) -> str:
        path = self._existing_path(name)
        with open(path, "r") as f:
            return f.read()

    # ---------- write ----------

    def create(self, name: str, content: str = "", enable: bool = False) -> str:
        path = self._path(name)
        if os.path.exists(path):
            raise ServerConfError(f"File already exists: {name}")
        self._write(path, content)
        enabled_now = enable and self.SUPPORTS_ENABLE and self._enable(name)
        ok, output = self.test_config()
        if not ok:
            if enabled_now:
                self._disable(name)
            os.remove(path)
            raise ServerConfError(f"Config test failed, file not created:\n{output}")
        return self.reload()

    def save(self, name: str, content: str) -> str:
        path = self._existing_path(name)
        with open(path, "r") as f:
            backup = f.read()
        self._write(path, content)
        ok, output = self.test_config()
        if not ok:
            self._write(path, backup)
            raise ServerConfError(f"Config test failed, changes reverted:\n{output}")
        return self.reload()

    # ---------- hooks ----------

    def _enable(self, name: str) -> bool:
        return False

    def _disable(self, name: str) -> None:
        pass

    # ---------- internals ----------

    def _path(self, name: str) -> str:
        name = (name or "").strip()
        if not self.NAME_PATTERN.match(name) or ".." in name:
            raise ServerConfError(
                "Invalid filename. Use letters, digits, '.', '_' or '-' and end with .conf"
            )
        if not self.dir_exists():
            raise ServerConfError(f"Directory not found: {self.conf_dir}")
        base = os.path.realpath(self.conf_dir)
        path = os.path.realpath(os.path.join(base, name))
        if os.path.dirname(path) != base:
            raise ServerConfError("Invalid file path.")
        return path

    def _existing_path(self, name: str) -> str:
        path = self._path(name)
        if not os.path.isfile(path):
            raise ServerConfError(f"File not found: {name}")
        return path

    @staticmethod
    def _write(path: str, content: str) -> None:
        content = content.replace("\r\n", "\n")
        with open(path, "w") as f:
            f.write(content)

    def _run(self, cmd: List[str]) -> Tuple[int, str]:
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False
            )
            return proc.returncode, (proc.stdout or "").strip()
        except FileNotFoundError:
            return 127, f"{cmd[0]} not found."

    def test_config(self) -> Tuple[bool, str]:
        code, output = self._run(self.TEST_CMD)
        return code == 0, output

    def reload(self) -> str:
        code, output = self._run(self.RELOAD_CMD)
        if code != 0:
            return f"Saved, but {self.label} reload failed: {output}"
        return f"Saved and {self.label} reloaded."


class NginxConfManager(ServerConfManager):
    key = "nginx"
    label = "Nginx"
    CONF_DIR = "/etc/nginx/conf.d"
    TEST_CMD = ["nginx", "-t"]
    RELOAD_CMD = ["nginx", "-s", "reload"]
    DEFAULT_TEMPLATE = (
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:8080;\n"
        "    }\n"
        "}\n"
    )

    @staticmethod
    def is_installed() -> bool:
        return bool(shutil.which("nginx")) or os.path.isdir("/etc/nginx")


class ApacheConfManager(ServerConfManager):
    """Debian/Ubuntu: sites-available (+ sites-enabled symlinks). RHEL/CentOS: /etc/httpd/conf.d."""

    key = "apache"
    label = "Apache"
    DEBIAN_AVAILABLE = "/etc/apache2/sites-available"
    DEBIAN_ENABLED = "/etc/apache2/sites-enabled"
    RHEL_CONF_DIR = "/etc/httpd/conf.d"
    DEFAULT_TEMPLATE = (
        "<VirtualHost *:80>\n"
        "    ServerName example.com\n"
        "    DocumentRoot /var/www/html\n\n"
        "    ErrorLog ${APACHE_LOG_DIR}/example.com-error.log\n"
        "    CustomLog ${APACHE_LOG_DIR}/example.com-access.log combined\n"
        "</VirtualHost>\n"
    )

    def __init__(self, conf_dir: Optional[str] = None, enabled_dir: Optional[str] = None):
        super().__init__(conf_dir)
        if enabled_dir is not None:
            self.enabled_dir = enabled_dir
        elif self.conf_dir == self.DEBIAN_AVAILABLE:
            self.enabled_dir = self.DEBIAN_ENABLED
        else:
            self.enabled_dir = None
        ctl = "apache2ctl" if shutil.which("apache2ctl") or not shutil.which("apachectl") else "apachectl"
        self.TEST_CMD = [ctl, "configtest"]
        self.RELOAD_CMD = [ctl, "-k", "graceful"]

    @property
    def SUPPORTS_ENABLE(self) -> bool:
        return bool(self.enabled_dir) and os.path.isdir(self.enabled_dir)

    @classmethod
    def default_conf_dir(cls) -> str:
        if os.path.isdir(cls.DEBIAN_AVAILABLE):
            return cls.DEBIAN_AVAILABLE
        if os.path.isdir(cls.RHEL_CONF_DIR):
            return cls.RHEL_CONF_DIR
        return cls.DEBIAN_AVAILABLE

    @staticmethod
    def is_installed() -> bool:
        return any(shutil.which(b) for b in ("apache2ctl", "apache2", "apachectl", "httpd")) \
            or os.path.isdir("/etc/apache2") or os.path.isdir("/etc/httpd")

    def is_enabled(self, name: str) -> bool:
        if not self.SUPPORTS_ENABLE:
            return True
        return os.path.exists(os.path.join(self.enabled_dir, name))

    def _enable(self, name: str) -> bool:
        link = os.path.join(self.enabled_dir, name)
        if os.path.lexists(link):
            return False
        os.symlink(os.path.join("..", os.path.basename(self.conf_dir), name), link)
        return True

    def _disable(self, name: str) -> None:
        link = os.path.join(self.enabled_dir, name)
        if os.path.islink(link):
            os.remove(link)


CONF_MANAGERS: Dict[str, Type[ServerConfManager]] = {
    NginxConfManager.key: NginxConfManager,
    ApacheConfManager.key: ApacheConfManager,
}


def get_conf_manager(server: str) -> Optional[ServerConfManager]:
    cls = CONF_MANAGERS.get(server)
    return cls() if cls else None
