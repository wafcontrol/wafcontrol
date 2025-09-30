import json
import subprocess
from pathlib import Path

from django.conf import settings

def detect_server_kind() -> str:

    try:
        script_path = (Path(settings.BASE_DIR) / "scripts" / "basic.sh").resolve()
        # Fallback: if not found relative to BASE_DIR, try relative to app root
        if not script_path.exists():
            app_root = Path(__file__).resolve().parents[1]
            candidate = (app_root.parent / "scripts" / "basic.sh").resolve()
            if candidate.exists():
                script_path = candidate

        if not script_path.exists():
            return "none"

        res = subprocess.run(
            ["/bin/bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        # basic.sh should print a JSON like {"server":"nginx"} to stdout
        raw = (res.stdout or "").strip()
        data = json.loads(raw) if raw else {}
        return (str(data.get("server") or "none")).lower()
    except Exception:
        return "none"
