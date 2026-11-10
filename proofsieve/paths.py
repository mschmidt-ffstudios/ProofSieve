"""Find public assets and writable state in source and installed runs."""

import os
from pathlib import Path


_PACKAGE_DIR = Path(__file__).resolve().parent
_BUNDLED_ASSETS = _PACKAGE_DIR / "assets"


def _installed_state():
    configured = Path(os.environ.get("XDG_STATE_HOME", ""))
    base = configured if configured.is_absolute() else Path.home() / ".local" / "state"
    return base / "proofsieve" / "rule.json"


if _BUNDLED_ASSETS.is_dir():
    ROOT = _BUNDLED_ASSETS
    DEFAULT_STATE = _installed_state()
else:
    ROOT = _PACKAGE_DIR.parent
    DEFAULT_STATE = ROOT / "instance" / "rule.json"
