"""Small settings file, %LOCALAPPDATA%\\Blotter\\settings.json. No secrets go here (keys are in Credential Manager)."""

import json
import os
import threading

from . import config

DEFAULTS = {
    "setup_done": False,     # the first-run setup was saved or skipped
    "clamav": True,          # run ClamAV while Blotter is open (if it is set up)
}

_lock = threading.Lock()


def load() -> dict:
    try:
        data = json.loads(config.SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {k: type(v)(data.get(k, v)) for k, v in DEFAULTS.items()}


def update(changes: dict) -> dict:
    with _lock:
        current = load()
        for key, value in changes.items():
            if key not in DEFAULTS or not isinstance(value, type(DEFAULTS[key])):
                raise ValueError(f"unknown setting or wrong type: {key}")
            current[key] = value
        config.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = config.SETTINGS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
        os.replace(tmp, config.SETTINGS_PATH)
        return current
