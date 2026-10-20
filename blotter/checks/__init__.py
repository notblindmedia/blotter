"""Checks are plug-ins. Every module in this folder that has the attributes below is one.

To add a check in phase 2, drop a new module here; nothing else needs to change.

    ID = "short_id"          # unique, used in the cache
    NAME = "Shown name"
    ORDER = 10               # position on the card (lower first)
    TIMEOUT = 60             # seconds before the runner gives up on it
    CACHE = False            # True: results are stored by SHA-256 (online lookups that cost quota)
    NEEDS_FILE = False       # True: reads the file bytes; False: only needs the hash
    def scan(path) -> list[Finding]

A check only ever reads the file's bytes. It never runs, opens or imports the file.
"""

import importlib
import pkgutil

REQUIRED = ("ID", "NAME", "TIMEOUT", "scan")


def load_checks() -> list:
    found = []
    for info in pkgutil.iter_modules(__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        if all(hasattr(module, attr) for attr in REQUIRED):
            found.append(module)
    ids = [m.ID for m in found]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"two checks share an ID: {ids}")
    return sorted(found, key=lambda m: getattr(m, "ORDER", 100))
