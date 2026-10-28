"""Layer 2: YARA pattern rules (YARA Forge "core" + Blotter's own rules/ folder)."""

from .. import config
from ..analyze import yararules
from ..findings import CLEAR, ERROR, Finding

ID = "yara"
NAME = "YARA rules"
ORDER = 40
TIMEOUT = 120
CACHE = False
NEEDS_FILE = True


def scan(path) -> list[Finding]:
    rules = yararules.load()
    if rules is None:
        return [Finding(ID, ERROR, "No YARA rules are installed yet (run Update rules in Settings).")]
    found = yararules.scan_target(rules, ID, path=path)
    if found:
        return found
    which = "YARA Forge's core rules and Blotter's own rules" if config.YARA_FORGE.is_file() else \
        "Blotter's own rules (YARA Forge's rules aren't downloaded yet)"
    return [Finding(ID, CLEAR, f"None of {which} match it.")]
