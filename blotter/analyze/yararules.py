"""YARA: pattern rules from YARA Forge ("core" package) plus our own in the rules/ folder.

YARA Forge's rules, and the compiled form of all rules, are kept encrypted at rest (vault.py) and
only unpacked in memory, so antivirus programs don't mistake them for malware. They are compiled
again whenever a rule file changes. Our own rules stay plain text so they are easy to edit.
"""

import hashlib
import io
import os
import re

import yara

from .. import config, vault
from ..findings import MALICIOUS, SUSPICIOUS, Finding, hiding, risky, unchecked

MATCH_TIMEOUT = 60
FORGE_MEMBER = "yara-forge-core.yar"
TOOLISH = {"HKTL", "HACKTOOL", "TOOL", "PUA", "VULN", "RT", "REDTEAM", "OFFENSIVE", "PENTEST"}
PATTERNISH = {"INDICATOR", "SUSP", "SUSPICIOUS", "HUNTING", "LOG", "ANOMALY", "INFO"}
PACKERISH = {"PACKED", "PACKER", "OBFUSCATED", "OBFUSCATION", "OBFUSC", "CRYPTER", "PROTECTOR"}
GENERIC = {"GENERIC", "GEN"}


def own_rules() -> dict:
    return {"own_" + re.sub(r"\W", "_", p.stem): p for p in sorted(config.OWN_RULES.glob("*.yar"))}


def _key(own: dict) -> str:
    h = hashlib.sha256(yara.__version__.encode())
    for ns, p in [("forge", config.YARA_FORGE), *sorted(own.items())]:
        if p.is_file():
            st = p.stat()
            h.update(f"{ns}|{p}|{st.st_size}|{st.st_mtime_ns}".encode())
    return h.hexdigest()


def save_forge(text: bytes) -> None:
    vault.write(config.YARA_FORGE, {FORGE_MEMBER: text})


def migrate() -> None:
    """Move rules from older Blotter versions (plain files) into the vault, then remove the plain files."""
    plain = config.OLD_PLAIN_RULES[0]
    if plain.is_file() and not config.YARA_FORGE.is_file():
        save_forge(plain.read_bytes())
    for old in config.OLD_PLAIN_RULES:
        old.unlink(missing_ok=True)


def load():
    """Compiled rules (compiling them if needed), or None when there are no rule files at all."""
    own = own_rules()
    if not own and not config.YARA_FORGE.is_file():
        return None
    key = _key(own).encode()
    try:
        stored = vault.read(config.YARA_COMPILED)
        if stored.get("key") == key:
            return yara.load(file=io.BytesIO(stored["rules.yarc"]))
    except Exception:  # missing or damaged cache: compile afresh
        pass
    sources = {ns: p.read_text(encoding="utf-8") for ns, p in own.items()}
    if config.YARA_FORGE.is_file():
        sources["forge"] = vault.read(config.YARA_FORGE)[FORGE_MEMBER].decode("utf-8")
    rules = yara.compile(sources=sources)
    compiled = io.BytesIO()
    rules.save(file=compiled)
    # A sandboxed worker (BLOTTER_WORK is set) may not write here, and on Windows a refused temporary
    # file is retried thousands of times. Blotter itself refreshes the cache at start and after updates.
    if not os.environ.get("BLOTTER_WORK"):
        try:
            vault.write(config.YARA_COMPILED, {"key": key, "rules.yarc": compiled.getvalue()})
        except OSError:
            pass
    return rules


def describe(match) -> str:
    meta = match.meta or {}
    text = str(meta.get("description") or "").strip().rstrip(".")
    return text or match.rule.replace("_", " ")


def classify(check, match, scope=None) -> Finding:
    s = {"scope": scope} if scope else {}
    meta = match.meta or {}
    info = {**s, "rule": match.rule, "source": "our rules" if match.namespace.startswith("own_") else "YARA Forge",
            "description": describe(match), "score": meta.get("score"), "author": meta.get("author")}
    if match.namespace.startswith("own_"):
        level = str(meta.get("blotter", "suspicious")).lower()
        text = str(meta.get("text") or f"It matches Blotter's rule {match.rule}: {describe(match)}.")
        if level == "risky":
            return risky(check, f"yara:{match.rule}", text, info)
        if level == "hiding":
            return hiding(check, f"yara:{match.rule}", text, info)
        return Finding(check, MALICIOUS if level == "malicious" else SUSPICIOUS, text, info)

    tokens = set(match.rule.upper().split("_"))
    what = describe(match)
    if "EICAR" in tokens:
        return Finding(check, MALICIOUS, "YARA recognises the EICAR antivirus test file. It is harmless, "
                                         "but every scanner is built to treat it as malware.", info)
    if tokens & PACKERISH:
        return hiding(check, "packed", f"A YARA rule says it is packed or scrambled ({what}). Some programs "
                                       "protect themselves like that, but malware does it to hide.", info)
    if tokens & TOOLISH:
        return risky(check, f"yara-tool:{match.rule}",
                     f"A YARA rule recognises it as a hacking, cheat or admin tool ({what}). Such tools aren't "
                     "malware by themselves, but attackers use them too.", info)
    if tokens & PATTERNISH:
        return risky(check, f"yara-pattern:{match.rule}",
                     f"A YARA rule found a pattern often seen in malware ({what}). Legitimate programs "
                     "sometimes match these too.", info)
    score = int(meta.get("score") or 0)
    if tokens & GENERIC or match.rule.upper().endswith("_AUTO") or score < 70:
        return Finding(check, SUSPICIOUS, f"A YARA rule for malware matches it ({what}). This kind of rule is "
                                          "broad, so it is a warning sign rather than proof.", info)
    return Finding(check, MALICIOUS, f"A YARA rule recognises it as malware: {what}.", info)


def scan_target(rules, check, path=None, data=None, scope=None) -> list[Finding]:
    target = {"data": data} if data is not None else {"filepath": str(path)}
    try:
        matches = rules.match(timeout=MATCH_TIMEOUT, **target)
    except yara.TimeoutError:
        return [unchecked(check, f"The YARA rules needed more than {MATCH_TIMEOUT} seconds, so Blotter stopped "
                                 "them.", {"scope": scope} if scope else {})]
    return [classify(check, m, scope) for m in matches[:25]]
