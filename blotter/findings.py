"""The one shape every check returns: a list of Findings."""

from dataclasses import asdict, dataclass, field

MALICIOUS = "malicious"    # the check recognises the file as malware
SUSPICIOUS = "suspicious"  # a warning sign on its own (a few antivirus engines, a broken signature)
NOTE = "note"              # something the file can do or hides; the scorer weighs these together
CLEAR = "clear"            # the check ran and recognised nothing
UNKNOWN = "unknown"        # the check ran but has no record of this file
SKIPPED = "skipped"        # the check doesn't apply to this file, or is switched off
ERROR = "error"            # the check could not run

LEVELS = (MALICIOUS, SUSPICIOUS, NOTE, CLEAR, UNKNOWN, SKIPPED, ERROR)

# Signals: facts the scorer (verdict.py) combines. A finding can carry several.
RISKY = "risky"                    # a risky ability, e.g. injecting code (details["ability"] names it)
WEAK = "weak"                      # a weak sign: common in ordinary programs, counts only together with
                                   # UNSIGNED, PACKED or UNKNOWN_ONLINE (see verdict.py)
HIDING = "hiding"                  # hides what it is or does: obfuscation, anti-analysis, encoded commands
LYING_NAME = "lying_name"          # the name doesn't match the real contents
DISGUISED = "disguised"            # a program or script dressed up as a document, picture or video
PACKED = "packed"                  # a program whose code is compressed or scrambled
PADDED = "padded"                  # a program with lots of empty filler appended (against size limits)
SIGNED = "signed"                  # a program with a valid digital signature
UNSIGNED = "unsigned"              # a program without a valid signature
UNKNOWN_ONLINE = "unknown_online"  # VirusTotal has never seen this file
KNOWN_GOOD = "known_good"          # CIRCL hashlookup lists it as known, common software
UNCHECKED = "unchecked"            # part of the file couldn't be looked at (locked or oversized archive)
HIDDEN_ZIP = "hidden_zip"          # a picture or document with a zip archive glued after it: Unusual alone

SIGNALS = (RISKY, WEAK, HIDING, LYING_NAME, DISGUISED, PACKED, PADDED, SIGNED, UNSIGNED, UNKNOWN_ONLINE,
           KNOWN_GOOD, UNCHECKED, HIDDEN_ZIP)


@dataclass
class Finding:
    check: str          # ID of the check that made it
    level: str          # one of LEVELS
    text: str           # plain sentences for the person reading the card
    details: dict = field(default_factory=dict)  # extra facts for the "details" section
    signals: list = field(default_factory=list)  # zero or more of SIGNALS

    def __post_init__(self):
        if self.level not in LEVELS:
            raise ValueError(f"unknown finding level: {self.level!r}")
        unknown = [s for s in self.signals if s not in SIGNALS]
        if unknown:
            raise ValueError(f"unknown signal: {unknown[0]!r}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(data["check"], data["level"], data["text"], dict(data.get("details") or {}),
                   list(data.get("signals") or []))


def detected(finding: Finding, engine: str, threat=None) -> Finding:
    """Mark a finding as an engine's detection (Defender, ClamAV, YARA ...) and the threat it names.
    Detections are never quieted by "Trust this file", and the card groups those naming the same threat."""
    finding.details.update(engine=engine, threat=threat or None)
    return finding


def risky(check, ability, text, details=None, hiding=False, level=NOTE) -> Finding:
    """A risky ability. `ability` is a short key so two checks finding the same thing count once."""
    signals = [RISKY, HIDING] if hiding else [RISKY]
    return Finding(check, level, text, {"ability": ability, **(details or {})}, signals)


def weak(check, ability, text, details=None) -> Finding:
    """Something many ordinary programs do. Quiet on its own; see verdict.py for when it counts."""
    return Finding(check, NOTE, text, {"ability": ability, **(details or {})}, [WEAK])


def unchecked(check, text, details=None, level=NOTE) -> Finding:
    """Part of the file wasn't looked at (too big, too deep, too slow). The answer can't be 'No known detections'."""
    return Finding(check, level, text, dict(details or {}), [UNCHECKED])


def hiding(check, what, text, details=None) -> Finding:
    return Finding(check, NOTE, text, {"ability": what, **(details or {})}, [HIDING])
