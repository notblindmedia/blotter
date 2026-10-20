"""The one shape every check returns: a list of Findings."""

from dataclasses import asdict, dataclass, field

MALICIOUS = "malicious"    # the check recognises the file as malware
SUSPICIOUS = "suspicious"  # a weak or partial warning sign
CLEAR = "clear"            # the check ran and recognised nothing
UNKNOWN = "unknown"        # the check ran but has no record of this file
ERROR = "error"            # the check could not run

LEVELS = (MALICIOUS, SUSPICIOUS, CLEAR, UNKNOWN, ERROR)


@dataclass
class Finding:
    check: str          # ID of the check that made it
    level: str          # one of LEVELS
    text: str           # one plain sentence for the person reading the card
    details: dict = field(default_factory=dict)  # extra facts for the "details" section

    def __post_init__(self):
        if self.level not in LEVELS:
            raise ValueError(f"unknown finding level: {self.level!r}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(data["check"], data["level"], data["text"], dict(data.get("details") or {}))
