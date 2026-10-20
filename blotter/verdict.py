"""Turn all findings into one verdict with its reasons. No verdict promises a file is harmless."""

from .findings import CLEAR, ERROR, MALICIOUS, SUSPICIOUS, UNKNOWN

VERDICTS = {
    "malicious": (
        "Malicious",
        "At least one check recognises this file as malware. Don't open or run it.",
    ),
    "suspicious": (
        "Suspicious",
        "A check raised a warning sign, but no clear detection. Be careful with this file.",
    ),
    "no_known_detections": (
        "No known detections",
        "None of the checks that ran recognise this file as malware. "
        "That isn't proof it's harmless: new or rare malware can go unrecognised.",
    ),
    "couldnt_check": (
        "Couldn't check",
        "None of the checks could run, so Blotter has no answer for this file.",
    ),
}

_ORDER = {MALICIOUS: 0, SUSPICIOUS: 1, CLEAR: 2, UNKNOWN: 3, ERROR: 4}


def decide(findings) -> dict:
    levels = {f.level for f in findings}
    if MALICIOUS in levels:
        key = "malicious"
    elif SUSPICIOUS in levels:
        key = "suspicious"
    elif levels & {CLEAR, UNKNOWN}:
        key = "no_known_detections"
    else:
        key = "couldnt_check"
    title, summary = VERDICTS[key]
    reasons = [f.text for f in sorted(findings, key=lambda f: _ORDER[f.level])]
    return {"verdict": key, "title": title, "summary": summary, "reasons": reasons}
