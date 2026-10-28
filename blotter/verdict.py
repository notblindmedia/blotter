"""Turn all findings into one verdict with its reasons. No verdict promises a file is harmless.

Malicious            a check recognises it as malware
Suspicious           a warning sign on its own (a few antivirus engines, a broken signature),
                     a program disguised as another kind of file, or
                     risky abilities PLUS hiding / a lying name / packed and unsigned / unknown everywhere
Unusual              risky abilities only
No known detections  checks ran and found nothing

Weak signs (things ordinary programs do all the time: a runtime changing its own memory, talking to a
device, .NET loading its parts, compressed .NET resources, checking card-like numbers) are quiet on
their own. Together with context they count:
  weak + one of (unsigned, packed, VirusTotal never saw it)          -> Unusual
  weak + two of those, or one of those + hiding or a lying name      -> Suspicious
Couldn't check       nothing could run
Couldn't fully check part of the file was over a size, depth or time limit (never "No known detections")

Known-good software (CIRCL hashlookup) lowers a Suspicious or Unusual that came only from
abilities by one step. A file you trust can't be more than "No known detections" unless a check
recognises it as malware or couldn't finish.
"""

from collections import defaultdict

from .findings import (CLEAR, DISGUISED, ERROR, HIDING, KNOWN_GOOD, LYING_NAME, MALICIOUS, NOTE, PACKED,
                       RISKY, SIGNED, SKIPPED, SUSPICIOUS, UNCHECKED, UNKNOWN, UNKNOWN_ONLINE, UNSIGNED, WEAK)

VERDICTS = {
    "malicious": (
        "Malicious",
        "At least one check recognises this file as malware. Don't open or run it.",
    ),
    "suspicious": (
        "Suspicious",
        "There are warning signs, but no check recognises it as known malware. Be careful with this file.",
    ),
    "unusual": (
        "Unusual",
        "This file can do things that malware also does, but nothing hides it and no check recognises it "
        "as malware. Only use it if you trust where it came from.",
    ),
    "no_known_detections": (
        "No known detections",
        "None of the checks that ran recognise this file as malware or found risky abilities. "
        "That isn't proof it's harmless: new or rare malware can go unrecognised.",
    ),
    "couldnt_check": (
        "Couldn't check",
        "None of the checks could run, so Blotter has no answer for this file.",
    ),
    "couldnt_fully_check": (
        "Couldn't fully check",
        "Part of this file was too big, nested too deep or took too long to check, so Blotter can't say it "
        "has no known detections. What it did check is listed below.",
    ),
}

STEPS = ["no_known_detections", "unusual", "suspicious"]
_ORDER = {MALICIOUS: 0, SUSPICIOUS: 1, NOTE: 2, CLEAR: 3, UNKNOWN: 4, ERROR: 5, SKIPPED: 6}
_WHY = {
    HIDING: "it also hides what it is or does",
    LYING_NAME: "its name doesn't match what it really is",
    PACKED: "it is a packed program without a valid signature",
    UNKNOWN_ONLINE: "VirusTotal has never seen this file",
}
_CONTEXT = {UNSIGNED: "it isn't signed", PACKED: "it is packed", UNKNOWN_ONLINE: "VirusTotal has never seen it"}


def _weak(signals, unknown_everywhere):
    """(level, reasons) for weak signs with their context, or None while they stay quiet."""
    context = [s for s in (UNSIGNED, PACKED) if s in signals] + ([UNKNOWN_ONLINE] if unknown_everywhere else [])
    if WEAK not in signals or not context:
        return None
    strong = [s for s in (HIDING, LYING_NAME) if s in signals]
    level = "suspicious" if len(context) >= 2 or strong else "unusual"
    words = [_CONTEXT[s] for s in context] + [_WHY[s].replace("it also ", "it ") for s in strong]
    return level, ["signs that are common on their own add up: " + ", ".join(words)]


def _abilities(findings):
    """Per scope (the file itself, or one file inside an archive): its signals."""
    scopes = defaultdict(set)
    for f in findings:
        scopes[f.details.get("scope", "")].update(f.signals)
    return scopes


def decide(findings, trusted=False) -> dict:
    findings = list(findings)
    levels = {f.level for f in findings}
    everything = set().union(*(f.signals for f in findings)) if findings else set()
    unknown_everywhere = UNKNOWN_ONLINE in everything and KNOWN_GOOD not in everything

    heuristic, why, counted = None, [], set()
    for scope, signals in _abilities(findings).items():
        if DISGUISED in signals:
            level, reasons = "suspicious", ["it is a program or script dressed up as another kind of file"]
        elif RISKY in signals:
            reasons = [_WHY[s] for s in (HIDING, LYING_NAME) if s in signals]
            if PACKED in signals and SIGNED not in signals:
                reasons.append(_WHY[PACKED])
            if unknown_everywhere:
                reasons.append(_WHY[UNKNOWN_ONLINE])
            level = "suspicious" if reasons else "unusual"
        elif _weak(signals, unknown_everywhere):
            level, reasons = _weak(signals, unknown_everywhere)
            counted.add(scope)
        else:
            continue
        if heuristic is None or STEPS.index(level) > STEPS.index(heuristic):
            heuristic, why = level, reasons
        elif level == heuristic:
            why += [r for r in reasons if r not in why]

    if MALICIOUS in levels:
        key = "malicious"
    elif SUSPICIOUS in levels:
        key = "suspicious"
    elif heuristic == "suspicious":
        key = heuristic
    elif UNCHECKED in everything:
        # outranks Unusual: what wasn't checked could be worse
        key = "couldnt_fully_check" if levels & {NOTE, CLEAR, UNKNOWN} else "couldnt_check"
    elif heuristic:
        key = heuristic
    elif levels & {NOTE, CLEAR, UNKNOWN}:
        key = "no_known_detections"
    else:
        key = "couldnt_check"

    title, summary = VERDICTS[key]
    notes = []
    if key == heuristic and why:
        sentence = ("It can do risky things, and " if RISKY in everything else "") + ", and ".join(why)
        notes.append(sentence[0].upper() + sentence[1:] + ".")
    # Trust quiets warnings about abilities, never a detection and never a check that didn't finish.
    if trusted and key in ("suspicious", "unusual") and levels & {NOTE, CLEAR, UNKNOWN}:
        notes.append(f"You marked this file as trusted, so Blotter doesn't raise a warning for it "
                     f"(it would have said {title}).")
        key = "no_known_detections"
        title, summary = VERDICTS[key]
    elif trusted and key == "malicious":
        notes.append("You marked this file as trusted, but a check recognises it as malware.")
    elif KNOWN_GOOD in everything and key == heuristic and key in ("suspicious", "unusual"):
        lower = STEPS[STEPS.index(key) - 1]
        notes.append(f"CIRCL hashlookup lists it as known software, so Blotter lowered {title} to "
                     f"{VERDICTS[lower][0]}.")
        key = lower
        title, summary = VERDICTS[key]

    return {"verdict": key, "title": title, "summary": " ".join([summary, *notes]), "reasons": _reasons(findings, counted)}


def _reasons(findings, counted=()) -> list[str]:
    """Reasons, most serious first. Weak signs only appear where they counted (the rest stay in Details)."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: _ORDER[f.level]):
        if f.level == SKIPPED:
            continue
        if f.signals == [WEAK] and f.details.get("scope", "") not in counted:
            continue
        ability = f.details.get("ability")
        key = (f.details.get("scope", ""), ability) if ability else (f.check, f.text)
        if key in seen:
            continue  # two checks found the same ability: say it once
        seen.add(key)
        out.append(f.text)
    return out
