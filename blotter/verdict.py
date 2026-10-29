"""Turn all findings into one verdict with its reasons. No verdict promises a file is harmless.

Malicious            a check recognises it as malware
Suspicious           a warning sign on its own (a few antivirus engines, a broken signature),
                     a program disguised as another kind of file, or
                     risky abilities PLUS hiding / a lying name / packed and unsigned / unknown everywhere
Unusual              risky abilities only

A valid signature from a well-known publisher (rules/trusted-publishers.txt, not on
rules/stolen-certificates.txt) quiets the program's abilities (capa, program and script patterns):
they stay listed but don't raise the answer. If capa had to skip such a program (too big, too slow),
the card says "Signed by <publisher>, deep check skipped" instead of "Couldn't fully check".
Any other valid signature forgives one warning sign: risky abilities need two reasons (instead of one)
to reach Suspicious, and weak signs count one step lower.
Engine detections that name malware are never quieted. ClamAV's generic guesses (heuristics, PUA,
packer names) are Suspicious at most, and Unusual for a well-known publisher's program.
An unsigned program padded with lots of empty filler is Suspicious on its own.
No known detections  checks ran and found nothing

Weak signs (things ordinary programs do all the time: a runtime changing its own memory, talking to a
device, .NET loading its parts, compressed .NET resources, checking card-like numbers) are quiet on
their own. Together with context they count:
  weak + one of (unsigned, packed, VirusTotal never saw it)          -> Unusual
  weak + two of those, or one of those + hiding or a lying name      -> Suspicious
Couldn't check       nothing could run
Couldn't fully check part of the file was over a size, depth or time limit, a check made for its kind of
                     file (unpacking, capa, Office, RTF, PDF, program, script, signature) or YARA failed on
                     it, or no antivirus engine could scan it (Defender and ClamAV both failed; in test mode
                     ClamAV alone).
                     Never "No known detections"; only Malicious or Suspicious from another check outranks it.

Known-good software (CIRCL hashlookup) lowers a Suspicious or Unusual that came only from
abilities by one step. A file you trust can't be more than "No known detections" unless a check
recognises it as malware or couldn't finish.
"""

import re
from collections import defaultdict

from .findings import (CLEAR, DISGUISED, ERROR, HIDING, KNOWN_GOOD, LYING_NAME, MALICIOUS, NOTE, PACKED, PADDED,
                       RISKY, SIGNED, SKIPPED, SUSPICIOUS, UNCHECKED, UNKNOWN, UNKNOWN_ONLINE, UNSIGNED, WEAK,
                       Finding)

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
        "Part of this file couldn't be checked (too big, nested too deep, too slow, or a check couldn't read it), "
        "so Blotter can't say it has no known detections. What it did check, and what it couldn't, is listed below.",
    ),
}

STEPS = ["no_known_detections", "unusual", "suspicious"]
# Checks made for one kind of file, and YARA. If one of them fails on a file it applies to, part of the file
# wasn't read, so the answer can't be "No known detections" (fail closed).
FILE_READERS = {"archive", "capa", "macros", "rtf", "pdf", "program", "scripts", "signature", "yara"}
# The antivirus engines fail closed together: when every one that tried failed and none scanned the file
# (in test mode, without Defender, that is ClamAV alone). One failing while another scans stays a note,
# and so do the online lookups.
AV_ENGINES = {"defender", "clamav"}
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


def _fail_closed(f, no_av=False):
    """A file reader that errored didn't finish reading the file: count it like a limit. So does an antivirus
    engine's error when no engine scanned the file (no_av)."""
    if f.level != ERROR or UNCHECKED in f.signals or not (f.check in FILE_READERS or no_av and f.check in AV_ENGINES):
        return f
    return Finding(f.check, f.level, f.text, dict(f.details), [*f.signals, UNCHECKED])


def _no_av_scanned(findings) -> bool:
    """True when an antivirus engine tried and failed, and none scanned the file."""
    tried = {f.check for f in findings if f.check in AV_ENGINES and f.level != SKIPPED}
    scanned = {f.check for f in findings if f.check in AV_ENGINES and f.level not in (ERROR, SKIPPED)}
    return bool(tried) and not scanned


def _deep_check_skipped(f, signed_by):
    """For a program signed by a trusted publisher, capa being skipped (too big or too slow) isn't a gap
    worth "Couldn't fully check": say so plainly instead. Unsigned programs keep the warning."""
    scope = f.details.get("scope", "")
    if not f.details.get("deep_check") or scope not in signed_by:
        return f
    return Finding(f.check, NOTE, f"Signed by {signed_by[scope]}, deep check skipped.", dict(f.details),
                   [s for s in f.signals if s != UNCHECKED])


def _generic_clamav(f, signed_by):
    """ClamAV's generic guess on a well-known publisher's program: a note that keeps the answer at Unusual."""
    kind = f.details.get("generic")
    if f.check != "clamav" or f.level != SUSPICIOUS or not kind or "" not in signed_by:
        return f
    what = "generic packer guess" if kind == "packer" else "generic guess"
    return Finding(f.check, NOTE, f"ClamAV's {what}; the file is signed by {signed_by[''].rstrip('.')}.",
                   {**f.details, "signed_generic": True}, list(f.signals))


def _vt_words(f) -> str:
    """'1 VirusTotal engine flags it' / '2 VirusTotal engines flag it' / '... call it suspicious'."""
    mal, sus = int(f.details.get("malicious") or 0), int(f.details.get("suspicious") or 0)
    if mal:
        return "1 VirusTotal engine flags it" if mal == 1 else f"{mal} VirusTotal engines flag it"
    return "1 VirusTotal engine calls it suspicious" if sus == 1 else f"{sus} VirusTotal engines call it suspicious"


def _abilities(findings):
    """Per scope (the file itself, or one file inside an archive): its signals."""
    scopes = defaultdict(set)
    for f in findings:
        scopes[f.details.get("scope", "")].update(f.signals)
    return scopes


def decide(findings, trusted=False) -> dict:
    findings = list(findings)
    # Programs signed by a trusted publisher (valid signature, not on the stolen-certificate list).
    signed_by = {f.details.get("scope", ""): f.details["trusted_publisher"] for f in findings
                 if f.details.get("trusted_publisher") and SIGNED in f.signals}
    # Programs with any other valid signature: it counts for a little (forgives one warning sign).
    mild = {f.details.get("scope", ""): f.details["signed_by"] for f in findings
            if f.details.get("signed_by") and SIGNED in f.signals}
    no_av = _no_av_scanned(findings)
    findings = [_generic_clamav(_deep_check_skipped(_fail_closed(f, no_av), signed_by), signed_by) for f in findings]
    generic_signed = [f for f in findings if f.details.get("signed_generic")]
    levels = {f.level for f in findings}
    everything = set().union(*(f.signals for f in findings)) if findings else set()
    unknown_everywhere = UNKNOWN_ONLINE in everything and KNOWN_GOOD not in everything

    heuristic, why, counted, quieted = None, [], set(), []
    for scope, signals in _abilities(findings).items():
        if DISGUISED in signals:
            level, reasons = "suspicious", ["it is a program or script dressed up as another kind of file"]
        elif PADDED in signals and SIGNED not in signals:
            level, reasons = "suspicious", ["it is an unsigned program padded with empty filler, a trick to get "
                                            "past scanners' size limits"]
        elif scope in signed_by:
            # A trusted publisher's program: what it can do is what such programs normally do. Its abilities
            # stay on the card but don't raise the answer. Engine detections are counted further down as usual.
            if signals & {RISKY, HIDING, WEAK, PACKED}:
                quieted.append(signed_by[scope])
            continue
        elif RISKY in signals:
            reasons = [_WHY[s] for s in (HIDING, LYING_NAME) if s in signals]
            if PACKED in signals and SIGNED not in signals:
                reasons.append(_WHY[PACKED])
            if unknown_everywhere:
                reasons.append(_WHY[UNKNOWN_ONLINE])
            level = "suspicious" if len(reasons) >= (2 if scope in mild else 1) else "unusual"
            if scope in mild and level == "suspicious":
                reasons.append(f"its signature ({mild[scope]}) doesn't outweigh that")
        elif _weak(signals, unknown_everywhere):
            level, reasons = _weak(signals, unknown_everywhere)
            if scope in mild:
                if level == "unusual":
                    continue  # the signature outweighs one weak sign with one bit of context
                level = "unusual"
            counted.add(scope)
        else:
            continue
        if heuristic is None or STEPS.index(level) > STEPS.index(heuristic):
            heuristic, why = level, reasons
        elif level == heuristic:
            why += [r for r in reasons if r not in why]

    if generic_signed and heuristic is None:
        heuristic = "unusual"

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
    notes = [f.text for f in generic_signed]
    if quieted and key in ("no_known_detections", "unusual"):
        notes.append(f"It is signed by {quieted[0]}, a trusted publisher, so what it can do (listed below) "
                     "doesn't raise a warning.")
    if key == heuristic and why:
        sentence = ("It can do risky things, and " if RISKY in everything else "") + ", and ".join(why)
        notes.append(sentence[0].upper() + sentence[1:] + ".")
    # Trust (and CIRCL's known-good) quiet warnings about abilities, and a weak VirusTotal result (1-2 engines,
    # often false alarms). Never: Malicious (3+ VirusTotal engines, Defender, ClamAV, MalwareBazaar, YARA),
    # ClamAV's or YARA's broader warnings, capa malware families, or an unfinished check.
    weak_vt = [f for f in findings if f.check == "virustotal" and f.level == SUSPICIOUS]
    weak_ids = {id(f) for f in weak_vt}
    flagged = any(f.level == MALICIOUS or (f.details.get("engine") and f.level == SUSPICIOUS and id(f) not in weak_ids)
                  for f in findings) or bool(generic_signed)
    quiet_to = "couldnt_fully_check" if UNCHECKED in everything else "no_known_detections"
    if trusted and flagged:
        word = "detected" if key == "malicious" else "flagged"
        notes.append(f"You trusted this file before, but it is now {word}. Your trust stays saved; "
                     "remove it under Settings if you no longer trust the file.")
    elif trusted and key in ("suspicious", "unusual") and levels & {NOTE, CLEAR, UNKNOWN}:
        if weak_vt:
            notes.append(f"You trusted this file; {_vt_words(weak_vt[0])}.")
        else:
            notes.append(f"You marked this file as trusted, so Blotter doesn't raise a warning for it "
                         f"(it would have said {title}).")
        key = quiet_to
        title, summary = VERDICTS[key]
    elif KNOWN_GOOD in everything and not (flagged or weak_vt) and key == heuristic and key in ("suspicious", "unusual"):
        lower = STEPS[STEPS.index(key) - 1]
        notes.append(f"CIRCL hashlookup lists it as known software, so Blotter lowered {title} to "
                     f"{VERDICTS[lower][0]}.")
        key = lower
        title, summary = VERDICTS[key]

    return {"verdict": key, "title": title, "summary": " ".join([summary, *notes]), "reasons": _reasons(findings, counted)}


# Engines in the order the card names them, and words that say nothing about which threat it is.
ENGINE_ORDER = ["Defender", "ClamAV", "MalwareBazaar", "VirusTotal", "YARA", "Blotter", "capa"]
_GENERIC = set("""virus trojan worm backdoor dropper downloader ransom ransomware spyware adware riskware pua
    win32 win64 windows dos msil linux script test file files signature signatures sample known family malw
    malware generic heur heuristic heuristics agent variant rule rules detect detects detection pattern standard
    antivirus string strings trellix elastic ditekshen signature_base malpedia auto suspicious hacktool tool
    trojandownloader trojandropper trojanspy trojanclicker trojanproxy trojanpws pwsstealer virtool exploit
    behavior packed obfuscated obfuscator stealer infostealer loader keylogger miner coinminer potentially
    unwanted program application other multi andr android macos script html office doc pdf
    the this that with from""".split())


def _threat_words(f) -> set:
    raw = " ".join(str(x) for x in (f.details.get("threat"), f.details.get("rule")) if x)
    return {w for w in re.findall(r"[a-z0-9]+", raw.lower()) if len(w) >= 4 and w not in _GENERIC and not w.isdigit()}


def _threat_name(group, words) -> str:
    if "eicar" in words:
        return "EICAR test file"
    counts = {}
    for f in group:
        for w in _threat_words(f):
            counts[w] = counts.get(w, 0) + 1
    word = max(sorted(counts), key=lambda w: counts[w])
    for f in group:  # keep the spelling an engine used, e.g. AgentTesla
        m = re.search(re.escape(word), str(f.details.get("threat") or ""), re.I)
        if m:
            return m.group(0)
    return word.title()


def _grouped_detections(findings):
    """{id(finding): line or None}: detections at the same level naming the same threat share one line
    ('Recognised as EICAR test file by Defender, ClamAV, YARA and Blotter.'); the rest are left alone."""
    detections = [f for f in findings if f.details.get("engine") and f.level in (MALICIOUS, SUSPICIOUS)]
    groups, unnamed = [], []  # groups: [level, words, members]
    for f in detections:
        words = _threat_words(f)
        if not words:
            unnamed.append(f)  # e.g. Defender removed the copy without saying what it found
            continue
        home = next((g for g in groups if g[0] == f.level and g[1] & words), None)
        if home:
            home[1] |= words
            home[2].append(f)
        else:
            groups.append([f.level, set(words), [f]])
    for f in unnamed:
        # Without a name it can only join when there is exactly one threat at its level on the card.
        same_level = [g for g in groups if g[0] == f.level]
        if len(same_level) == 1:
            same_level[0][2].append(f)
    out = {}
    for level, words, members in groups:
        if len(members) < 2:
            continue
        engines = sorted({m.details["engine"] for m in members},
                         key=lambda e: ENGINE_ORDER.index(e) if e in ENGINE_ORDER else 99)
        names = engines[0] if len(engines) == 1 else ", ".join(engines[:-1]) + " and " + engines[-1]
        verb = "Recognised as" if level == MALICIOUS else "Flagged as possibly"
        line = f"{verb} {_threat_name(members, words)} by {names}."
        out[id(members[0])] = line
        for m in members[1:]:
            out[id(m)] = None
    return out


def _weak_counted(f) -> Finding:
    """capa's 'none of the risky ones' line, when its weak signs made the answer Unusual: name them instead."""
    labels = f.details["weak_labels"]
    signs = "a weak sign that counts here" if len(labels) == 1 else "weak signs that count here"
    return Finding(f.check, f.level, f"capa found {f.details.get('rules', 'some')} abilities, including {signs}: "
                                     f"{'; '.join(labels)}.", dict(f.details), list(f.signals))


def _reasons(findings, counted=()) -> list[str]:
    """Reasons, most serious first. Weak signs only appear where they counted (the rest stay in Details).
    Detections naming the same threat are one line here; each check's own line stays under Details."""
    seen, out = set(), []
    grouped = _grouped_detections(findings)
    for f in sorted(findings, key=lambda f: 2.5 if UNCHECKED in f.signals else _ORDER[f.level]):
        if f.level == SKIPPED:
            continue
        if f.details.get("weak_labels") and f.details.get("scope", "") in counted:
            f = _weak_counted(f)
        if id(f) in grouped:
            if grouped[id(f)]:
                out.append(grouped[id(f)])
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
