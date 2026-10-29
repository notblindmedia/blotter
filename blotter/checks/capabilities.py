"""Layer 2: what a program can do, with capa (Mandiant's open-source tool).

capa reads the program's machine code without running it and names abilities such as
"inject code into another process". Blotter keeps only the abilities that matter for malware
and says each one in plain words, with what else does the same.
"""

import json
import os
import re
import tempfile
from pathlib import Path


from .. import capa_fast, config, procs, worker
from ..analyze import filetype, program
from ..findings import (CLEAR, ERROR, SKIPPED, SUSPICIOUS, WEAK, Finding, detected, hiding, risky, unchecked,
                        weak)

ID = "capa"
NAME = "Abilities (capa)"
ORDER = 55
TIMEOUT = 15 * 60
CACHE = True          # capa is slow and gives the same answer for the same file and rules
CACHE_VERSION = "capa-9.4.0-1"  # change when the rules, capa or the ability list change
NEEDS_FILE = True
BACKGROUND = True     # the deep check: the answer is shown without it and updated when it finishes (runner.py)

CAPA_TIMEOUT = TIMEOUT - 15
MAX_SIZE = 25 * 1024 * 1024

# (pattern, ability key, kind, sentence), matched against "namespace :: rule name". First match wins.
# Kind: risky / hiding / both. Broad rules that ordinary programs trip (a program changing its own
# memory, talking to a device, checking a card number) are left out on purpose.
ABILITIES = [
    (r"^malware-family/", "family", "family", None),
    (r"^host-interaction/process/inject :: .*(inject|hollow|remote|apc|write process memory|attach user process)"
     r"|inject dll reflectively|process hollowing",
     "inject", "risky", "It can inject code into other running programs. Cheats, mod loaders and some overlays "
                        "do that too, but so does malware."),
    (r"^collection/keylog", "keylog", "risky",
     "It can record what you type. Hotkey and macro tools do that too, but so does spyware."),
    (r"^collection/(browser|password-manager|file-managers) ::|credential manager|steam token",
     "credentials", "risky", "It looks for saved passwords, browser logins or game account tokens. Password "
                             "managers and import tools do that too, but it is what password stealers do."),
    (r"^collection/(microphone|webcam|screenshot)", "spy", "risky",
     "It can use the microphone or webcam, or take screenshots. Chat, streaming and screenshot tools do that "
     "too, but so does spyware."),
    (r"^communication/c2/", "remote", "risky",
     "It can take commands or files over the network, like a remote-control tool. Remote-desktop tools and "
     "updaters do that too, but so do backdoors."),
    (r"^persistence/(?!office)", "persistence", "risky",
     "It can make itself start automatically with Windows. Launchers and updaters do that too, but so does "
     "malware that wants to stay."),
    (r"^host-interaction/uac/bypass", "uac-bypass", "both",
     "It tries to get administrator rights without asking you. Legitimate programs use the normal Windows "
     "prompt instead."),
    (r"disable (driver )?code (integrity|signing)|^host-interaction/bootloader", "boot", "both",
     "It can switch off Windows' driver checks or change how Windows starts. Rootkits do that."),
    (r"^host-interaction/(driver|filter) :: .*(install driver|load driver|register minifilter|start minifilter)",
     "driver", "risky",
     "It can install or load a driver into the core of Windows. Anti-cheat and hardware tools do that too, "
     "but so do rootkits."),
    (r"^host-interaction/firewall/modify", "firewall", "risky",
     "It can change Windows Firewall settings. Games and servers sometimes add firewall rules too."),
    (r"^impact/inhibit-system-recovery", "delete-backups", "both",
     "It can delete Windows' backup copies (shadow copies). Ransomware does that before it locks your files."),
    (r"^impact/", "wipe", "risky", "It can wipe disks or damage how Windows starts. Disk tools do that too."),
    (r"^load-code/shellcode", "shellcode", "risky",
     "It can run machine code it builds in memory. Game engines and mod loaders sometimes do that too, but so "
     "does malware that hides from scanners."),
    (r"^load-code/powershell|^load-code ::|execute .*script", "load-script", "risky",
     "It runs PowerShell or script code from inside itself."),
    (r"download and write a file|write and execute a file", "download-run", "risky",
     "It can download files and run them. Installers, launchers and updaters do that too, but so do malware "
     "\"droppers\"."),
    (r"^anti-analysis/anti-forensic|bypass mark of the web|bypass powershell", "cover-tracks", "hiding",
     "It can cover its tracks (delete itself, clear Windows' logs or remove the downloaded-from-internet "
     "mark)."),
    (r"^anti-analysis/(anti-debugging|anti-vm|anti-av|anti-emulation|anti-disasm)", "anti-analysis", "hiding",
     "It checks whether it is being watched (debuggers, virtual machines or antivirus). Games with copy "
     "protection or anti-cheat do that too."),
    (r"^anti-analysis/(obfuscation|packer)", "packed", "hiding",
     "Its code is packed or scrambled ({name}). Some commercial programs protect themselves like that, but "
     "malware does it to avoid detection."),
]
# Weak signs: ordinary programs trip these all the time (a runtime changing its own memory, talking
# to a device, checking a number, .NET loading its own parts). Quiet on their own; they count when the
# program is also unsigned, packed or unknown everywhere (verdict.py).
WEAK_ABILITIES = [
    (r"^host-interaction/process/inject ::", "memory", "It can make parts of its own memory runnable or reach "
     "into process memory. Many ordinary programs (runtimes, script engines) do that; on its own it means little."),
    (r"^collection/credit-card ::", "card-numbers", "It contains code that checks or reads card-like numbers. "
     "Text tools trip this too; on its own it means little."),
    (r"^host-interaction/(driver|filter) ::", "device", "It talks to a device driver. Disk, game-controller and "
     "hardware tools do that; on its own it means little."),
    (r"^load-code/dotnet ::", "load-assembly", "It loads extra .NET code while running. Most .NET programs do "
     "that; on its own it means little."),
]
LIMITATION = re.compile(r"^internal/limitation")


def command(path) -> list[str]:
    args = ["-j", "-q", "--color", "never", "-r", str(config.CAPA_RULES), "--os", "auto"]
    if config.CAPA_SIGS.is_dir():
        args += ["-s", str(config.CAPA_SIGS)]
    return worker.module_command("blotter.capa_fast", args + [str(path)])  # capa with vivisect's speed fix


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    if ft.real != "pe":
        return [Finding(ID, SKIPPED, "Not a Windows program, so capa had nothing to look at.")]
    target, note = _without_overlay(path)
    if os.path.getsize(target) > MAX_SIZE:
        return [unchecked(ID, f"The program is over {MAX_SIZE // 1024 ** 2} MB, which would take capa "
                              "too long, so its abilities weren't checked; the other checks still looked at it.",
                          {"deep_check": True})]
    if not config.CAPA_RULES.is_dir():
        return [Finding(ID, ERROR, "capa's rules aren't downloaded yet (run Update rules in Settings).")]
    code, out, err = procs.run(command(target), timeout=CAPA_TIMEOUT, memory_limit=config.WORKER_MEMORY,
                               priority=procs.BELOW_NORMAL)  # the deep check never slows the PC down
    if code is None:
        return [unchecked(ID, f"capa didn't finish this program within {TIMEOUT // 60} minutes, so Blotter "
                              "stopped it. Programs with very many functions can take that long.",
                          {"deep_check": True})]
    try:
        result = json.loads(out.decode("utf-8", "replace"))
    except ValueError:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [f"exit code {code}"]
        return [Finding(ID, ERROR, f"capa couldn't analyse this program ({tail[0][:160]}).")]
    found = interpret(result)
    if note:
        found.append(Finding(ID, CLEAR, note))
    if capa_fast.WARNING.encode() in err:
        found.append(Finding(ID, CLEAR, "capa ran without Blotter's speed fix because the installed vivisect "
                                        f"isn't version {capa_fast.VIVISECT}, so it was slower. The results "
                                        "are the same."))
    return found


def _without_overlay(path):
    """capa only needs the program itself. Data appended after it (the "overlay": installer payloads,
    signatures, or padding meant to push a file past scanners' size limits) is cut off first."""
    info = program.overlay(path)
    if not info or info["size"] < 1024 * 1024:
        return path, None
    folder = Path(os.environ.get("BLOTTER_WORK") or tempfile.mkdtemp())
    trimmed = folder / "without-overlay.blotter"
    with open(path, "rb") as src, open(trimmed, "wb") as out:
        left = info["start"]
        while left > 0 and (chunk := src.read(min(left, 1024 * 1024))):
            out.write(chunk)
            left -= len(chunk)
    mb = info["size"] / 1024 ** 2
    return trimmed, (f"capa looked at the program itself and skipped the {mb:.0f} MB of data appended after it.")


def interpret(result: dict) -> list[Finding]:
    rules = result.get("rules") or {}
    found, seen = [], set()
    for name, rule in sorted(rules.items()):
        meta = rule.get("meta") or {}
        namespace = meta.get("namespace") or ""
        if meta.get("lib") or namespace.startswith("nursery"):
            continue
        if LIMITATION.match(namespace):
            found.append(Finding(ID, CLEAR, f"capa can't see far inside this kind of program "
                                            f"({name.replace('(internal) ', '')}); other checks still ran.",
                                 {"rule": name}))
            continue
        target = f"{namespace} :: {name}"
        details = {"rule": name, "namespace": namespace, "attack": meta.get("attack") or []}
        for pattern, ability, kind, sentence in ABILITIES:
            if re.search(pattern, target, re.I):
                break
        else:
            for pattern, ability, sentence in WEAK_ABILITIES:
                if re.search(pattern, target, re.I) and ability not in seen:
                    seen.add(ability)
                    found.append(weak(ID, ability, sentence, details))
                    break
            continue
        if ability == "family":
            family = namespace.split("/")[1] if "/" in namespace else name
            found.append(detected(Finding(ID, SUSPICIOUS, f"capa recognises code from the {family} malware family "
                                                          f"(\"{name}\").", details), "capa", family))
            continue
        if ability in seen:
            continue
        seen.add(ability)
        text = sentence.format(name=name)
        if kind == "hiding":
            found.append(hiding(ID, ability, text, details))
        else:
            found.append(risky(ID, ability, text, details, hiding=kind == "both"))
    if all(WEAK in f.signals for f in found):
        count = len(rules)
        found.append(Finding(ID, CLEAR, f"capa found {count} abilities and none of the risky ones Blotter looks "
                                        "for.", {"rules": count}))
        return found
    if not found:
        count = len(rules)
        return [Finding(ID, CLEAR, f"capa found {count} ordinary abilities and none of the risky ones Blotter "
                                   "looks for.", {"rules": count})]
    return found
