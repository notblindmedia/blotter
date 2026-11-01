"""Windows programs (PE files): digital signature, packing, and risky combinations of Windows functions.

pefile only reads the file's structure. The signature is checked by Windows itself
(PowerShell's Get-AuthenticodeSignature, which reads the file and never runs it).
"""

import json
import math
import os
import re

from .. import config, procs
from ..findings import CLEAR, NOTE, PACKED, PADDED, SIGNED, SUSPICIOUS, UNSIGNED, Finding, detected, risky, weak

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".themida": "Themida", ".winlice": "WinLicense", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", "pec2": "PECompact", ".packed": "a packer", ".perplex": "Perplex",
}
INJECT_WRITE = {"WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"}
INJECT_ALLOC = {"VirtualAllocEx", "NtAllocateVirtualMemory", "VirtualAlloc2", "MapViewOfFile2", "NtMapViewOfSection"}
INJECT_RUN = {"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
              "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtSetContextThread"}
DOWNLOAD = {"URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW"}
DRIVER = {"NtLoadDriver", "ZwLoadDriver"}
SIGNATURE_TIMEOUT = 40
PADDING_MIN = 10 * 1024 * 1024  # appended filler from this size on counts as padding


def overlay(path) -> dict | None:
    """Data appended after the program's last section: {'start', 'size', 'entropy'} or None.
    Reads only samples of it, so a 300 MB file costs a few MB."""
    import pefile
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            start = pe.get_overlay_data_start_offset()
        finally:
            pe.close()
    except (pefile.PEFormatError, OSError, ValueError, AttributeError):
        return None  # not a readable program: nothing to say about what follows it
    if start is None:
        return None
    total = os.path.getsize(path)
    size = total - start
    samples = []
    with open(path, "rb") as f:
        for i in range(16):
            f.seek(start + size * i // 16)
            samples.append(f.read(64 * 1024))
    return {"start": start, "size": size, "entropy": round(entropy(b"".join(samples)), 2)}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(bytes((i,))) for i in range(256)]  # 256 fast passes beat one slow Python loop
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def signature(path) -> dict:
    """Windows' verdict on the digital signature: {'status', 'signer', 'kind', 'serial', 'thumbprint',
    'sha256', 'issuer'}. 'thumbprint' is Windows' SHA-1 one; 'sha256' is what abuse.ch lists.

    Get-AuthenticodeSignature asks Windows' WinVerifyTrust, which checks both a signature inside the file
    and Windows' catalog files (how System32 programs like kernel32.dll are signed), so copies count too.
    """
    script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:BLOTTER_SIGNED_FILE; $c = $s.SignerCertificate; "
              "$h = ''; if ($c) { $h = [BitConverter]::ToString("
              "[Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)) -replace '-', '' }; "
              "[pscustomobject]@{status = [string]$s.Status; signer = [string]$c.Subject; "
              "kind = [string]$s.SignatureType; serial = [string]$c.SerialNumber; "
              "thumbprint = [string]$c.Thumbprint; sha256 = $h; issuer = [string]$c.Issuer} | ConvertTo-Json -Compress")
    env = {**os.environ, "BLOTTER_SIGNED_FILE": str(path)}
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]
    try:
        code, out, _ = procs.run(command, timeout=SIGNATURE_TIMEOUT, env=env)
    except OSError:
        return {"status": "Unavailable", "signer": ""}
    if code is None:
        return {"status": "TimedOut", "signer": ""}
    try:
        result = json.loads(out.decode("utf-8", "replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"status": "Unavailable", "signer": ""}
    return {"status": result.get("status") or "Unavailable", "signer": _common_name(result.get("signer") or ""),
            "kind": result.get("kind") or "", "serial": (result.get("serial") or "").lower(),
            "thumbprint": (result.get("thumbprint") or "").lower(), "sha256": (result.get("sha256") or "").lower(),
            "issuer": _common_name(result.get("issuer") or "")}


def _listed(name: str, folder=None) -> list[tuple[str, str]]:
    """(value, note) pairs from a list in rules/ (or `folder`): one value per line, # starts a note."""
    try:
        lines = ((folder or config.OWN_RULES) / name).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        value, _, note = line.partition("#")
        if value.strip():
            out.append((value.strip(), note.strip()))
    return out


def stolen_certificates() -> dict:
    """{serial or thumbprint (lower-case hex): note} from rules/stolen-certificates.txt plus the intel pack's
    newer copy in %LOCALAPPDATA%\\Blotter\\intel (blotter/intel.py). The pack can add entries, never remove one."""
    from ..intel import folder
    return {value.replace(" ", "").replace(":", "").lower(): note
            for where in (folder(), None) for value, note in _listed("stolen-certificates.txt", where)}


def well_known_publishers() -> set:
    """Lower-case signer names from rules/trusted-publishers.txt."""
    return {" ".join(value.split()).lower() for value, _ in _listed("trusted-publishers.txt")}


def _common_name(subject: str) -> str:
    """The CN part of a certificate subject such as 'CN="Advanced Micro Devices, Inc.", O=...'."""
    for m in re.finditer(r'(?:^|,)\s*([A-Za-z0-9.]+)=("(?:[^"]|"")*"|[^,]*)', subject):
        if m.group(1).upper() == "CN":
            value = m.group(2).strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('""', '"')
            return value
    return subject


def analyze(check, path, scope=None, check_signature=True) -> list[Finding]:
    import pefile

    s = {"scope": scope} if scope else {}
    out = []
    pe = None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imports = {imp.name.decode("latin-1") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                   for imp in entry.imports if imp.name}
        sections = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("latin-1", "replace")
            data = sec.get_data()[:4 * 1024 * 1024]
            sections.append({"name": name, "size": len(data), "entropy": round(entropy(data), 2),
                             "exec": bool(sec.Characteristics & 0x20000000)})
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        is_dotnet = len(dirs) > 14 and dirs[14].VirtualAddress != 0
    except (pefile.PEFormatError, IndexError, AttributeError, ValueError) as e:
        return [Finding(check, NOTE, f"It looks like a Windows program but its structure is broken ({e}). "
                                     "Damaged or deliberately malformed programs confuse scanners.", s)]
    finally:
        if pe is not None:
            pe.close()  # pefile maps the file; Windows can't delete it while that is open

    packer = next((PACKER_SECTIONS[s_["name"].lower()] for s_ in sections if s_["name"].lower() in PACKER_SECTIONS), None)
    dense = [s_ for s_ in sections if s_["exec"] and s_["size"] > 64 * 1024 and s_["entropy"] > 7.2]
    # .NET programs keep compressed resources (pictures, data) in their code section, so there
    # randomness is only a weak sign, counted together with other signs (verdict.py).
    dotnet_dense, dense = (dense, []) if is_dotnet else ([], dense)
    few_imports = not is_dotnet and len(imports) <= 8 and {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"} & imports
    packed_reason = (f"packed with {packer}" if packer else
                     "its code is compressed or scrambled (very random-looking data)" if dense else
                     "it hides almost all the Windows functions it uses" if few_imports else None)
    details = {**s, "sections": sections, "imports": len(imports), "dotnet": is_dotnet, "packer": packer}

    if check_signature:
        out += signature_findings(check, path, details)

    info = overlay(path)
    if info and info["size"] >= PADDING_MIN and info["size"] > info["start"] and info["entropy"] < 1.0:
        out.append(Finding(check, NOTE,
            f"It carries {info['size'] / 1024 ** 2:.0f} MB of empty filler after the real program "
            f"({info['start'] / 1024 ** 2:.1f} MB). Padding a program like that is a trick to get past "
            "scanners' size limits; Blotter checked the program without it.",
            {**s, "overlay": info, "ability": "padded"}, [PADDED]))
    if dotnet_dense:
        out.append(weak(check, "dotnet-compressed",
            "Part of its code section is compressed or scrambled. In .NET programs that is usually packed-in "
            "pictures or data; on its own it means little.", {**s, "sections": [d["name"] for d in dotnet_dense]}))
    if packed_reason:
        out.append(Finding(check, NOTE,
            f"It is packed: {packed_reason}, so its real code is hidden until it runs. Some legitimate "
            "programs do that to stay small or protect themselves, but malware does it to avoid scanners.",
            {**details, "ability": "packed"}, [PACKED]))

    if INJECT_WRITE & imports and INJECT_ALLOC & imports and INJECT_RUN & imports:
        out.append(risky(check, "inject",
            "It can inject code into other running programs. Cheats, mod loaders and some overlays do that "
            "too, but so does malware.", {**s, "functions": sorted((INJECT_WRITE | INJECT_ALLOC | INJECT_RUN) & imports)}))
    if DOWNLOAD & imports:
        out.append(risky(check, "download",
            "It can download files from the internet by itself. Installers and updaters do that too.",
            {**s, "functions": sorted(DOWNLOAD & imports)}))
    if DRIVER & imports:
        out.append(risky(check, "driver",
            "It can load a driver into the core of Windows. Anti-cheat and hardware tools do that too, but so "
            "do rootkits.", {**s, "functions": sorted(DRIVER & imports)}))
    if not out:
        out.append(Finding(check, CLEAR, "Its program structure shows nothing unusual.", details))
    return out


def signature_findings(check, path, details=None) -> list[Finding]:
    """What Windows says about the program's digital signature, as findings."""
    details = dict(details or {})
    signed = signature(path)
    details["signature"] = signed
    status, signer = signed["status"], signed["signer"]
    # Checked whatever Windows says: a stolen certificate is often revoked or expired by the time it is listed.
    stolen = stolen_certificates()
    hit = next((stolen[k] for k in (signed.get("sha256"), signed.get("thumbprint"), signed.get("serial"))
                if k and k in stolen), None)
    if hit is not None:
        return [detected(Finding(check, SUSPICIOUS,
            f"It is signed as {signer or 'a publisher'}, but with a certificate known to be stolen or abused to "
            f"sign malware ({hit or 'on Blotter list'}). Such a signature proves nothing.", details),
            "Blotter", "stolen certificate")]
    if status == "Valid":
        how = " (through a Windows catalog)" if signed.get("kind") == "Catalog" else ""
        if signer and " ".join(signer.split()).lower() in well_known_publishers():
            details["trusted_publisher"] = signer
            return [Finding(check, CLEAR, f"It is digitally signed by {signer}{how}, and Windows says the "
                                          "signature is valid. That publisher is on Blotter's list of "
                                          "well-known publishers.", details, [SIGNED])]
        # Any company can buy a code-signing certificate, so other signatures only count for a little.
        details["signed_by"] = signer or "an unnamed publisher"
        return [Finding(check, CLEAR, f"It is digitally signed by {signer or 'an unnamed publisher'}{how}, and "
                                      "Windows says the signature is valid. That publisher isn't on Blotter's "
                                      "short list of well-known publishers, so the signature counts for a "
                                      "little, not a lot.", details, [SIGNED])]
    if status == "HashMismatch":
        return [Finding(check, SUSPICIOUS,
            "It carries a digital signature that no longer matches the file: it was changed after it was "
            "signed. Legitimate programs don't look like that.", details)]
    if status == "NotSigned":
        return [Finding(check, NOTE, "It isn't digitally signed. Many small tools and mods aren't, but big "
                                     "companies usually sign their programs.", details, [UNSIGNED])]
    if status in ("NotTrusted", "UnknownError", "NotSupportedFileFormat"):
        return [Finding(check, NOTE, f"It has a signature Windows doesn't trust ({signer or 'unknown signer'}"
                                     f", {status}). Self-made and test signatures look like this.", details,
                        [UNSIGNED])]
    return [Finding(check, NOTE, "Windows couldn't check its signature this time.", details)]
