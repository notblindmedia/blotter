"""Windows programs (PE files): digital signature, packing, and risky combinations of Windows functions.

pefile only reads the file's structure. The signature is checked by Windows itself
(PowerShell's Get-AuthenticodeSignature, which reads the file and never runs it).
"""

import json
import math
import os

from .. import procs
from ..findings import CLEAR, NOTE, PACKED, SIGNED, SUSPICIOUS, UNSIGNED, Finding, risky, weak

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


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(bytes((i,))) for i in range(256)]  # 256 fast passes beat one slow Python loop
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def signature(path) -> dict:
    """Windows' verdict on the digital signature: {'status', 'signer'} (status 'Valid', 'NotSigned', ...)."""
    script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:BLOTTER_SIGNED_FILE; "
              "[pscustomobject]@{status = [string]$s.Status; signer = [string]$s.SignerCertificate.Subject; "
              "kind = [string]$s.SignatureType} | ConvertTo-Json -Compress")
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
            "kind": result.get("kind") or ""}


def _common_name(subject: str) -> str:
    for part in subject.split(","):
        key, _, value = part.strip().partition("=")
        if key == "CN":
            return value.strip('"')
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
    if status == "Valid":
        how = " (through a Windows catalog)" if signed.get("kind") == "Catalog" else ""
        return [Finding(check, CLEAR, f"It is digitally signed by {signer or 'a known publisher'}{how}, "
                                      "and Windows says the signature is valid.", details, [SIGNED])]
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
