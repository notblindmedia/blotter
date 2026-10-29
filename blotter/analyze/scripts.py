"""Script and shortcut checks: .ps1 .bat .cmd .vbs .js .hta .wsf .lnk and friends.

Only reads the text. Patterns look for what script malware typically does: download something
and run it, hide its window, carry an encoded command, scramble itself, switch off Defender.
"""

import re
import struct

from ..findings import NOTE, Finding, hiding, risky

SCRIPT_EXTS = {"ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg"}
MAX_TEXT = 4 * 1024 * 1024
I = re.I | re.S

DOWNLOAD = re.compile(
    r"invoke-webrequest|\biwr\s|\bwget\s+https?:|\bcurl(?:\.exe)?\s+\S*https?:|net\.webclient|downloadstring|"
    r"downloaddata|downloadfile|start-bitstransfer|bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s+\S*\s*-urlcache|"
    r"msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp|invoke-restmethod|\birm\s+https?:", I)
EXECUTE = re.compile(
    r"invoke-expression|\biex\b|start-process|\bsaps\s|shellexecute|wscript\.shell|shell\.application|"
    r"\.run\s*\(|\.exec\s*\(|rundll32|regsvr32|mshta|\bcmd(?:\.exe)?\s+/[ck]\b|\bpowershell(?:\.exe)?\s|"
    r"\bstart\s+\"\"|invoke-item|\bii\s|\.\s*\(\s*\$", I)
ENCODED_COMMAND = re.compile(r"\s-(?:e|ec|en|enc|enco\w*)\s+['\"]?[A-Za-z0-9+/]{40,}={0,2}", I)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
FROM_BASE64 = re.compile(r"frombase64string|\batob\s*\(|base64\s+(?:-d|--decode)|certutil(?:\.exe)?\s+-decode", I)
HIDDEN_WINDOW = re.compile(r"-w(?:indowstyle)?\s+h(?:idden)?\b|\bvbhide\b|createnowindow\s*=\s*\$?true|"
                           r"\.run\s*\([^)]*,\s*0\s*(?:,|\))", I)
DEFENDER = re.compile(r"set-mppreference|add-mppreference\s[^\n]*-exclusion|disablerealtimemonitoring|"
                      r"\bsc(?:\.exe)?\s+(?:stop|config|delete)\s+windefend|amsiinitfailed|amsiutils|"
                      r"amsiscanbuffer", I)
PERSIST = re.compile(r"schtasks(?:\.exe)?\s+/create|register-scheduledtask|new-scheduledtask|"
                     r"currentversion\\run(?:once)?\b|\\start menu\\programs\\startup|new-service\s|"
                     r"\bsc(?:\.exe)?\s+create\s", I)
BACKUPS = re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no|"
                     r"wbadmin(?:\.exe)?\s+delete", I)
CREDENTIALS = re.compile(r"\\login data\b|\\local state\b|sekurlsa|mimikatz|\blsass(?:\.exe)?\b|\\cookies\b", I)
OBFUSCATION = [
    ("backticks", re.compile(r"\w`\w`\w|`[a-z]`[a-z]", I)),
    ("char codes", re.compile(r"(?:\[char\]\s*\d+\s*[+,]?\s*){6,}|(?:chrw?\s*\(\s*\d+\s*\)\s*&\s*){6,}|"
                              r"(?:string\.fromcharcode\s*\()", I)),
    ("reversed text", re.compile(r"\[\s*-1\s*\.\.\s*-|strreverse\s*\(|\.reverse\(\)\.join", I)),
    ("format scrambling", re.compile(r"(?:\{\d+\}){4,}['\"]\s*-f\s", I)),
    ("eval", re.compile(r"\beval\s*\(|\bexecute(?:global)?\s*[(\"]|unescape\s*\(", I)),
    ("hex text", re.compile(r"(?:\\x[0-9a-f]{2}){20,}|(?:%u[0-9a-f]{4}){10,}", I)),
    ("cut-up variables", re.compile(r"(?:%\w+:~-?\d+,\d+%.*){5,}", I)),
    ("carets", re.compile(r"\w\^\w\^\w\^\w", I)),
]
# JavaScript (.js) gets its own patterns: web-app bundles are minified (long lines, short names) and use
# RegExp .exec(), String.fromCharCode() and eval() all the time, which says nothing on its own. What counts
# is code that starts programs, and the marks obfuscators leave.
JS_RUNS = re.compile(r"wscript\.shell|shell\.application|shellexecute|child_process|"
                     r"\b(?:eval|Function)\s*\([^)]{0,80}\bresponse(?:text|body)|"
                     # a command line, not just the word (code highlighters list "powershell" as a language)
                     r"\b(?:powershell|pwsh|mshta|rundll32|regsvr32|cscript|wscript)(?:\.exe\b|\s+[-/]\w)|"
                     r"\bcmd(?:\.exe)?\s+/[ck]\b", I)
# Download commands (not the XMLHTTP objects a web page or an old Internet Explorer fallback names).
COMMAND_DOWNLOAD = re.compile(
    r"invoke-webrequest|\biwr\s|\bwget\s+https?:|\bcurl(?:\.exe)?\s+\S*https?:|downloadstring|downloaddata|"
    r"downloadfile|start-bitstransfer|bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s+\S*\s*-urlcache|"
    r"invoke-restmethod|\birm\s+https?:", I)
# Web pages fetch things all the time; for a .js file a download matters when it is saved to disk or run.
JS_SAVES = re.compile(r"adodb\.stream|savetofile|scripting\.filesystemobject|\.writefile(?:sync)?\s*\(|"
                      r"createwritestream\s*\(", I)
JS_OBFUSCATION = [
    ("_0x names", re.compile(r"\b_0x[0-9a-f]{4,}\b(?:.*?\b_0x[0-9a-f]{4,}\b){9}", I)),
    ("packer", re.compile(r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)")),
    ("eval of decoded text", re.compile(r"\b(?:eval|Function)\s*\(\s*(?:window\.)?(?:unescape|atob|decodeURIComponent|"
                                        r"String\.fromCharCode)\s*\(")),
    ("char codes", re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}")),
    ("reversed text", re.compile(r"['\"][^'\"\n]{8,}['\"]\s*\.split\(\s*(?:''|\"\")\s*\)\s*\.reverse\(\s*\)\s*\.join")),
    ("hex text", re.compile(r"(?:\\x[0-9a-f]{2}){20,}", I)),
]
# A big list of strings that is then fed into eval() or Function(): how obfuscators hide the real code.
JS_STRING_ARRAY = re.compile(r"(?:var|let|const)\s+([\w$]+)\s*=\s*\[\s*(?:'[^'\n]*'|\"[^\"\n]*\")"
                             r"(?:\s*,\s*(?:'[^'\n]*'|\"[^\"\n]*\")){49,}\s*\]")


def js_tricks(text: str) -> list[str]:
    """The obfuscation marks in a JavaScript file (not plain minification)."""
    tricks = [name for name, pattern in JS_OBFUSCATION if pattern.search(text)]
    for m in JS_STRING_ARRAY.finditer(text):
        fed = re.compile(r"\b(?:eval|Function)\s*\([^;]{0,200}?(?<![\w$])" + re.escape(m.group(1)) + r"\s*\[")
        if fed.search(text):
            tricks.append("string list fed into eval/Function")
            break
    return tricks


SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "conhost.exe", "forfiles.exe", "msiexec.exe"}


URL_HOST = re.compile(r"\bhttps?://(\[[0-9a-f:.]+\]|[^\s/:'\"`]+)", re.I)
THIS_PC = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _only_this_pc(text: str) -> bool:
    """True when every web address in the script is this PC (a health check, a local server): that isn't
    downloading anything from the internet. Scripts without a visible address still count."""
    hosts = {h.lower().strip("[]") for h in URL_HOST.findall(text)}
    return bool(hosts) and hosts <= THIS_PC


# What counts as code for "downloads and runs": comments are dropped, and so are lists of strings (a
# blocklist like ['curl', 'wget', 'iwr'] names commands, it doesn't run them). Strings stay in place
# otherwise, so a URL or a command inside a string still counts.
_STRINGS = {
    "js": r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`",
    "ps1": r"'(?:''|[^'])*'|\"(?:`.|\"\"|[^\"`])*\"",
    "vbs": r"\"(?:\"\"|[^\"\n])*\"",
}
_COMMENTS = {
    "js": r"/\*.*?\*/|//[^\n]*",
    "ps1": r"<#.*?#>|#[^\n]*",
    "vbs": r"'[^\n]*|(?im:^[ \t]*rem\b[^\n]*)",
    "bat": r"(?im:^[ \t]*@?(?:rem\b|::)[^\n]*)",
}
_LANGUAGE = {"js": "js", "jse": "js", "hta": "js", "wsf": "js", "wsh": "js", "ps1": "ps1", "psm1": "ps1",
             "psd1": "ps1", "vbs": "vbs", "vbe": "vbs", "bat": "bat", "cmd": "bat"}
_ITEM = r"(?:'[^'\n]*'|\"[^\"\n]*\")"
STRING_LIST = re.compile(rf"(?:\[|@\(|\barray\s*\()\s*{_ITEM}(?:\s*,\s*{_ITEM})+\s*,?\s*[\])]|"
                         rf"(?<==)\s*{_ITEM}(?:\s*,\s*{_ITEM}){{2,}}", re.I)
# Code that runs text it gets at run time (from a variable, a list item or a string it builds). If the
# script has any of these outside its lists, a list's strings may be the real command, so the lists count.
# Looked for in the code without its lists, so a blocklist that names 'iex' doesn't count by itself.
_LITERAL = r"(?:'[^'\n]*'|\"[^\"\n]*\")"
_FIXED_ARG = rf"(?:{_LITERAL}|\[\s*(?:{_LITERAL}(?:\s*,\s*{_LITERAL})*)?\s*\])"  # plain text, or a list of it
_PS_VARIABLE = r"[^\n;|]*\$"  # a variable later in the same command
RUNS_TEXT = {
    "ps1": [
        ("Invoke-Expression", re.compile(r"\binvoke-expression\b|\biex\b", re.I)),
        ("Invoke-Command", re.compile(r"\binvoke-command\b|\bicm\b", re.I)),
        ("[scriptblock]::Create", re.compile(r"\[scriptblock\]\s*::\s*create|newscriptblock|\.invokescript\s*\(",
                                             re.I)),
        ("$ExecutionContext", re.compile(r"\$executioncontext\b", re.I)),
        ("Add-Type", re.compile(r"\badd-type\b", re.I)),
        ("a script block's .Invoke()", re.compile(r"\.invoke\s*\(", re.I)),
        ("& (call operator)", re.compile(r"(?<![&\w-])&\s*(?:\$|\()", re.I)),
        (". (dot source)", re.compile(r"(?:^|[\s;|{(=])\.\s+(?:\$|\()|(?<![\w\])}.'\"])\.\s*\(\s*\$", re.I | re.M)),
        ("Start-Process with a variable", re.compile(rf"(?<![\w$.-])(?:start-process|saps|start)\b{_PS_VARIABLE}",
                                                     re.I)),
        ("cmd /c with a variable", re.compile(rf"\bcmd(?:\.exe)?['\"]?\s[^\n;|]*?/[ck]\b{_PS_VARIABLE}", re.I)),
        ("powershell with a variable", re.compile(rf"\b(?:powershell|pwsh)(?:\.exe)?['\"]?\s{_PS_VARIABLE}", re.I)),
    ],
    "js": [
        ("eval", re.compile(r"\beval\s*\(")),
        ("Function()", re.compile(r"\bFunction\s*\(")),
        # child_process (Node) or WScript.Shell (Windows Script Host), called with anything but plain text.
        ("child_process with a variable", re.compile(
            rf"(?s:child_process.*)\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("
            rf"(?!\s*{_FIXED_ARG}(?:\s*,\s*{_FIXED_ARG})*\s*\))")),
        ("WScript.Shell with a variable", re.compile(
            rf"(?is:(?:wscript\.shell|shell\.application).*)\.(?:run|exec|shellexecute)\s*\("
            rf"(?!\s*{_LITERAL}\s*[,)])", re.I)),
    ],
    "vbs": [
        ("Execute / ExecuteGlobal", re.compile(r"(?<!\.)\bexecute(?:global)?\b", re.I)),  # not a RegExp's .Execute
        ("Eval", re.compile(r"\beval\s*\(", re.I)),
        ("WScript.Shell with a variable", re.compile(
            r"\.(?:run|exec|shellexecute)\b(?![ \t]*\(?[ \t]*\"(?:\"\"|[^\"\n])*\"[ \t]*(?:[,)]|$))", re.I | re.M)),
    ],
    "bat": [
        ("a variable run as a command", re.compile(r"(?:^[ \t]*@?|\bdo[ \t]+\(?[ \t]*)(?:call[ \t]+)?[%!][\w~%]",
                                                   re.I | re.M)),
        ("cmd /c with a variable", re.compile(r"\bcmd(?:\.exe)?\s[^\n]*?/[ck]\b[^\n]*[%!][\w~]", re.I)),
        ("start with a variable", re.compile(r"^[ \t]*@?start\b[^\n]*[%!][\w~]", re.I | re.M)),
        ("powershell with a variable", re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\s[^\n]*[%!][\w~]", re.I)),
    ],
}


def runs_text(code: str, lang: str) -> list[str]:
    """The kinds of code in `code` that run text they get at run time (see RUNS_TEXT)."""
    return [name for name, pattern in RUNS_TEXT.get(lang, []) if pattern.search(code)]


def code_only(text: str, kind: str) -> str:
    """The script without its comments, and without plain lists of strings unless the rest of it has code
    that runs text (then a list item can be the command it runs)."""
    lang = _LANGUAGE.get(kind)
    if not lang:
        return text
    strings, comments = _STRINGS.get(lang), _COMMENTS[lang]
    pattern = re.compile(f"({strings})|{comments}" if strings else comments, re.S)
    code = pattern.sub(lambda m: (m.group(1) if strings else None) or " ", text)
    without_lists = STRING_LIST.sub(" ", code)
    return code if runs_text(without_lists, lang) else without_lists


def decode(data: bytes) -> str:
    data = data[:MAX_TEXT]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if data[1:2] == b"\x00" and data[3:4] == b"\x00":
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def analyze_text(check, text, kind, scope=None, where="It") -> list[Finding]:
    """`kind` is the file ending (ps1, bat, ...) or 'lnk' for a shortcut's command line."""
    s = {"scope": scope} if scope else {}
    out = []
    code = code_only(text, kind)
    js = kind == "js"
    downloads = bool(DOWNLOAD.search(code)) and not _only_this_pc(code)
    runs = bool((JS_RUNS if js else EXECUTE).search(code))
    if js and not runs:
        # Lists still in `code` reach code that runs text (code_only): a command in one of them is what runs.
        listed = " ".join(m.group(0) for m in STRING_LIST.finditer(code))
        runs = bool(listed and (EXECUTE.search(listed) or COMMAND_DOWNLOAD.search(listed)))
    if js and downloads and not runs:
        downloads = bool(JS_SAVES.search(code))
    if downloads and runs:
        out.append(risky(check, "download-run",
            f"{where} downloads something from the internet and runs it. Installers and setup scripts do that "
            "too, but it is the most common way script malware works.", s))
    elif downloads:
        out.append(risky(check, "download",
            f"{where} downloads files from the internet. Update scripts do that too.", s))
    if ENCODED_COMMAND.search(text):
        out.append(hiding(check, "encoded-command",
            f"{where} runs an encoded PowerShell command, so you can't read what it does. "
            "Legitimate scripts rarely need that; malware does it to hide.", s))
    elif BASE64_BLOB.search(text) and (runs or "eval of decoded text" in js_tricks(text) if js else
                                        FROM_BASE64.search(text) or runs):
        out.append(hiding(check, "encoded-blob",
            f"{where} carries a long block of encoded text (base64) and decodes or runs it. Some installers "
            "embed files like that, but it is also how malware hides its real code.", s))
    if HIDDEN_WINDOW.search(text):
        out.append(hiding(check, "hidden-window",
            f"{where} runs with its window hidden, so you wouldn't see it working.", s))
    tricks = js_tricks(text) if js else [name for name, pattern in OBFUSCATION if pattern.search(text)]
    if tricks:
        out.append(hiding(check, "obfuscation",
            f"{where} is scrambled ({', '.join(tricks)}) so it's hard to read. Some tools do that to protect "
            "their code, but it is a classic way to slip past antivirus.", {**s, "tricks": tricks}))
    if DEFENDER.search(text):
        out.append(risky(check, "defender-tamper",
            f"{where} tries to switch off, blind or add exceptions to Microsoft Defender. "
            "\"Game booster\" scripts sometimes do that too, but so does malware.", s, hiding=True))
    if PERSIST.search(text):
        out.append(risky(check, "persistence",
            f"{where} sets something up to start automatically with Windows (a scheduled task, service or "
            "Run key). Launchers and updaters do that too, but so does malware that wants to stay.", s))
    if BACKUPS.search(text):
        out.append(risky(check, "delete-backups",
            f"{where} deletes Windows' backup copies (shadow copies or recovery). Ransomware does that "
            "before it locks your files.", s, hiding=True))
    if CREDENTIALS.search(text):
        out.append(risky(check, "credentials",
            f"{where} reaches for saved passwords or browser logins. Password tools do that too, but it is "
            "what password stealers do.", s))
    if kind == "hta":
        out.append(risky(check, "hta",
            "It is an HTML application (HTA): it looks like a web page but runs with full access to your "
            "PC. Very few legitimate programs still use them.", s))
    if kind in ("vbe", "jse") or text.lstrip().startswith("#@~^"):
        out.append(hiding(check, "encoded-script",
            f"{where} is an encoded script, scrambled so people can't read it.", s))
    return out


def _ansi(raw: bytes) -> str:
    try:
        return raw.decode("mbcs", "replace")  # Windows' own code page
    except LookupError:
        return raw.decode("latin-1")


def parse_lnk(data: bytes) -> dict:
    """The parts of a Windows shortcut that matter: what it starts and with which arguments."""
    if len(data) < 0x4C or data[:4] != b"L\x00\x00\x00":
        raise ValueError("not a shortcut")
    flags = struct.unpack_from("<I", data, 0x14)[0]
    show = struct.unpack_from("<I", data, 0x3C)[0]
    pos = 0x4C
    target = ""
    if flags & 0x1:  # HasLinkTargetIDList
        size = struct.unpack_from("<H", data, pos)[0]
        idlist = data[pos + 2:pos + 2 + size]
        found = re.findall(rb"[\w\\ :.\-()]{3,}\.(?:exe|com|bat|cmd|ps1|vbs|js|hta|dll|scr)", idlist, re.I)
        found += [m.decode("utf-16-le", "replace").encode() for m in
                  re.findall(rb"(?:[\w\\ :.\-()]\x00){3,}\.\x00(?:e\x00x\x00e\x00|c\x00m\x00d\x00|"
                             rb"b\x00a\x00t\x00|h\x00t\x00a\x00|s\x00c\x00r\x00)", idlist, re.I)]
        if found:
            target = found[-1].decode("latin-1")
        pos += 2 + size
    if flags & 0x2:  # HasLinkInfo
        size, header_size, info_flags = struct.unpack_from("<III", data, pos)
        if info_flags & 1 and pos + 20 <= len(data):
            base_offset = struct.unpack_from("<I", data, pos + 16)[0]
            end = data.find(b"\x00", pos + base_offset)
            local = _ansi(data[pos + base_offset:end])
            if local:
                target = local
        pos += size
    unicode = bool(flags & 0x80)
    strings = {}
    for bit, key in ((0x4, "name"), (0x8, "relative_path"), (0x10, "working_dir"),
                     (0x20, "arguments"), (0x40, "icon")):
        if flags & bit and pos + 2 <= len(data):
            count = struct.unpack_from("<H", data, pos)[0]
            width = 2 if unicode else 1
            raw = data[pos + 2:pos + 2 + count * width]
            strings[key] = raw.decode("utf-16-le", "replace") if unicode else _ansi(raw)
            pos += 2 + count * width
    if not target:
        target = strings.get("relative_path", "")
    return {"target": target, "arguments": strings.get("arguments", ""), "icon": strings.get("icon", ""),
            "name": strings.get("name", ""), "minimized": show == 7}


def analyze_lnk(check, data: bytes, scope=None) -> list[Finding]:
    s = {"scope": scope} if scope else {}
    try:
        lnk = parse_lnk(data)
    except (ValueError, struct.error):
        return [Finding(check, NOTE, "It claims to be a Windows shortcut but Blotter couldn't read it.", s)]
    exe = re.split(r"[\\/]", lnk["target"])[-1].lower()
    args = lnk["arguments"]
    out = []
    if exe in SHELLS and args.strip():
        shown = (args.strip()[:160] + "…") if len(args.strip()) > 160 else args.strip()
        out.append(risky(check, "lnk-command",
            f"This shortcut starts {exe} with a command ({shown}) instead of just opening a program or "
            "document. Some program shortcuts do that, but shortcuts that start PowerShell or cmd are a "
            "common malware trick in downloads.", {**s, **lnk}))
        if lnk["minimized"]:
            out.append(hiding(check, "hidden-window", "The shortcut starts it minimised, out of sight.", s))
    if len(args) > 1000 or re.search(r"\s{50,}", args):
        out.append(hiding(check, "padded-arguments",
            "The shortcut's command is padded or very long, which hides it in the Properties window.", s))
    out += analyze_text(check, args, "lnk", scope, where="Its command")
    return out
