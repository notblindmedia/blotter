"""The 0.9.0 code review's fixes: files inside archives (H1), containers Blotter can't open
(H2), Defender switched off by another antivirus (H3), HTML smuggling, a PDF header after junk, online answers that
expire, and Blotter's icon."""

import base64
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, hashing, shortcut, worker
from blotter.analyze import filetype
from blotter.cache import Cache
from blotter.checks import archive, capabilities, defender, pdf, scripts, signature
from blotter.checks import program as program_check
from blotter.findings import CLEAR, NOTE, PACKED, SIGNED, UNCHECKED, UNSIGNED, Finding
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

    def test_a_valid_signature_takes_the_unchecked_back(self):
        trusted = Finding("archive", CLEAR, "signed", {"scope": "tool.exe", "trusted_publisher": "Microsoft"}, [SIGNED])
        other = Finding("archive", CLEAR, "signed", {"scope": "tool.exe", "signed_by": "Someone"}, [SIGNED])
        unsigned = Finding("archive", NOTE, "unsigned", {"scope": "tool.exe"}, [UNSIGNED])
        self.assertEqual(decide(self.capa_skipped() + [trusted, ENGINE_RAN])["verdict"], "no_known_detections")
        self.assertEqual(decide(self.capa_skipped() + [other, ENGINE_RAN])["verdict"], "no_known_detections")
        self.assertEqual(decide(self.capa_skipped() + [unsigned, ENGINE_RAN])["verdict"], "couldnt_fully_check")

    def test_another_files_signature_doesnt_count(self):
        signed = Finding("archive", CLEAR, "signed", {"scope": "other.exe", "signed_by": "Someone"}, [SIGNED])
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


if __name__ == "__main__":
    unittest.main()
