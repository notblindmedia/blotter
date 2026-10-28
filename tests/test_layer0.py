"""Layer 0: the real file type, lying names, and archives (zip, rar, 7z, password, zip bombs)."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import py7zr

from blotter import config, hashing
from blotter.analyze import filetype as ft
from blotter.checks import archive, filetype
from blotter.findings import CLEAR, DISGUISED, HIDING, LYING_NAME, NOTE, SKIPPED, UNCHECKED
from tests import samples


def write(data: bytes, name="sample.blotter") -> Path:
    path = Path(tempfile.mkdtemp()) / name
    path.write_bytes(data)
    return path


def scan_named(check, data, name):
    path = write(data)
    hashing.remember(path, "0" * 64, name)
    try:
        return check.scan(path)
    finally:
        hashing.forget(path)


class DetectTests(unittest.TestCase):
    def test_magic_bytes(self):
        cases = {
            samples.minimal_pe(): ("program", "pe"),
            samples.minimal_pe(dll=True): ("program", "pe"),
            b"%PDF-1.7\n": ("document", "pdf"),
            b"\x89PNG\r\n\x1a\n" + bytes(20): ("image", "png"),
            b"Rar!\x1a\x07\x00" + bytes(20): ("archive", "rar"),
            b"7z\xbc\xaf\x27\x1c" + bytes(20): ("archive", "7z"),
            samples.lnk(): ("shortcut", "lnk"),
            samples.zip_of({"a.txt": "hi"}): ("archive", "zip"),
            samples.docm(): ("document", "ooxml"),
            b"Write-Host hello\r\n": ("text", "text"),
            bytes(range(256)) * 4: ("unknown", "unknown"),
        }
        for data, (kind, real) in cases.items():
            got = ft.detect(write(data))
            self.assertEqual((got.kind, got.real), (kind, real), got.label)

    def test_dll_label_and_macros_flag(self):
        self.assertIn("DLL", ft.detect(write(samples.minimal_pe(dll=True))).label)
        self.assertTrue(ft.detect(write(samples.docm())).detail["macros"])


class NameTests(unittest.TestCase):
    def test_double_extension(self):
        found = scan_named(filetype, samples.minimal_pe(), "invoice.pdf.exe")
        self.assertTrue(any(DISGUISED in f.signals for f in found))
        self.assertIn(".pdf.exe", found[0].text)

    def test_program_named_as_document(self):
        found = scan_named(filetype, samples.minimal_pe(), "holiday-photo.jpg")
        self.assertEqual(found[0].level, NOTE)
        self.assertEqual(set(found[0].signals), {DISGUISED, LYING_NAME})
        self.assertIn("really a Windows program", found[0].text)

    def test_hidden_flip_character(self):
        found = scan_named(filetype, samples.minimal_pe(), "invoice‮fdp.exe")
        self.assertTrue(any(HIDING in f.signals and DISGUISED in f.signals for f in found))
        self.assertIn("[U+202E]", found[0].text, "the card must not flip the text itself")

    def test_spaces_push_the_ending_away(self):
        found = scan_named(filetype, samples.minimal_pe(), "report.pdf" + " " * 40 + ".exe")
        self.assertTrue(any(f.details.get("ability") == "name-trick" for f in found))

    def test_harmless_mismatch_is_only_a_note(self):
        found = scan_named(filetype, b"\x89PNG\r\n\x1a\n" + bytes(40), "picture.jpg")
        self.assertEqual(found[0].signals, [LYING_NAME])
        self.assertNotIn(DISGUISED, found[0].signals)

    def test_honest_names(self):
        for data, name in [(samples.minimal_pe(), "setup.v1.2.exe"), (samples.docm(), "report.docm"),
                           (b"%PDF-1.4", "a.pdf"), (samples.zip_of({"x": "y"}), "mod.zip"),
                           (b"echo hi\r\n", "run.bat"), (samples.zip_of({"x": "y"}), "plugin.jar")]:
            found = scan_named(filetype, data, name)
            self.assertEqual([f.level for f in found], [CLEAR], name)

    def test_no_name_known(self):
        found = filetype.scan(write(samples.minimal_pe()))
        self.assertEqual(found[0].level, CLEAR)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        config.INCOMING.mkdir(parents=True, exist_ok=True)

    def scan(self, data):
        return archive.scan(write(data))

    def test_not_an_archive(self):
        self.assertEqual(self.scan(b"%PDF-1.4")[0].level, SKIPPED)

    def test_disguised_program_inside(self):
        found = self.scan(samples.zip_of({"docs/invoice.pdf.exe": samples.minimal_pe(), "readme.txt": "hi"}))
        inside = [f for f in found if DISGUISED in f.signals]
        self.assertTrue(inside)
        self.assertTrue(inside[0].text.startswith("Inside the archive, docs/invoice.pdf.exe:"))
        self.assertEqual(inside[0].details["scope"], "docs/invoice.pdf.exe")
        self.assertIn("2 files", found[-1].text)

    def test_nothing_unusual(self):
        found = self.scan(samples.zip_of({"a.txt": "hello", "b/c.txt": "world"}))
        self.assertEqual([f.level for f in found], [CLEAR])
        self.assertIn("2 files", found[0].text)

    def test_nested_archives_and_depth_limit(self):
        inner = samples.zip_of({"deep/run.pdf.exe": samples.minimal_pe()})
        found = self.scan(samples.zip_of({"inner.zip": inner}))
        self.assertTrue(any(f.details.get("scope") == "inner.zip/deep/run.pdf.exe" for f in found))
        nested = samples.zip_of({"x.txt": "x"})
        for i in range(config.ARCHIVE_MAX_DEPTH + 1):
            nested = samples.zip_of({f"level{i}.zip": nested})
        found = self.scan(nested)
        self.assertTrue(any(UNCHECKED in f.signals and "nested" in f.text for f in found))

    def test_password_infected_works(self):
        found = self.scan(samples.zip_locked("tool.pdf.exe", samples.minimal_pe()))
        self.assertTrue(any(DISGUISED in f.signals for f in found), "should have unpacked with 'infected'")

    def test_other_password_cant_be_checked(self):
        found = self.scan(samples.zip_locked("tool.exe", samples.minimal_pe(), password=b"hunter2"))
        locked = [f for f in found if UNCHECKED in f.signals]
        self.assertTrue(locked)
        self.assertIn("password", locked[0].text)

    def test_zip_bomb_ratio(self):
        found = self.scan(samples.zip_of({"zeros.bin": bytes(8 * 1024 * 1024)}))
        self.assertTrue(any(UNCHECKED in f.signals and "zip bomb" in f.text for f in found))

    def test_total_size_and_member_limits(self):
        with mock.patch.object(config, "ARCHIVE_MAX_TOTAL", 1000):
            found = self.scan(samples.zip_of({"a.bin": bytes(range(256)) * 8}, compress=0))
        self.assertTrue(any(UNCHECKED in f.signals and "MB" in f.text for f in found))
        with mock.patch.object(config, "ARCHIVE_MAX_MEMBERS", 3):
            found = self.scan(samples.zip_of({f"{i}.txt": "x" for i in range(5)}))
        self.assertTrue(any(UNCHECKED in f.signals and "more than 3 files" in f.text for f in found))

    def test_7z_plain_and_locked(self):
        for password in (None, "infected"):
            path = Path(tempfile.mkdtemp()) / "a.7z"
            with py7zr.SevenZipFile(path, "w", password=password) as z:
                z.writestr(samples.minimal_pe(), "game/trainer.mp4.exe")
                z.writestr(b"hello", "notes.txt")
            found = archive.scan(path)
            self.assertTrue(any(DISGUISED in f.signals for f in found), password)

    def test_7z_wrong_password(self):
        path = Path(tempfile.mkdtemp()) / "a.7z"
        with py7zr.SevenZipFile(path, "w", password="other") as z:
            z.writestr(b"hello", "notes.txt")
        found = archive.scan(path)
        self.assertTrue(any(UNCHECKED in f.signals for f in found))

    def test_rar(self):
        found = self.scan(samples.rar_stored("cheat.jpg.exe", samples.minimal_pe()))
        self.assertTrue(any(DISGUISED in f.signals for f in found), [f.text for f in found])

    def test_unpacked_files_are_cleaned_up(self):
        self.scan(samples.zip_of({"a.txt": "x"}))
        self.assertEqual(list(config.INCOMING.glob("unpack-*")), [])

    def test_documents_and_scripts_inside_are_checked(self):
        # Mild samples only: these land on disk, and Defender shouldn't be bothered by a test run.
        found = self.scan(samples.zip_of({"report.docm": samples.docm(),
                                          "go.ps1": b"Start-Process notepad.exe -WindowStyle Hidden\r\n",
                                          "start.lnk": samples.lnk(arguments="-NoProfile -Command Get-Date")}))
        scopes = {f.details.get("scope") for f in found}
        self.assertTrue({"report.docm", "go.ps1", "start.lnk"} <= scopes, scopes)


if __name__ == "__main__":
    unittest.main()
