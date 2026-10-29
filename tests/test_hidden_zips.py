"""Zips hidden in other files: glued after a picture or a PDF, two zips back to back, after a program, and a zip whose
start was overwritten (round 2's head512). All built in memory from harmless pieces."""

import random
import unittest

from blotter import config
from blotter.analyze import archives
from blotter.checks import archive
from blotter.findings import CLEAR, DISGUISED, HIDING, SKIPPED, UNCHECKED, Finding
from blotter.verdict import decide
from tests import samples
from tests.test_layer0 import write

# Just the start and end markers of a JPEG and a tiny PDF: enough for Blotter's type check, nothing to show.
JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + random.Random(7).randbytes(3000) + b"\xff\xd9"
PDF = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> "
       b"endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")
DISGUISED_PROGRAM = {"holiday.jpg.exe": samples.minimal_pe(), "readme.txt": b"hello"}


def verdict(found):
    return decide([Finding("filetype", CLEAR, "A file."), *found])["verdict"]


class HiddenZipTests(unittest.TestCase):
    def setUp(self):
        config.INCOMING.mkdir(parents=True, exist_ok=True)

    def scan(self, data):
        return archive.scan(write(data))

    def assertHidden(self, found, after):
        notes = [f for f in found if f.details.get("hidden_zip")]
        self.assertTrue(notes, [f.text for f in found])
        self.assertIn(after, notes[0].text)
        self.assertIn(HIDING, notes[0].signals)
        self.assertTrue(any(DISGUISED in f.signals for f in found))  # what was inside got checked

    def test_zip_after_a_picture(self):
        found = self.scan(JPG + samples.zip_of(DISGUISED_PROGRAM))
        self.assertHidden(found, "hidden after a JPEG picture")
        self.assertIn("byte 3,022", found[0].text + " ".join(f.text for f in found))
        self.assertEqual(verdict(found), "suspicious")
        self.assertIn("2 files", found[-1].text)

    def test_zip_appended_with_offsets_counted_from_the_start_of_the_file(self):
        path = write(JPG)
        with samples.zipfile.ZipFile(path, "a") as z:  # appending to a picture: offsets include the picture
            for name, data in DISGUISED_PROGRAM.items():
                z.writestr(name, data)
        found = archive.scan(path)
        self.assertHidden(found, f"hidden after a JPEG picture (from byte {len(JPG):,})")
        self.assertEqual(verdict(found), "suspicious")

    def test_zip_after_a_pdf(self):
        found = self.scan(PDF + samples.zip_of(DISGUISED_PROGRAM))
        self.assertHidden(found, "hidden after a PDF")
        self.assertEqual(verdict(found), "suspicious")

    def test_two_zips_back_to_back(self):
        first = samples.zip_of({"a.txt": b"first zip"})
        found = self.scan(first + samples.zip_of(DISGUISED_PROGRAM))
        self.assertHidden(found, "hidden after another zip")
        self.assertIn("3 files", found[-1].text)  # a.txt from the first, both files from the second
        self.assertEqual(verdict(found), "suspicious")

    def test_the_first_of_two_zips_is_not_lost_either(self):
        found = self.scan(samples.zip_of(DISGUISED_PROGRAM) + samples.zip_of({"a.txt": b"second zip"}))
        self.assertTrue(any(DISGUISED in f.signals for f in found))
        self.assertIn("3 files", found[-1].text)

    def test_zip_whose_start_was_overwritten(self):
        """Round 2's head512: the first 512 bytes random. The first file's header is gone, its directory isn't."""
        noise = random.Random(10).randbytes
        data = samples.zip_of({"tool.exe": samples.minimal_pe() + noise(4000), "b.txt": noise(3000)})
        broken = random.Random(8).randbytes(512) + data[512:]
        found = self.scan(broken)
        self.assertNotEqual(found[0].level, SKIPPED)
        self.assertEqual(verdict(found), "couldnt_fully_check")
        one_file = samples.zip_of({"tool.exe": samples.minimal_pe() + noise(4000)})
        self.assertEqual(verdict(self.scan(random.Random(9).randbytes(512) + one_file[512:])), "couldnt_fully_check")

    def test_picture_with_a_cut_off_zip(self):
        data = samples.zip_of({"holiday.jpg.exe": samples.minimal_pe(), "big.bin": random.Random(3).randbytes(50_000)})
        found = self.scan(JPG + data[:len(data) - 2000])  # no end record left: found by its file headers
        self.assertTrue(any(DISGUISED in f.signals for f in found))
        self.assertTrue(any(UNCHECKED in f.signals for f in found))
        self.assertEqual(verdict(found), "suspicious")

    def test_a_clean_zip_after_a_picture_pdf_or_document_is_unusual(self):
        """The Doctor, after round 2's N1: the headline should say a picture, PDF or document carries files."""
        clean = samples.zip_of({"notes.txt": b"just text"})
        ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(1016)  # an older Word file's start
        rtf = b"{\\rtf1\\ansi Hello.}"
        for name, carrier in (("jpg", JPG), ("pdf", PDF), ("doc", ole), ("rtf", rtf)):
            found = self.scan(carrier + clean)
            self.assertTrue([f for f in found if f.details.get("hidden_zip")], name)
            v = decide([Finding("filetype", CLEAR, "A file."), *found])
            self.assertEqual(v["verdict"], "unusual", name)
            self.assertTrue(v["summary"].startswith("This file has a zip archive hidden after it"), name)
            self.assertNotIn("nothing hides it", v["summary"], name)

    def test_inside_an_archive_the_picture_counts_too(self):
        outer = samples.zip_of({"holiday/photo.jpg": JPG + samples.zip_of({"notes.txt": b"just text"})})
        self.assertEqual(verdict(self.scan(outer)), "unusual")

    def test_what_is_in_the_hidden_zip_still_wins(self):
        found = self.scan(JPG + samples.zip_of(DISGUISED_PROGRAM))
        self.assertEqual(verdict(found), "suspicious")
        detected = Finding("clamav", "malicious", "ClamAV recognises it.", {"engine": "ClamAV", "threat": "Test.Thing"})
        self.assertEqual(verdict([*self.scan(PDF + samples.zip_of({"a.txt": b"x"})), detected]), "malicious")

    def test_a_clean_zip_after_another_zip_stays_no_known(self):
        """Not decided yet: zip + zip keeps its note but doesn't raise the answer."""
        found = self.scan(samples.zip_of({"a.txt": b"first"}) + samples.zip_of({"b.txt": b"second"}))
        self.assertTrue([f for f in found if f.details.get("hidden_zip")])
        self.assertEqual(verdict(found), "no_known_detections")

    def test_zip_after_a_program_is_an_ordinary_note(self):
        found = self.scan(samples.minimal_pe() + samples.zip_of({"readme.txt": b"setup files"}))
        notes = [f for f in found if f.details.get("hidden_zip")]
        self.assertIn("Self-extracting installers do that", notes[0].text)
        self.assertNotIn(HIDING, notes[0].signals)
        self.assertEqual(verdict(found), "no_known_detections")

    def test_pieces_of_zips_after_a_program_are_left_alone(self):
        """The Python installer keeps a pip wheel's pieces in its appended data; only whole zips count there."""
        piece = samples.zip_of({"pip/t64.exe": random.Random(4).randbytes(20_000)})
        self.assertEqual(self.scan(samples.minimal_pe() + piece[:-3000])[0].level, SKIPPED)

    def test_zips_inside_a_programs_own_code_are_left_alone(self):
        """Programs keep zips in their resources (installers, .NET); only what is appended after a program counts."""
        pe = samples.pe_with_section(64 * 1024)
        resource = samples.zip_of({"payload.txt": b"x"})
        inside = pe[:0x400 + 1000] + resource + pe[0x400 + 1000 + len(resource):]
        self.assertEqual(len(inside), len(pe))
        self.assertEqual(self.scan(inside)[0].level, SKIPPED)

    def test_files_without_zip_data(self):
        for data in (JPG, PDF, samples.minimal_pe(), b"Some text that mentions PK\x03\x04 in passing. " * 3, random.Random(5).randbytes(9000)):
            self.assertEqual(self.scan(data)[0].level, SKIPPED, data[:12])

    def test_a_docx_is_still_left_to_the_office_check(self):
        self.assertEqual(self.scan(samples.docm())[0].level, SKIPPED)

    def test_a_docx_with_a_zip_glued_on(self):
        found = self.scan(samples.docm() + samples.zip_of(DISGUISED_PROGRAM))
        self.assertTrue(any(f.details.get("hidden_zip") for f in found))
        self.assertEqual(verdict(found), "suspicious")

    def test_a_zip_stored_inside_a_zip_is_one_zip(self):
        inner = samples.zip_of({"deep/run.pdf.exe": samples.minimal_pe()})
        outer = samples.zip_of({"inner.zip": inner, "a.txt": b"x"}, compress=samples.zipfile.ZIP_STORED)
        self.assertEqual(archives.zip_segments(write(outer)), [(0, len(outer))])
        found = self.scan(outer)
        self.assertFalse(any(f.details.get("hidden_zip") for f in found))
        self.assertTrue(any(DISGUISED in f.signals for f in found))

    def test_hidden_zip_inside_an_archive(self):
        found = self.scan(samples.zip_of({"photos/cat.jpg": JPG + samples.zip_of(DISGUISED_PROGRAM)}))
        notes = [f for f in found if f.details.get("hidden_zip")]
        self.assertTrue(notes[0].text.startswith("Inside the archive, photos/cat.jpg has a zip archive hidden"))
        self.assertEqual(verdict(found), "suspicious")

    def test_segments(self):
        a, b = samples.zip_of({"a.txt": b"1"}), samples.zip_of({"b.txt": b"2"})
        self.assertEqual(archives.zip_segments(write(JPG + a)), [(len(JPG), len(JPG) + len(a))])
        self.assertEqual(archives.zip_segments(write(a + b)), [(0, len(a)), (len(a), len(a) + len(b))])
        self.assertEqual(archives.zip_segments(write(a + JPG)), [(0, len(a))])


if __name__ == "__main__":
    unittest.main()
