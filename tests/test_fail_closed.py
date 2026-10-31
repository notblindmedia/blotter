"""Fail closed (round 2's H1-H3): a check made for a file's kind that fails can never leave "No known detections".
Also the lenient zip reader for archives with a broken table of contents, and the RTF check (embedded objects)."""

import binascii
import hashlib
import random
import struct
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

from blotter import config
from blotter.analyze import archives, rtf
from blotter.checks import archive, capabilities, macros
from blotter.checks import rtf as rtf_check
from blotter.findings import (CLEAR, DISGUISED, ERROR, MALICIOUS, NOTE, SIGNED, SUSPICIOUS, UNCHECKED, UNSIGNED,
                              Finding, risky)
from blotter.verdict import FILE_READERS, decide
from tests import samples
from tests.test_layer0 import write

ROJO = Path.home() / "Downloads" / "rojo-7.7.1-windows-x86_64.zip"  # the report's source zip
REPORT_RTFS = [Path(p) for p in (
    r"C:\Windows\System32\Licenses\neutral\OEM\Professional\de-license.rtf",
    r"C:\Windows\System32\oobe\info\default\ILA_ko-KR.rtf",
    r"C:\Windows\System32\oobe\info\default\ILA_nb-NO.rtf",
    r"C:\Windows\SysWOW64\en-US\Licenses\_Default\Professional\license.rtf",
)]


def clear(check="filetype", text="It is a file."):
    return Finding(check, CLEAR, text)


def cut1(data: bytes) -> bytes:
    """The report's 'last byte cut off'."""
    return data[:-1]


def cdoffset(data: bytes) -> bytes:
    """The report's 'central directory offset points past the end'."""
    b = bytearray(data)
    struct.pack_into("<I", b, data.rfind(b"PK\x05\x06") + 16, 0x7FFFFFF0)
    return bytes(b)


class Unseekable(BytesIO):
    """zipfile writes 'data descriptors' after each file when it can't go back and fill in the sizes."""

    def seekable(self):
        return False

    def seek(self, *a):
        raise OSError("not seekable")

    def tell(self):
        raise OSError("not seekable")


class FailClosedTests(unittest.TestCase):
    """The scorer rule, one test per round-2 high finding, plus what may still outrank it."""

    def assertNotClean(self, findings, why):
        v = decide(findings)
        self.assertEqual(v["verdict"], "couldnt_fully_check", v)
        self.assertIn(why, " ".join(v["reasons"]))
        return v

    def test_h1_archive_that_cant_be_unpacked(self):
        failed = Finding("archive", ERROR, "Blotter couldn't unpack this archive (BadZipFile).")
        self.assertNotClean([clear(), failed], "couldn't unpack this archive")

    def test_h2_capa_couldnt_analyse_an_unsigned_program(self):
        failed = Finding("capa", ERROR, "capa couldn't analyse this program (MemoryError).")
        self.assertNotClean([clear(), Finding("signature", NOTE, "Not signed.", {}, [UNSIGNED]), failed],
                            "capa couldn't analyse")

    def test_h2_capa_failure_on_a_well_known_publishers_program_is_not_hidden_either(self):
        """Not "No known detections": since N7 its own answer, the same however capa failed."""
        signed = Finding("signature", NOTE, "Signed by Google LLC.", {"trusted_publisher": "Google LLC"}, [SIGNED])
        failed = Finding("capa", ERROR, "capa couldn't analyse this program (exit code 1).")
        v = decide([clear(), signed, failed])
        self.assertEqual(v["title"], "Signed by Google LLC, deep check couldn't finish")
        self.assertIn("capa couldn't analyse", " ".join(v["reasons"]))

    def test_h3_office_document_that_cant_be_read(self):
        failed = Finding("macros", ERROR, "Blotter couldn't read the document's parts (FileOpenError).")
        self.assertNotClean([clear(), failed], "document's parts")

    def test_rtf_and_pdf_readers_too(self):
        self.assertNotClean([clear(), Finding("rtf", ERROR, "Blotter couldn't read the RTF file's structure (X).")],
                            "RTF file's structure")
        self.assertNotClean([clear(), Finding("pdf", ERROR, "PDF check failed unexpectedly (ValueError).")],
                            "PDF check failed")
        self.assertTrue({"archive", "capa", "macros", "rtf", "pdf"} <= FILE_READERS)

    def test_the_failure_is_listed_before_what_ran_fine(self):
        v = decide([clear(), Finding("capa", ERROR, "capa couldn't analyse this program (MemoryError).")])
        self.assertEqual(v["reasons"][0], "capa couldn't analyse this program (MemoryError).")
        self.assertIn("a check couldn't read it", v["summary"])

    def test_something_worse_still_wins(self):
        failed = Finding("archive", ERROR, "Blotter couldn't unpack this archive (BadZipFile).")
        self.assertEqual(decide([failed, Finding("clamav", MALICIOUS, "ClamAV: Win.Trojan.X")])["verdict"], "malicious")
        self.assertEqual(decide([failed, Finding("virustotal", SUSPICIOUS, "2 engines")])["verdict"], "suspicious")
        hiding = risky("scripts", "download-run", "Downloads and runs.", hiding=True)
        self.assertEqual(decide([failed, hiding])["verdict"], "suspicious")

    def test_it_outranks_unusual(self):
        failed = Finding("macros", ERROR, "Blotter couldn't read the document's parts (ValueError).")
        self.assertEqual(decide([failed, risky("capa", "inject", "It can inject code.")])["verdict"],
                         "couldnt_fully_check")

    def test_a_trusted_file_still_says_couldnt_fully_check(self):
        failed = Finding("capa", ERROR, "capa couldn't analyse this program (MemoryError).")
        self.assertEqual(decide([clear(), failed], trusted=True)["verdict"], "couldnt_fully_check")

    def test_online_lookups_keep_their_errors_as_notes(self):
        for check in ("virustotal", "malwarebazaar", "hashlookup"):
            v = decide([clear(), Finding(check, ERROR, "Couldn't be reached.")])
            self.assertEqual(v["verdict"], "no_known_detections", check)

    def test_one_antivirus_engine_failing_while_the_other_scans_stays_a_note(self):
        scanned = {"defender": Finding("defender", CLEAR, "Defender found nothing."),
                   "clamav": Finding("clamav", CLEAR, "ClamAV found nothing.")}
        for failed, other in (("defender", "clamav"), ("clamav", "defender")):
            v = decide([clear(), Finding(failed, ERROR, "It couldn't scan it."), scanned[other]])
            self.assertEqual(v["verdict"], "no_known_detections", failed)

    def test_both_antivirus_engines_failing_is_couldnt_fully_check(self):
        v = decide([clear(), Finding("defender", ERROR, "Defender couldn't scan the file."),
                    Finding("clamav", ERROR, "ClamAV wasn't ready (it isn't running).")])
        self.assertEqual(v["verdict"], "couldnt_fully_check")
        self.assertIn("ClamAV wasn't ready (it isn't running).", v["reasons"][:2])

    def test_in_test_mode_clamav_failing_alone_is_couldnt_fully_check(self):
        # --test-mode leaves the Defender check out, so ClamAV is the only engine.
        v = decide([clear(), Finding("clamav", ERROR, "ClamAV wasn't ready (it isn't running).")])
        self.assertEqual(v["verdict"], "couldnt_fully_check")

    def test_clamav_turned_off_and_defender_failing_means_no_engine_scanned(self):
        v = decide([clear(), Finding("clamav", "skipped", "ClamAV is turned off in Settings."),
                    Finding("defender", ERROR, "Defender couldn't scan the file.")])
        self.assertEqual(v["verdict"], "couldnt_fully_check")
        off = decide([clear(), Finding("clamav", "skipped", "ClamAV is turned off in Settings.")])
        self.assertEqual(off["verdict"], "no_known_detections")  # nothing failed: switched off, as before

    def test_yara_failing_is_couldnt_fully_check(self):
        v = decide([clear(), Finding("yara", ERROR, "No YARA rules are installed yet (run Update rules in Settings).")])
        self.assertEqual(v["verdict"], "couldnt_fully_check")

    def test_yara_failing_on_a_file_inside_an_archive(self):
        with mock.patch.object(archive.yararules, "load", return_value=object()), \
                mock.patch.object(archive.yararules, "scan_target", side_effect=RuntimeError("rules broke")):
            found = archive.scan(write(samples.zip_of({"a.txt": b"hello"})))
        self.assertIn("Inside the archive, a.txt: YARA couldn't scan it (RuntimeError).", [f.text for f in found])
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_nothing_ran_is_still_couldnt_check(self):
        self.assertEqual(decide([Finding("archive", ERROR, "x."), Finding("capa", ERROR, "y.")])["verdict"],
                         "couldnt_check")

    def capa(self, stderr, code=1):
        path = write(samples.minimal_pe())
        with mock.patch.object(capabilities.procs, "run", return_value=(code, b"", stderr)), \
                mock.patch.object(capabilities.config, "CAPA_RULES", Path(__file__).parent):
            return capabilities.scan(path)

    def test_h2_end_to_end_capa_crash_names_the_real_error(self):
        found = self.capa(b"WARNING capa.rules: skipping non-.yml file README.md\nTraceback (most recent call last):\n"
                          b"  File \"capa\\main.py\", line 1\n    run()\nvivisect.exc.InvalidAddress: 0x401000\n\n"
                          b"   -------------------------\nPlease also report your issue on the capa GitHub page\n")
        self.assertEqual(found[0].text, "capa couldn't analyse this program (vivisect.exc.InvalidAddress: 0x401000).")
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_h2_capa_out_of_memory_is_a_limit(self):
        """Round 2's MemoryError and this PC's Once Human DLLs: capa hit Blotter's memory limit (seen 2026-10-29)."""
        rust = b"WARNING  capa.rules: skipping non-.yml file: .version\nmemory allocation of 170800 bytes failed\n" \
               b"note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"
        for stderr, code in ((rust, 0xC0000409), (b"Traceback (most recent call last):\n  File x\nMemoryError\n", 1)):
            found = self.capa(stderr, code)
            self.assertIn("GB of memory", found[0].text)
            self.assertEqual(decide([clear(), Finding("signature", NOTE, "Not signed.", {}, [UNSIGNED]), *found])
                             ["verdict"], "couldnt_fully_check")
            signed = Finding("signature", NOTE, "Signed.", {"trusted_publisher": "NetEase (Hangzhou) Network Co., Ltd"},
                             [SIGNED])
            v = decide([clear(), signed, *found])  # a limit on a well-known publisher's program: N7's one answer
            self.assertEqual(v["verdict"], "deep_check_unfinished")
            self.assertEqual(v["title"], "Signed by NetEase (Hangzhou) Network Co., Ltd, deep check couldn't finish")

    def test_n7_any_capa_failure_on_a_well_known_publishers_program_gives_one_answer(self):
        """Round 2's N7: Chrome's signed setup got "Couldn't fully check" when capa crashed (access violation) and
        "No known detections" when it ran out of memory. Stand-ins for a crash, out of memory, a timeout, size."""
        crash = self.capa(b"", 0xC0000005)  # access violation: no output at all
        out_of_memory = self.capa(b"Traceback (most recent call last):\n  File x\nMemoryError\n", 1)
        traceback = self.capa(b"Traceback (most recent call last):\n  File x\nvivisect.exc.InvalidAddress: 0x401000\n")
        with mock.patch.object(capabilities.procs, "run", return_value=(None, b"", b"")), \
                mock.patch.object(capabilities.config, "CAPA_RULES", Path(__file__).parent):
            timeout = capabilities.scan(write(samples.minimal_pe()))
        with mock.patch.object(capabilities, "MAX_SIZE", 10):
            too_big = capabilities.scan(write(samples.minimal_pe()))
        self.assertEqual(crash[0].level, ERROR)
        google = Finding("signature", CLEAR, "Signed.", {"trusted_publisher": "Google LLC"}, [SIGNED])
        answers = set()
        for found in (crash, out_of_memory, traceback, timeout, too_big):
            v = decide([clear(), google, *found])
            answers.add((v["verdict"], v["title"]))
            self.assertTrue(any(r.startswith("Signed by Google LLC, deep check couldn't finish: ") for r in v["reasons"]),
                            v["reasons"])
            # Unknown or unsigned programs keep "Couldn't fully check"
            self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")
            unsigned = Finding("signature", NOTE, "Not signed.", {}, [UNSIGNED])
            self.assertEqual(decide([clear(), unsigned, *found])["verdict"], "couldnt_fully_check")
            other = Finding("signature", CLEAR, "Signed.", {"signed_by": "Some Small Company"}, [SIGNED])
            self.assertEqual(decide([clear(), other, *found])["verdict"], "couldnt_fully_check")
        self.assertEqual(answers, {("deep_check_unfinished", "Signed by Google LLC, deep check couldn't finish")})

    def test_n7_another_gap_still_says_couldnt_fully_check_and_a_detection_still_wins(self):
        crash = self.capa(b"", 0xC0000005)
        google = Finding("signature", CLEAR, "Signed.", {"trusted_publisher": "Google LLC"}, [SIGNED])
        yara_failed = Finding("yara", ERROR, "YARA couldn't scan it.")
        self.assertEqual(decide([clear(), google, *crash, yara_failed])["verdict"], "couldnt_fully_check")
        found = Finding("clamav", MALICIOUS, "ClamAV recognises it as malware: Win.Trojan.X.", {"engine": "ClamAV"})
        self.assertEqual(decide([clear(), google, *crash, found])["verdict"], "malicious")

    def test_capa_error_without_a_traceback_shows_its_last_real_line(self):
        found = self.capa(b"WARNING capa.rules: skipping\n   ----\nfailed to load the file\nnote: see the log\n")
        self.assertEqual(found[0].text, "capa couldn't analyse this program (failed to load the file).")

    def test_l3_capa_logged_error_shows_its_message_not_its_source_line(self):
        """Round 2's L3: Edge's psmachine_arm64.dll read "(ERROR capa: helpers.py:341)". capa's log, as it printed it."""
        log = (
            "WARNING  capa.rules: skipping non-.yml file: .version          __init__.py:2214\r\n"
            "WARNING  capa.features.extractors.pefile: unsupported             pefile.py:138\r\n"
            "         architecture: IMAGE_FILE_MACHINE_ARM64                                \r\n"
            "ERROR    capa:                                                   helpers.py:337\r\n"
            "         -------------------------------------------------------               \r\n"
            "         -------------------------                                             \r\n"
            "ERROR    capa:  Input file does not appear to target a supported helpers.py:338\r\n"
            "         architecture.                                                         \r\n"
            "ERROR    capa:                                                   helpers.py:339\r\n"
            "ERROR    capa:  capa currently only supports analyzing x86 (32-  helpers.py:340\r\n"
            "         and 64-bit).                                                          \r\n"
            "ERROR    capa:                                                   helpers.py:341\r\n"
            "         -------------------------------------------------------               \r\n"
            "         -------------------------                                             \r\n")
        found = self.capa(log.encode(), 17)
        self.assertEqual(found[0].text, "capa couldn't analyse this program (Input file does not appear to target a "
                                        "supported architecture. capa currently only supports analyzing x86 (32- and "
                                        "64-bit)).")
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_capa_crash_codes_are_named(self):
        found = self.capa(b"WARNING capa.rules: skipping\nException in thread Thread-1:\n", 0xC00000FD)
        self.assertEqual(found[0].text, "capa couldn't analyse this program (it crashed: stack overflow, "
                                        "exit code 0xC00000FD).")
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")
        self.assertIn("GB of memory", self.capa(b"", 0xC0000017)[0].text)  # Windows' "out of memory" code

    def test_h3_end_to_end_damaged_old_office_document(self):
        damaged = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + random.Random(3).randbytes(4096)  # report's magic_ole.doc
        found = macros.scan(write(damaged))
        self.assertEqual(found[0].level, ERROR)
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_h1_end_to_end_zip_header_with_nothing_readable_behind_it(self):
        data = b"PK\x03\x04" + random.Random(4).randbytes(64 * 1024)  # report's magic_pk.zip
        found = archive.scan(write(data))
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")


class BrokenZipTests(unittest.TestCase):
    """When the normal zip reader gives up, Blotter reads each file from its own header (like 7-Zip and tar)."""

    def setUp(self):
        config.INCOMING.mkdir(parents=True, exist_ok=True)

    def unpack(self, data):
        got = {}
        notes = archives.walk(write(data), "zip", lambda n, p: got.__setitem__(n, p.read_bytes()), archives.Budget())
        return got, notes

    def test_cut_off_last_byte_and_bad_directory_pointer_give_back_every_file(self):
        files = {"tool.exe": samples.minimal_pe(), "docs/readme.txt": b"hello " * 500}
        for damage in (cut1, cdoffset):
            got, notes = self.unpack(damage(samples.zip_of(files)))
            self.assertEqual(got, files, damage.__name__)
            self.assertTrue(notes["lenient"] and notes["complete"], damage.__name__)
            self.assertEqual(notes["damaged"], [])

    def test_stored_files_and_data_descriptors(self):
        out = Unseekable()
        files = {"a.bin": random.Random(1).randbytes(70_000), "b.txt": b"abc" * 1000}
        with zipfile.ZipFile(out, "w") as z:
            z.writestr(zipfile.ZipInfo("a.bin"), files["a.bin"], compress_type=zipfile.ZIP_STORED)
            z.writestr(zipfile.ZipInfo("b.txt"), files["b.txt"], compress_type=zipfile.ZIP_DEFLATED)
        data = out.getvalue()
        got, notes = self.unpack(cut1(data))
        self.assertEqual(got, files)
        self.assertTrue(notes["complete"])
        # Without any table of contents Blotter can't know nothing followed, so it says the archive was cut off.
        got, notes = self.unpack(data[:data.find(b"PK\x01\x02")])
        self.assertEqual(got, files)
        self.assertFalse(notes["complete"])

    def test_a_cut_off_zip_is_couldnt_fully_check_and_what_was_read_is_still_checked(self):
        data = samples.zip_of({"invoice.pdf.exe": samples.minimal_pe(), "big.bin": random.Random(2).randbytes(200_000)})
        found = archive.scan(write(data[:len(data) * 3 // 4]))
        self.assertTrue(any(DISGUISED in f.signals for f in found))   # the disguised program was still found
        damaged = [f for f in found if f.details.get("damaged")]
        self.assertTrue(damaged and UNCHECKED in damaged[0].signals)
        self.assertEqual(decide([clear(), *found])["verdict"], "suspicious")  # the disguise outranks the gap
        found = archive.scan(write(samples.zip_of({"a.txt": b"x", "big.bin": random.Random(2).randbytes(200_000)})[:-5000]))
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_breaking_the_table_of_contents_no_longer_hides_a_program(self):
        data = cdoffset(samples.zip_of({"holiday.jpg.exe": samples.minimal_pe()}))
        found = archive.scan(write(data))
        self.assertEqual(decide([clear(), *found])["verdict"], "suspicious")
        self.assertTrue(any(f.details.get("repaired") for f in found))

    def test_damaged_data_inside_a_readable_zip(self):
        first = random.Random(6).randbytes(5000)
        data = bytearray(samples.zip_of({"a.txt": first, "b.txt": b"second " * 2000}))
        data[data.find(b"PK\x03\x04", 10) - 2500] ^= 0xFF  # in the middle of a.txt's data
        got, notes = self.unpack(bytes(data))
        self.assertIn("a.txt", notes["damaged"])
        self.assertEqual(got["b.txt"], b"second " * 2000)
        found = archive.scan(write(bytes(data)))
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_limits_still_apply(self):
        data = cut1(samples.zip_of({f"f{n}.txt": b"x" for n in range(config.ARCHIVE_MAX_MEMBERS + 1)}))
        with self.assertRaises(archives.Bomb):
            self.unpack(data)

    @unittest.skipUnless(ROJO.is_file(), "the report's rojo zip isn't on this PC")
    def test_the_two_damaged_zips_from_the_report(self):
        original = ROJO.read_bytes()
        with zipfile.ZipFile(ROJO) as z:
            want = hashlib.sha256(z.read("rojo.exe")).hexdigest()
        for damage in (cut1, cdoffset):  # zip_rojo_cut1.zip, zip_rojo_zip_cdoffset.zip
            got, notes = self.unpack(damage(original))
            self.assertEqual(hashlib.sha256(got["rojo.exe"]).hexdigest(), want, damage.__name__)
            self.assertTrue(notes["complete"])
            found = archive.scan(write(damage(original)))
            self.assertNotIn("couldn't unpack", " ".join(f.text for f in found))
            self.assertTrue(any(f.details.get("repaired") for f in found))


def ole1(class_name: bytes, native: bytes) -> bytes:
    """An embedded OLE 1.0 object as RTF carries it (MS-OLEDS 2.2): version, 'embedded', class, topic, item, data."""
    def text(s):
        return struct.pack("<I", len(s) + 1) + s + b"\0" if s else struct.pack("<I", 0)
    return struct.pack("<II", 0x501, 2) + text(class_name) + text(b"") + text(b"") + struct.pack("<I", len(native)) + native


def package(filename: str, data: bytes) -> bytes:
    """OLE Package native data: the file name, where it came from, where it is unpacked to, and the file."""
    name = filename.encode()
    temp = b"C:\\Users\\x\\AppData\\Local\\Temp\\" + name
    return (struct.pack("<H", 2) + name + b"\0" + b"C:\\" + name + b"\0" + struct.pack("<II", 0, 0) + temp + b"\0"
            + struct.pack("<I", len(data)) + data)


def rtf_with(*objects: bytes, autoload=False) -> bytes:
    body = b"".join(b"{\\object\\objemb" + (b"\\objupdate" if autoload else b"") + b"{\\*\\objdata " +
                    binascii.hexlify(o) + b"}}" for o in objects)
    return b"{\\rtf1\\ansi Hello. " + body + b"}"


class RtfTests(unittest.TestCase):
    """Built in memory (nothing like an attack file is written to disk); the objects carry no attack code."""

    def verdict(self, data):
        return decide([clear(), *rtf.analyze("rtf", data)])

    def test_plain_rtf(self):
        found = rtf.analyze("rtf", b"{\\rtf1\\ansi Just text.}")
        self.assertEqual([f.level for f in found], [CLEAR])
        self.assertEqual(self.verdict(b"{\\rtf1\\ansi Just text.}")["verdict"], "no_known_detections")

    def test_equation_editor_object(self):
        found = rtf.analyze("rtf", rtf_with(ole1(b"Equation.3", b"\0" * 32)))
        self.assertEqual(found[0].level, SUSPICIOUS)
        self.assertIn("CVE-2017-11882", found[0].text)

    def test_ole2link_names_the_address(self):
        native = "x http://blotter-test.invalid/doc.hta x".encode("utf-16-le")
        found = rtf.analyze("rtf", rtf_with(ole1(b"OLE2Link", native), autoload=True))
        self.assertEqual(found[0].level, SUSPICIOUS)
        self.assertIn("http://blotter-test.invalid/doc.hta", found[0].text)
        self.assertTrue(any(f.details.get("ability") == "rtf-autoload" for f in found))

    def test_program_packed_inside(self):
        data = rtf_with(ole1(b"Package", package("invoice.exe", b"MZ" + bytes(64))))
        self.assertEqual(self.verdict(data)["verdict"], "suspicious")

    def test_ordinary_file_packed_inside_is_only_listed(self):
        data = rtf_with(ole1(b"Package", package("notes.txt", b"shopping list")))
        found = rtf.analyze("rtf", data)
        self.assertIn("notes.txt", found[0].text)
        self.assertEqual(self.verdict(data)["verdict"], "no_known_detections")

    def test_ordinary_object(self):
        found = rtf.analyze("rtf", rtf_with(ole1(b"PBrush", b"\0" * 16)))
        self.assertEqual([f.level for f in found], [CLEAR])
        self.assertIn("PBrush", found[0].text)

    def test_broken_object_is_couldnt_fully_check(self):
        self.assertEqual(self.verdict(rtf_with(b"\x01\x02\x03\x04" * 8))["verdict"], "couldnt_fully_check")

    def test_parser_failure_fails_closed(self):
        from oletools import rtfobj
        with mock.patch.object(rtfobj.RtfObjParser, "parse", side_effect=RuntimeError("bad")):
            found = rtf.analyze("rtf", b"{\\rtf1 x}")
        self.assertEqual(found[0].level, ERROR)
        self.assertEqual(decide([clear(), *found])["verdict"], "couldnt_fully_check")

    def test_the_macro_check_leaves_rtf_to_the_rtf_check(self):
        path = write(b"{\\rtf1\\ansi Just text.}")
        self.assertEqual(macros.scan(path)[0].level, "skipped")
        self.assertEqual(rtf_check.scan(path)[0].level, CLEAR)
        self.assertEqual(rtf_check.scan(write(b"%PDF-1.4"))[0].level, "skipped")

    def test_report_rtfs(self):
        present = [p for p in REPORT_RTFS if p.is_file()]
        if not present:
            self.skipTest("the report's Windows license RTFs aren't on this PC")
        for path in present:
            found = rtf_check.scan(path)
            self.assertEqual([f.level for f in found], [CLEAR], path)
            self.assertEqual(decide([clear(), *found, *macros.scan(path)])["verdict"], "no_known_detections", path)


if __name__ == "__main__":
    unittest.main()
