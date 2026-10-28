"""PDF check: JavaScript, self-starting actions, Launch, packed-in files, disguised names, object streams."""

import tempfile
import unittest
import zlib
from pathlib import Path

from blotter.checks import archive, pdf
from blotter.findings import CLEAR, HIDING, RISKY, SKIPPED, SUSPICIOUS, WEAK
from blotter.verdict import decide
from tests import samples


def make_pdf(*objects: bytes) -> bytes:
    body = b"".join(b"%d 0 obj\n" % n + o + b"\nendobj\n" for n, o in enumerate(objects, 1))
    return b"%PDF-1.7\n" + body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


PLAIN = make_pdf(b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [] /Count 0 >>")
AUTORUN = make_pdf(b"<< /Type /Catalog /OpenAction 2 0 R >>", b"<< /S /JavaScript /JS (app.alert('hi')) >>")


def abilities(found):
    return {f.details.get("ability") for f in found}


class PdfTests(unittest.TestCase):
    def test_plain_pdf(self):
        found = pdf.analyze("pdf", PLAIN)
        self.assertEqual([f.level for f in found], [CLEAR])

    def test_javascript_that_runs_on_opening(self):
        found = pdf.analyze("pdf", AUTORUN)
        self.assertEqual(abilities(found), {"pdf-autorun-script"})
        self.assertEqual(found[0].signals, [RISKY])

    def test_autorun_with_launch_is_suspicious(self):
        data = make_pdf(b"<< /OpenAction 2 0 R >>", b"<< /S /JavaScript /JS (x) >>",
                        b"<< /S /Launch /F (cmd.exe) >>")
        self.assertEqual(pdf.analyze("pdf", data)[0].level, SUSPICIOUS)

    def test_form_javascript_is_only_weak(self):
        found = pdf.analyze("pdf", make_pdf(b"<< /AcroForm << >> /JS (calc()) >>"))
        self.assertEqual(found[0].signals, [WEAK])
        self.assertEqual(decide(found)["verdict"], "no_known_detections")

    def test_disguised_names(self):
        data = make_pdf(b"<< /Open#41ction 2 0 R >>", b"<< /S /J#61vaScript /J#53 (x) >>")
        found = pdf.analyze("pdf", data)
        self.assertIn("pdf-autorun-script", abilities(found), "the disguise is seen through")
        self.assertTrue(any(HIDING in f.signals for f in found))
        self.assertEqual(decide(found)["verdict"], "suspicious", "risky + hiding")

    def test_keywords_inside_compressed_object_streams(self):
        inner = zlib.compress(b"<< /OpenAction 3 0 R >> << /S /JavaScript /JS (x) >>")
        stream = b"<< /Type /ObjStm /N 2 /First 0 /Filter /FlateDecode /Length %d >>\nstream\n" % len(inner)
        data = make_pdf(stream + inner + b"\nendstream")
        self.assertIn("pdf-autorun-script", abilities(pdf.analyze("pdf", data)))

    def test_embedded_file_counts_with_context(self):
        found = pdf.analyze("pdf", make_pdf(b"<< /Type /EmbeddedFile /Length 3 >>"))
        self.assertEqual(found[0].signals, [WEAK])
        self.assertEqual(decide(found)["verdict"], "no_known_detections")

    def test_scan_skips_other_files_and_reads_pdfs(self):
        folder = Path(tempfile.mkdtemp())
        (folder / "a.blotter").write_bytes(b"not a pdf")
        (folder / "b.blotter").write_bytes(AUTORUN)
        self.assertEqual(pdf.scan(folder / "a.blotter")[0].level, SKIPPED)
        self.assertIn("pdf-autorun-script", abilities(pdf.scan(folder / "b.blotter")))

    def test_pdf_inside_an_archive(self):
        path = Path(tempfile.mkdtemp()) / "a.blotter"
        path.write_bytes(samples.zip_of({"invoice.pdf": AUTORUN}))
        found = archive.scan(path)
        self.assertTrue(any(f.details.get("scope") == "invoice.pdf" and RISKY in f.signals for f in found))


if __name__ == "__main__":
    unittest.main()
