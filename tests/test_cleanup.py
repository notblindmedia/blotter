"""Deleting only Blotter's own work folders (cleanup.safe_remove), and unpacking that can't write outside them
("zip slip") or leave links behind. Harmless: plain text files, and junctions inside the test's own temp folders."""

import io
import os
import re
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from blotter import cleanup, config
from blotter.analyze import archives

try:
    import _winapi
    JUNCTIONS = hasattr(_winapi, "CreateJunction")
except ImportError:
    JUNCTIONS = False

HOSTILE = ["../evil.txt", "..\\evil2.txt", "dir/../../up.txt", "/abs.txt", "\\abs2.txt", "C:/drive.txt",
           "C:drive2.txt", "\\\\server\\share\\unc.txt", "CON", "NUL.exe", "COM1.txt", "a/b/c/nested.txt",
           "-C", "--help"]


def outside_folder(test):
    """A folder next to (not inside) Blotter's test home, with one file in it; gone again after the test."""
    temp = tempfile.TemporaryDirectory(prefix="blotter-outside-")
    test.addCleanup(temp.cleanup)
    folder = Path(temp.name)
    (folder / "keep.txt").write_text("must survive", encoding="utf-8")
    return folder


def junction(link: Path, target: Path):
    _winapi.CreateJunction(str(target), str(link))


def snapshot(*folders):
    return {f: sorted(str(p.relative_to(f)) for p in f.rglob("*")) for f in folders}


class SafeRemoveTests(unittest.TestCase):
    def setUp(self):
        config.INCOMING.mkdir(parents=True, exist_ok=True)

    def test_removes_a_work_folder(self):
        folder = archives.workdir()
        (folder / "sub").mkdir()
        (folder / "sub" / "m0001.blotter").write_bytes(b"x")
        ro = folder / "readonly.blotter"
        ro.write_bytes(b"y")
        os.chmod(ro, stat.S_IREAD)
        self.assertTrue(cleanup.safe_remove(folder))
        self.assertFalse(folder.exists())

    def test_refuses_a_path_outside_blotters_folders(self):
        outside = outside_folder(self)
        self.assertFalse(cleanup.safe_remove(outside))
        self.assertFalse(cleanup.safe_remove(outside / "keep.txt"))
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "must survive")

    def test_refuses_the_incoming_folder_itself_and_a_way_out_with_dots(self):
        self.assertFalse(cleanup.safe_remove(config.INCOMING))
        self.assertTrue(config.INCOMING.is_dir())
        outside = outside_folder(self)
        sneaky = config.INCOMING / os.path.relpath(outside, config.INCOMING)  # incoming\..\..\blotter-outside-...
        self.assertTrue(sneaky.is_dir())
        self.assertFalse(cleanup.safe_remove(sneaky))
        self.assertTrue((outside / "keep.txt").is_file())
        home_file = config.HOME / "keep-home.txt"
        home_file.write_text("Blotter's home, not its work folder", encoding="utf-8")
        self.assertFalse(cleanup.safe_remove(config.INCOMING / ".." / "keep-home.txt"))
        self.assertTrue(home_file.is_file())

    @unittest.skipUnless(JUNCTIONS, "junctions need Windows")
    def test_a_junction_inside_a_work_folder_is_removed_not_followed(self):
        outside = outside_folder(self)
        folder = archives.workdir()
        (folder / "m0001.blotter").write_bytes(b"x")
        junction(folder / "way-out", outside)
        before = snapshot(outside)
        self.assertTrue((folder / "way-out" / "keep.txt").is_file())  # the junction really points outside
        self.assertTrue(cleanup.safe_remove(folder))
        self.assertFalse(folder.exists())
        self.assertEqual(snapshot(outside), before)
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "must survive")

    @unittest.skipUnless(JUNCTIONS, "junctions need Windows")
    def test_a_junction_named_directly_goes_as_a_link(self):
        outside = outside_folder(self)
        link = config.INCOMING / "unpack-junction-test"
        junction(link, outside)
        self.assertTrue(cleanup.safe_remove(link))
        self.assertFalse(os.path.lexists(link))
        self.assertTrue((outside / "keep.txt").is_file())

    @unittest.skipUnless(JUNCTIONS, "junctions need Windows")
    def test_a_path_that_reaches_outside_through_a_junction_is_refused(self):
        outside = outside_folder(self)
        link = config.INCOMING / "unpack-junction-test2"
        junction(link, outside)
        try:
            self.assertFalse(cleanup.safe_remove(link / "keep.txt"))
            self.assertTrue((outside / "keep.txt").is_file())
        finally:
            cleanup.safe_remove(link)

    def test_a_file_symlink_inside_a_work_folder(self):
        outside = outside_folder(self)
        folder = archives.workdir()
        try:
            os.symlink(outside / "keep.txt", folder / "link.blotter")
        except OSError:
            cleanup.safe_remove(folder)
            self.skipTest("symbolic links need Developer Mode or admin rights on this PC")
        self.assertTrue(cleanup.safe_remove(folder))
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "must survive")

    def test_a_sandbox_work_folder_is_allowed(self):
        temp = tempfile.TemporaryDirectory(prefix="blotter-work-")
        self.addCleanup(temp.cleanup)
        work = Path(temp.name)
        (work / "unpack-1").mkdir()
        with mock.patch.dict(os.environ, {"BLOTTER_WORK": str(work)}):
            self.assertTrue(cleanup.safe_remove(work / "unpack-1"))
            self.assertFalse(cleanup.safe_remove(work))  # the root itself stays
        self.assertFalse(cleanup.safe_remove(work))  # outside a sandboxed worker it isn't Blotter's
        self.assertTrue(work.is_dir())

    def test_walk_cleans_its_folder_through_safe_remove(self):
        made = []
        real_workdir = archives.workdir
        with mock.patch.object(archives, "workdir", lambda: made.append(real_workdir()) or made[-1]), \
                mock.patch.object(cleanup, "safe_remove", wraps=cleanup.safe_remove) as remove:
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as z:
                z.writestr("a.txt", "hi")
            path = config.INCOMING / "walk-test.blotter"
            path.write_bytes(data.getvalue())
            archives.walk(path, "zip", lambda n, p: None, archives.Budget())
            path.unlink()
        remove.assert_called_with(made[0])
        self.assertFalse(made[0].exists())


class ZipSlipTests(unittest.TestCase):
    """Names inside an archive never become paths: every file is written as mNNNN.blotter in a fresh work folder."""

    def setUp(self):
        config.INCOMING.mkdir(parents=True, exist_ok=True)
        self.outside = outside_folder(self)
        self.cwd = Path.cwd()
        self.before = snapshot(self.outside, config.INCOMING.parent)
        self.cwd_before = sorted(os.listdir(self.cwd))

    def hostile_zip(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            for name in HOSTILE:
                info = zipfile.ZipInfo(name)
                z.writestr(info, f"contents of {name}")
            link = zipfile.ZipInfo("link-to-outside")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16  # a Unix symbolic link entry
            z.writestr(link, str(self.outside / "keep.txt"))
        raw = data.getvalue()
        for name in HOSTILE:  # zipfile tidies some names when writing; put the hostile bytes back
            tidy = zipfile.ZipInfo(name).filename.encode()
            if tidy != name.encode() and len(tidy) == len(name.encode()):
                raw = raw.replace(tidy, name.encode())
        return raw

    def unpack(self, data, real="zip"):
        path = config.INCOMING / "slip-test.blotter"
        path.write_bytes(data)
        seen = []

        def visit(name, p):
            self.assertRegex(p.name, r"^m\d{4}\.blotter$")
            self.assertEqual(p.parent.parent, config.INCOMING)
            self.assertTrue(re.match(r"unpack-[0-9a-f]{32}$", p.parent.name))
            self.assertFalse(p.is_symlink() or p.is_junction(), name)
            self.assertTrue(p.is_file())
            seen.append((name, p.read_bytes()))

        try:
            archives.walk(path, real, visit, archives.Budget())
        finally:
            path.unlink()
        return seen

    def assertNothingOutside(self):
        self.assertEqual(snapshot(self.outside, config.INCOMING.parent), self.before)
        self.assertEqual(sorted(os.listdir(self.cwd)), self.cwd_before)
        self.assertEqual(list(config.INCOMING.glob("unpack-*")), [])  # and the work folder is gone again

    def test_hostile_names_in_a_zip(self):
        seen = self.unpack(self.hostile_zip())
        self.assertEqual(len(seen), len(HOSTILE) + 1)
        link = dict(seen)["link-to-outside"]
        self.assertEqual(link, str(self.outside / "keep.txt").encode())  # the link's text, as a plain file
        self.assertNothingOutside()

    def test_hostile_names_through_the_lenient_reader(self):
        seen = self.unpack(self.hostile_zip()[:-1])  # broken table of contents: read from file headers
        self.assertEqual(len(seen), len(HOSTILE) + 1)
        self.assertNothingOutside()

    def test_hostile_name_in_a_7z(self):
        import py7zr
        data = io.BytesIO()
        with py7zr.SevenZipFile(data, "w") as z:  # py7zr refuses ../ and C:/ names even when writing
            z.writestr(b"reserved name", "CON")
            z.writestr(b"fine", "ok.txt")
        self.assertEqual(sorted(n for n, _ in self.unpack(data.getvalue(), "7z")), ["CON", "ok.txt"])
        self.assertNothingOutside()

    def test_windows_tar_reads_a_dash_name_as_a_name(self):
        if not archives.WINDOWS_TAR.is_file():
            self.skipTest("Windows' tar.exe isn't here")
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            z.writestr("-C", b"dash C")
            z.writestr("--help", b"dash help")
        path = config.INCOMING / "dash-test.blotter"
        path.write_bytes(data.getvalue())
        folder = archives.workdir()
        try:
            for name, want in (("-C", b"dash C"), ("--help", b"dash help")):
                target = folder / "m0001.blotter"
                self.assertTrue(archives._tar_member(path, name, target, archives.Budget(), len(want), None), name)
                self.assertEqual(target.read_bytes(), want)
        finally:
            archives.remove(folder)
            path.unlink()
        self.assertNothingOutside()


if __name__ == "__main__":
    unittest.main()
