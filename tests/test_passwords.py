"""Locked archives: if "infected" doesn't open them, the person can type the password and Blotter checks again."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import py7zr

from blotter import runner as runner_module
from blotter.analyze import archives
from blotter.cache import Cache
from blotter.checks import archive
from blotter.findings import DISGUISED, UNCHECKED
from blotter.runner import Runner
from tests import samples
from tests.test_runner_app import wait_done

SECRET = "hunter2"


def locked_zip() -> bytes:
    return samples.zip_locked("tool.pdf.exe", samples.minimal_pe(), password=SECRET.encode())


def copy(data: bytes) -> Path:
    path = Path(tempfile.mkdtemp()) / "copy.blotter"
    path.write_bytes(data)
    return path


def findings(job):
    return [f for c in job.checks.values() for f in c["findings"]]


class WalkTests(unittest.TestCase):
    def test_typed_password_opens_zip_7z(self):
        seen = []
        archives.walk(copy(locked_zip()), "zip", lambda n, p: seen.append(n), archives.Budget(), [SECRET])
        self.assertEqual(seen, ["tool.pdf.exe"])
        path = Path(tempfile.mkdtemp()) / "a.7z"
        with py7zr.SevenZipFile(path, "w", password=SECRET) as z:
            z.writestr(b"hello", "notes.txt")
        seen = []
        archives.walk(path, "7z", lambda n, p: seen.append(n), archives.Budget(), [SECRET])
        self.assertEqual(seen, ["notes.txt"])

    def test_infected_is_still_tried(self):
        seen = []
        data = samples.zip_locked("a.txt", b"x")  # locked with "infected"
        archives.walk(copy(data), "zip", lambda n, p: seen.append(n), archives.Budget(), ["wrong"])
        self.assertEqual(seen, ["a.txt"])


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [archive])

    def test_locked_then_right_password(self):
        path = copy(locked_zip())
        job = wait_done(self.runner.start(path, "tools.zip", 1, "0" * 64), seconds=60)
        self.assertTrue(job.to_dict()["needs_password"])
        self.assertEqual(job.verdict["verdict"], "couldnt_fully_check")
        self.assertTrue(path.exists(), "the copy waits for the password")
        self.assertIn("Type its password", " ".join(job.verdict["reasons"]))

        again = wait_done(self.runner.retry_with_password(job.id, SECRET), seconds=60)
        self.assertTrue(any(DISGUISED in f.signals for f in findings(again)), "the inside was checked")
        self.assertFalse(again.to_dict()["needs_password"])
        self.assertEqual(again.verdict["verdict"], "suspicious")
        self.assertFalse(path.exists(), "the copy is deleted once the archive could be opened")
        self.assertNotIn(SECRET, str(again.to_dict()), "the password is never sent back to the page")
        self.assertIsNone(self.runner.retry_with_password(job.id, SECRET), "one retry per kept copy")

    def test_wrong_password_asks_again(self):
        job = wait_done(self.runner.start(copy(locked_zip()), "tools.zip", 1, "0" * 64), seconds=60)
        again = wait_done(self.runner.retry_with_password(job.id, "nope"), seconds=60)
        self.assertTrue(again.to_dict()["needs_password"])
        self.assertIn("didn't open them either", " ".join(again.verdict["reasons"]))
        self.assertTrue(any(UNCHECKED in f.signals for f in findings(again)))

    def test_copy_is_deleted_after_a_while(self):
        with mock.patch.object(runner_module, "KEEP_LOCKED", 0.2):
            path = copy(locked_zip())
            job = wait_done(self.runner.start(path, "tools.zip", 1, "0" * 64), seconds=60)
            time.sleep(0.6)
        self.assertFalse(path.exists())
        self.assertIsNone(self.runner.retry_with_password(job.id, SECRET))

    def test_unlocked_archives_are_deleted_right_away(self):
        path = copy(samples.zip_of({"a.txt": "x"}))
        job = wait_done(self.runner.start(path, "a.zip", 1, "0" * 64), seconds=60)
        self.assertFalse(job.to_dict()["needs_password"])
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
