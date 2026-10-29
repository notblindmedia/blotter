"""Loaded first (by name), so the tests' own folder, ports and key store are set before any Blotter module reads
them. Without this, `unittest discover -s tests` (no `-t .`) imported blotter.config before tests/__init__.py and
the tests used the real %LOCALAPPDATA%\\Blotter: on 2026-10-29 that deleted the real YARA Forge rules."""

import os
import unittest
from pathlib import Path

import tests  # noqa: F401  (sets BLOTTER_HOME and friends)
from blotter import config


class IsolationTests(unittest.TestCase):
    def test_tests_never_use_the_real_blotter_folder(self):
        real = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Blotter"
        self.assertNotEqual(config.HOME.resolve(), real.resolve())
        self.assertTrue(config.HOME.name.startswith("blotter-test-"))
        self.assertNotEqual(config.CLAMD_PORT, 4849)
        self.assertNotEqual(config.KEYRING_SERVICE, "Blotter")
