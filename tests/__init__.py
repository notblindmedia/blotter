"""Tests never touch the real cache, the real keys or the real Defender."""

import os
import tempfile

os.environ["BLOTTER_HOME"] = tempfile.mkdtemp(prefix="blotter-test-")
os.environ["BLOTTER_KEYRING_SERVICE"] = "Blotter-test"
os.environ["BLOTTER_PORT"] = "48791"
os.environ["BLOTTER_CLAMD_PORT"] = "48792"
os.environ["BLOTTER_DEFENDER_EXE"] = os.path.join(os.environ["BLOTTER_HOME"], "no-scanner-here.exe")
