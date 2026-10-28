"""Rule packs are stored encrypted, so no antivirus reads them as malware, and still load."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, updates, vault
from blotter.analyze import yararules
from blotter.findings import MALICIOUS

MARKER = "blotter-vault-test-marker-7f3a"
FAKE_FORGE = ('rule SIGNATURE_BASE_MAL_Blotter_Vault_Test {\n'
              '  meta:\n    description = "Blotter vault test"\n    score = 75\n'
              f'  strings:\n    $a = "{MARKER}"\n  condition:\n    $a\n}}\n').encode()


class VaultTests(unittest.TestCase):
    def test_round_trip_and_contents_unreadable(self):
        path = Path(tempfile.mkdtemp()) / "v.7z"
        vault.write(path, {"a.yar": FAKE_FORGE, "b.bin": bytes(range(256)) * 10})
        self.assertEqual(vault.read(path), {"a.yar": FAKE_FORGE, "b.bin": bytes(range(256)) * 10})
        raw = path.read_bytes()
        for visible in (MARKER.encode(), b"rule ", b"a.yar"):
            self.assertNotIn(visible, raw, "nothing inside may be readable at rest")

    def test_failed_write_keeps_the_old_vault(self):
        path = Path(tempfile.mkdtemp()) / "v.7z"
        vault.write(path, {"a": b"old"})
        with mock.patch("py7zr.SevenZipFile.writef", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                vault.write(path, {"a": b"new"})
        self.assertEqual(vault.read(path), {"a": b"old"})
        self.assertEqual([p.name for p in path.parent.iterdir()], ["v.7z"])


class ForgeAtRestTests(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(config, "YARA_FORGE", folder / "yara-forge-core.7z"),
                        mock.patch.object(config, "YARA_COMPILED", folder / "compiled.7z"),
                        mock.patch.object(config, "OLD_PLAIN_RULES", [folder / "yara-forge-core.yar",
                                                                      folder / "compiled.yarc",
                                                                      folder / "compiled.key"])]
        for p in self.patches:
            p.start()
        self.folder = folder

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def plain_files(self):
        return [p.name for p in self.folder.iterdir() if p.suffix in (".yar", ".yarc", ".key")]

    def test_forge_rules_load_from_the_vault(self):
        vault.write(config.YARA_FORGE, {yararules.FORGE_MEMBER: FAKE_FORGE})
        rules = yararules.load()
        found = yararules.scan_target(rules, "yara", data=f"xx {MARKER} xx".encode())
        self.assertEqual(found[0].level, MALICIOUS)
        self.assertEqual(found[0].details["source"], "YARA Forge")
        self.assertEqual(self.plain_files(), [], "no plain rules or compiled rules on disk")
        self.assertNotIn(MARKER.encode(), config.YARA_COMPILED.read_bytes())

    def test_compiled_rules_are_reused_and_redone_on_change(self):
        vault.write(config.YARA_FORGE, {yararules.FORGE_MEMBER: FAKE_FORGE})
        yararules.load()
        stamp = config.YARA_COMPILED.stat().st_mtime_ns
        yararules.load()
        self.assertEqual(config.YARA_COMPILED.stat().st_mtime_ns, stamp)
        vault.write(config.YARA_FORGE, {yararules.FORGE_MEMBER: FAKE_FORGE.replace(b"7f3a", b"8e4b")})
        rules = yararules.load()
        self.assertTrue(rules.match(data=MARKER.replace("7f3a", "8e4b").encode()))

    def test_old_plain_files_are_moved_into_the_vault(self):
        config.OLD_PLAIN_RULES[0].write_bytes(FAKE_FORGE)
        config.OLD_PLAIN_RULES[1].write_bytes(b"old compiled")
        yararules.migrate()
        self.assertEqual(self.plain_files(), [])
        self.assertEqual(vault.read(config.YARA_FORGE)[yararules.FORGE_MEMBER], FAKE_FORGE)

    def test_update_writes_only_the_vault(self):
        import io
        import zipfile
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w") as z:
            z.writestr(updates.FORGE_MEMBER, FAKE_FORGE)
        release = mock.Mock(status_code=200, json=lambda: {"tag_name": "20990101", "assets": [
            {"name": updates.FORGE_ASSET, "digest": "sha256:" + "0" * 64, "browser_download_url": "https://github.com/x"}]})
        with mock.patch("blotter.network.get", return_value=release), \
             mock.patch.object(updates, "download", return_value=package.getvalue()):
            print_line = updates.yara_forge(force=True)
        self.assertIn("20990101", print_line)
        self.assertEqual(self.plain_files(), [])
        self.assertEqual(vault.read(config.YARA_FORGE)[yararules.FORGE_MEMBER], FAKE_FORGE)


class ClamAVExclusionTests(unittest.TestCase):
    def test_rules_and_quarantine_are_excluded(self):
        from blotter import clamav
        text = clamav._write_configs()[0].read_text()
        for folder in (config.HOME / "rules", config.QUARANTINE, config.OWN_RULES, config.CLAMAV_DB):
            self.assertIn(f"ExcludePath ^{clamav.regex_path(folder)}", text)


if __name__ == "__main__":
    unittest.main()
