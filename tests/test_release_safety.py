"""Phase 3a, release safety: signatures, the stolen-certificate list, the intel pack, update.bat,
the release builder and the signing kit. Every key here is a throwaway test key."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blotter import config, intel, keysetup, selfupdate, signing
from blotter.analyze import program
from blotter.checks import signature as signature_check
from blotter.findings import SIGNED, SUSPICIOUS

ROOT = Path(__file__).resolve().parent.parent
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
sys.path.insert(0, str(ROOT / "tools"))
import make_release  # noqa: E402

_kit = importlib.util.spec_from_file_location("sign_release", ROOT / "tools" / "sign-release" / "sign_release.py")
sign_release = importlib.util.module_from_spec(_kit)
_kit.loader.exec_module(sign_release)

THUMB = "ab" * 32  # a made-up SHA-256 thumbprint


def new_key():
    private = Ed25519PrivateKey.generate()
    return private, signing.public_b64(private)


class FakeResponse:
    def __init__(self, body=b"", status=200):
        self.content, self.status_code = body, status

    def json(self):
        return json.loads(self.content)

    def iter_content(self, size):
        for i in range(0, len(self.content), size):
            yield self.content[i:i + size]


def fake_web(files: dict):
    """network.get stand-in: url -> bytes (or a list/dict, sent as JSON); anything else is a 404."""
    def get(url, **kwargs):
        body = files.get(url)
        if body is None:
            return FakeResponse(b"", 404)
        return FakeResponse(body if isinstance(body, bytes) else json.dumps(body).encode())
    return mock.patch("blotter.network.get", side_effect=get)


def quiet():
    return contextlib.redirect_stdout(io.StringIO())


# ---- signatures ----

class SigningTests(unittest.TestCase):
    def test_round_trip_and_every_kind_of_mismatch(self):
        private, public = new_key()
        sig = signing.sign(private, signing.RELEASE, b"manifest")
        signing.verify(public, signing.RELEASE, b"manifest", sig)
        signing.verify(public, signing.RELEASE, b"manifest", (sig + "\n").encode())  # as read from a file
        _, other = new_key()
        for key, purpose, data, s in ((public, signing.RELEASE, b"manifest!", sig),  # tampered
                                      (public, signing.PACK, b"manifest", sig),      # other purpose
                                      (other, signing.RELEASE, b"manifest", sig),    # other key
                                      (public, signing.RELEASE, b"manifest", "not base64!"),
                                      ("", signing.RELEASE, b"manifest", sig),        # no key built in
                                      ("c2hvcnQ=", signing.RELEASE, b"manifest", sig)):
            with self.assertRaises(signing.BadSignature):
                signing.verify(key, purpose, data, s)

    def test_fingerprint_and_built_in_keys(self):
        _, public = new_key()
        self.assertRegex(signing.fingerprint(public), r"^([0-9A-F]{4} ){7}[0-9A-F]{4}$")
        self.assertEqual(signing.fingerprint(signing.PACK_KEY), "54E1 1404 9925 BB12 E7BC 6E21 7AFA 1DEE")
        self.assertNotEqual(signing.CODE_KEY, signing.PACK_KEY, "one key, one job")
        self.assertNotEqual(signing.RELEASE, signing.PACK)
        with mock.patch.object(signing, "CODE_KEY", ""):
            self.assertIn("not built into this copy yet", signing.describe()[0])

    def test_the_signing_kit_signs_what_blotter_checks(self):
        self.assertEqual(sign_release.RELEASE, signing.RELEASE)
        _, public = new_key()
        self.assertEqual(sign_release.fingerprint(public), signing.fingerprint(public))


# ---- the stolen-certificate list ----

class StolenCertificateTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        patch = mock.patch.object(config, "HOME", self.home)
        patch.start()
        self.addCleanup(patch.stop)

    def copy(self, name="certutil.exe"):
        target = Path(tempfile.mkdtemp()) / "copy.blotter"
        shutil.copyfile(SYSTEM32 / name, target)
        return target

    def test_windows_gives_the_certificates_sha256(self):
        info = program.signature(self.copy())
        self.assertRegex(info["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(info["sha256"], info["thumbprint"])

    def test_a_listed_sha256_takes_all_trust_away(self):
        target = self.copy()
        sha = program.signature(target)["sha256"]
        with mock.patch.object(program, "stolen_certificates", return_value={sha: "Test Ltd; Trojan; listed 2026-01-01"}):
            [found] = signature_check.scan(target)
        self.assertEqual(found.level, SUSPICIOUS)
        self.assertNotIn(SIGNED, found.signals)
        self.assertNotIn("trusted_publisher", found.details)
        self.assertNotIn("signed_by", found.details)
        self.assertIn("Test Ltd; Trojan", found.text)
        self.assertEqual(found.details["threat"], "stolen certificate")

    def test_a_revoked_or_untrusted_listed_certificate_is_still_suspicious(self):
        for status in ("NotTrusted", "UnknownError", "HashMismatch", "Valid"):
            info = {"status": status, "signer": "Some Ltd", "kind": "Authenticode", "serial": "01",
                    "thumbprint": "cd" * 20, "sha256": THUMB, "issuer": "CA"}
            with mock.patch.object(program, "signature", return_value=info), \
                    mock.patch.object(program, "stolen_certificates", return_value={THUMB: "listed"}):
                [found] = program.signature_findings("signature", "x")
            self.assertEqual(found.level, SUSPICIOUS, status)
            self.assertIn("stolen or abused", found.text)

    def test_the_intel_pack_list_adds_to_the_shipped_one(self):
        rules = Path(tempfile.mkdtemp())
        (rules / "stolen-certificates.txt").write_text(f"{'11' * 32}  # shipped\n", encoding="utf-8")
        (self.home / "intel").mkdir()
        (self.home / "intel" / "stolen-certificates.txt").write_text(f"{THUMB}  # from the pack\n", encoding="utf-8")
        with mock.patch.object(config, "OWN_RULES", rules):
            self.assertEqual(program.stolen_certificates(), {"11" * 32: "shipped", THUMB: "from the pack"})

    def test_list_from_abuse_ch_answer(self):
        entries = [
            {"time_stamp": "2025-02-01 10:00:00", "thumbprint": THUMB.upper(), "thumbprint_algorithm": "SHA256",
             "subject_cn": "Evil\nLtd", "cscb_listed": True, "cscb_reason": "Trojan"},
            {"time_stamp": "2025-01-01 10:00:00", "thumbprint": "CD" * 20, "thumbprint_algorithm": "SHA1",
             "subject_cn": "Old Ltd", "cscb_listed": "True", "cscb_reason": "Loader"},
            {"time_stamp": "2025-03-01", "thumbprint": "EF" * 32, "thumbprint_algorithm": "SHA256",
             "subject_cn": "Delisted Ltd", "cscb_listed": False, "cscb_reason": "x"},
            {"time_stamp": "2025-03-01", "thumbprint": "12" * 16, "thumbprint_algorithm": "MD5",
             "subject_cn": "Odd", "cscb_listed": True, "cscb_reason": "x"},
            {"time_stamp": "2025-04-01", "thumbprint": THUMB, "thumbprint_algorithm": "SHA256",
             "subject_cn": "Evil Ltd", "cscb_listed": True, "cscb_reason": "Trojan"},  # listed twice
        ]
        text = intel.stolen_list_from_cscb(entries, "2026-11-01 20:00 UTC")
        self.assertEqual(intel._hex_list(text), 2)
        rules = Path(tempfile.mkdtemp())
        (rules / "stolen-certificates.txt").write_text(text, encoding="utf-8")
        with mock.patch.object(config, "OWN_RULES", rules):
            listed = program.stolen_certificates()
        self.assertEqual(set(listed), {THUMB, "cd" * 20})
        self.assertEqual(listed[THUMB], "Evil Ltd; Trojan; listed 2025-04-01")
        self.assertIn("abuse.ch", text)
        self.assertIn("2 certificates", text)


# ---- the intel pack ----

class IntelPackTests(unittest.TestCase):
    def setUp(self):
        self.private, public = new_key()
        self.home = Path(tempfile.mkdtemp())
        for patch in (mock.patch.object(config, "HOME", self.home), mock.patch.object(signing, "PACK_KEY", public),
                      mock.patch.object(config, "OWN_RULES", Path(tempfile.mkdtemp()))):
            patch.start()
            self.addCleanup(patch.stop)

    def pack(self, days_ago=1, files=None, purpose=signing.PACK, key=None):
        made = (datetime.now(timezone.utc) - timedelta(days=days_ago)).replace(microsecond=0)
        body = json.dumps({"kind": intel.KIND, "format": 1, "made": made.isoformat(),
                           "files": files or {"stolen-certificates.txt": f"# test\n{THUMB}  # test entry\n"}}).encode()
        return body, signing.sign(key or self.private, purpose, body)

    def test_a_signed_pack_is_installed_and_used(self):
        line = intel.apply(*self.pack())
        self.assertIn("installed", line)
        self.assertEqual(program.stolen_certificates(), {THUMB: "test entry"})
        self.assertEqual(intel.installed()["counts"], {"stolen-certificates.txt": 1})

    def test_wrong_key_or_purpose_is_refused(self):
        other, _ = new_key()
        for body, sig in (self.pack(key=other), self.pack(purpose=signing.RELEASE)):
            with self.assertRaises(signing.BadSignature):
                intel.apply(body, sig)
        body, sig = self.pack()
        with self.assertRaises(signing.BadSignature):
            intel.apply(body.replace(b"test entry", b"else entry"), sig)
        self.assertFalse((self.home / "intel").exists())

    def test_only_plain_lists_never_code(self):
        for files in ({"blotter/app.py": "print(1)"}, {"trusted-publishers.txt": "Evil Ltd"},
                      {"../stolen-certificates.txt": THUMB}, {"stolen-certificates.txt": "import os\n"},
                      {"stolen-certificates.txt": f"{THUMB}\nnot-hex  # x\n"}, {"stolen-certificates.txt": 5}):
            with self.assertRaises(intel.IntelError, msg=files):
                intel.apply(*self.pack(files=files))
        self.assertFalse((self.home / "intel").exists(), "nothing written from a refused pack")

    def test_older_and_future_packs_are_refused(self):
        first = self.pack(days_ago=2)
        intel.apply(*first)
        self.assertIn("already installed", intel.apply(*first))
        with self.assertRaises(intel.IntelError):
            intel.apply(*self.pack(days_ago=5))
        with self.assertRaises(intel.IntelError):
            intel.apply(*self.pack(days_ago=-3))
        self.assertIn("installed", intel.apply(*self.pack(days_ago=1)))

    def test_refresh_daily_missing_and_refused(self):
        with fake_web({}):
            self.assertIn("No intel pack is published yet", intel.refresh())
            self.assertIn("less than a day ago", intel.refresh())
        body, sig = self.pack()
        with fake_web({intel.PACK_URL: body, intel.PACK_URL + ".sig": sig.encode()}):
            self.assertIn("installed", intel.refresh(force=True))
        other, _ = new_key()
        body, sig = self.pack(days_ago=0, key=other)
        with fake_web({intel.PACK_URL: body, intel.PACK_URL + ".sig": sig.encode()}):
            self.assertIn("refused, the installed lists stay", intel.refresh(force=True))
        self.assertEqual(program.stolen_certificates(), {THUMB: "test entry"})


# ---- update.bat ----

def release_zip(version, extra=None, init_version=None, prefix=None):
    files = {"blotter/__init__.py": f'__version__ = "{init_version or version}"\n', "blotter/app.py": "new\n",
             "setup.bat": "@echo off\r\nnew\r\n", "requirements.txt": "same\n", **(extra or {})}
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        for name, text in files.items():
            z.writestr((prefix if prefix is not None else f"blotter-{version}/") + name, text)
    return data.getvalue()


def publish(key, tag_version, body, manifest_version=None, signed=True, purpose=signing.RELEASE, tamper=False):
    base = f"blotter-{tag_version}"
    manifest = {"kind": "blotter-release", "format": 1, "version": manifest_version or tag_version,
                "commit": "0" * 40, "zip": f"blotter-{manifest_version or tag_version}.zip", "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(), "changes": ["Better things."]}
    m = json.dumps(manifest).encode()
    url = "https://github.com/notblindmedia/blotter/releases/download/v" + tag_version + "/"
    files = {url + base + ".json": m.replace(b"Better", b"Worse") if tamper else m,
             url + manifest["zip"]: body}
    assets = [{"name": base + ".json"}, {"name": manifest["zip"]}]
    if signed:
        files[url + base + ".json.sig"] = signing.sign(key, purpose, m).encode()
        assets.append({"name": base + ".json.sig"})
    for a in assets:
        a["browser_download_url"] = url + a["name"]
    release = {"tag_name": "v" + tag_version, "draft": False, "prerelease": False, "assets": assets}
    return release, files


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.key, public = new_key()
        for patch in (mock.patch.object(signing, "CODE_KEY", public),
                      mock.patch.object(selfupdate, "_running", return_value=False)):
            patch.start()
            self.addCleanup(patch.stop)
        self.root = Path(tempfile.mkdtemp())
        (self.root / "blotter").mkdir()
        (self.root / "blotter" / "__init__.py").write_text('__version__ = "0.2.0"\n')
        (self.root / "blotter" / "old_only.py").write_text("old")
        (self.root / "setup.bat").write_text("old")
        (self.root / "requirements.txt").write_bytes(b"same\n")
        (self.root / ".venv").mkdir()
        (self.root / ".venv" / "keep").write_text("venv")

    def update(self, releases, files, answer="y"):
        asked = []
        web = {selfupdate.RELEASES: releases, **files}
        out = io.StringIO()
        with fake_web(web) as get, contextlib.redirect_stdout(out):
            code = selfupdate.run(root=self.root, current="0.2.0", ask=lambda q: asked.append(q) or answer)
        self.out, self.asked, self.fetched = out.getvalue(), asked, [c.args[0] for c in get.call_args_list]
        return code

    def unchanged(self):
        self.assertEqual((self.root / "setup.bat").read_text(), "old")
        self.assertTrue((self.root / "blotter" / "old_only.py").is_file())
        self.assertEqual((self.root / ".venv" / "keep").read_text(), "venv")

    def test_installs_a_newer_signed_release_after_yes(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        self.assertEqual(self.update([release], files), 0)
        self.assertIn("Better things.", self.out)
        self.assertEqual(len(self.asked), 1)
        self.assertEqual((self.root / "setup.bat").read_bytes(), b"@echo off\r\nnew\r\n")
        self.assertFalse((self.root / "blotter" / "old_only.py").exists(), "the old program folder is replaced")
        self.assertEqual((self.root / ".update-old" / "setup.bat").read_text(), "old")
        self.assertEqual((self.root / ".venv" / "keep").read_text(), "venv")
        self.assertFalse((self.root / ".update-new").exists())

    def test_changed_requirements_ask_update_bat_for_the_packages(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0", {"requirements.txt": "more\n"}))
        self.assertEqual(self.update([release], files), selfupdate.REQUIREMENTS_CHANGED)

    def test_no_means_nothing_downloaded_or_changed(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        self.assertEqual(self.update([release], files, answer=""), 0)
        self.assertFalse(any(u.endswith(".zip") for u in self.fetched))
        self.unchanged()

    def test_unsigned_tampered_or_wrongly_signed_releases_are_refused(self):
        pack_key, _ = new_key()
        body = release_zip("0.3.0")
        for kwargs in ({"signed": False}, {"tamper": True}, {"purpose": signing.PACK}):
            release, files = publish(self.key, "0.3.0", body, **kwargs)
            self.assertEqual(self.update([release], files), 1, kwargs)
            self.assertIn("Update refused", self.out)
            self.assertEqual(self.asked, [], "nothing is offered before the signature checks out")
            self.unchanged()
        release, files = publish(pack_key, "0.3.0", body)  # signed, but not with the release key
        self.assertEqual(self.update([release], files), 1)
        self.unchanged()

    def test_a_changed_zip_is_refused_after_yes(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        files[next(u for u in files if u.endswith(".zip"))] = release_zip("0.3.0", {"blotter/evil.py": "x"})
        self.assertEqual(self.update([release], files), 1)
        self.assertIn("doesn't match the signed checksum", self.out)
        self.unchanged()

    def test_older_versions_are_never_installed(self):
        old, files = publish(self.key, "0.1.9", release_zip("0.1.9"))
        same, more = publish(self.key, "0.2.0", release_zip("0.2.0"))
        self.assertEqual(self.update([old, same], {**files, **more}), 0)
        self.assertIn("newest version", self.out)
        self.assertEqual(self.asked, [])
        # An old signed manifest under a new tag: the signed version decides.
        release, files = publish(self.key, "0.9.0", release_zip("0.1.9"), manifest_version="0.1.9")
        self.assertEqual(self.update([release], files), 1)
        self.assertIn("is for version 0.1.9", self.out)
        self.unchanged()
        with self.assertRaises(selfupdate.Refused):
            selfupdate.check(old, (0, 2, 0))

    def test_drafts_and_pre_releases_dont_count(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        for flag in ("draft", "prerelease"):
            self.assertEqual(self.update([{**release, flag: True}], files), 0)
            self.assertIn("newest version", self.out)
        self.unchanged()

    def test_no_release_key_built_in_means_no_update(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        with mock.patch.object(signing, "CODE_KEY", ""):
            self.assertEqual(self.update([release], files), 1)
        self.assertIn("no valid public key", self.out)
        self.unchanged()

    def test_git_copies_and_a_running_blotter_are_left_alone(self):
        release, files = publish(self.key, "0.3.0", release_zip("0.3.0"))
        (self.root / ".git").mkdir()
        self.assertEqual(self.update([release], files), 1)
        self.assertIn("developer copy", self.out)
        (self.root / ".git").rmdir()
        with mock.patch.object(selfupdate, "_running", return_value=True):
            self.assertEqual(self.update([release], files), 1)
        self.assertIn("Close Blotter", self.out)
        self.assertEqual(self.fetched, [])
        self.unchanged()

    def test_strange_zips_are_refused(self):
        for body in (release_zip("0.3.0", {"../evil.bat": "x"}), release_zip("0.3.0", {".venv/evil": "x"}),
                     release_zip("0.3.0", prefix=""), release_zip("0.3.0", init_version="0.9.9"),
                     release_zip("0.3.0", {"C:/evil": "x"})):
            manifest = {"version": "0.3.0", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            with self.assertRaises(selfupdate.Refused):
                selfupdate.install(self.root, body, manifest)
            self.unchanged()

    def test_a_failed_swap_puts_the_old_version_back(self):
        body = release_zip("0.3.0")
        manifest = {"version": "0.3.0", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        real = os.replace

        def flaky(source, target):
            if Path(target) == self.root / "setup.bat":
                raise OSError(13, "in use", str(target))
            real(source, target)

        with mock.patch.object(selfupdate, "_move", side_effect=flaky):
            with self.assertRaises(selfupdate.Refused):
                selfupdate.install(self.root, body, manifest)
        self.unchanged()
        self.assertEqual((self.root / "blotter" / "__init__.py").read_text(), '__version__ = "0.2.0"\n')
        self.assertEqual((self.root / "requirements.txt").read_text(), "same\n")

    def test_update_bat_runs_as_one_block(self):
        lines = (ROOT / "update.bat").read_text(encoding="utf-8").splitlines()
        start = lines.index("(")
        self.assertEqual(lines[-1], ")")
        block = lines[start:]
        self.assertTrue(any(line.strip() == "exit /b" for line in block))
        for line in block:
            if line.strip().lower().startswith("echo"):
                self.assertNotRegex(line, r"[()]", "a bracket in an echo line ends the block early")
        self.assertIn("-m blotter.selfupdate", "\n".join(block))


# ---- building and signing a release ----

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


class ReleaseBuildTests(unittest.TestCase):
    def repo(self, extra=None):
        repo = Path(tempfile.mkdtemp())
        files = {"blotter/__init__.py": '__version__ = "0.3.0"\n', "setup.bat": "@echo off\r\n",
                 "CHANGES.txt": "WHAT CHANGED\r\n\r\n0.3.0\r\n- One.\r\n- Two, which goes\r\n  on.\r\n\r\n0.2.0\r\n- Old.\r\n",
                 "tests/test_x.py": "", "tools/make_release.py": "", "tools/sign-release/sign_release.py": "",
                 "tools/false_alarm_test.py": "", **(extra or {})}
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(text.encode())
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "x")
        return repo

    def test_build_is_reproducible_and_leaves_out_tests_and_tools(self):
        repo = self.repo()
        a, b = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        m = make_release.build(repo, a)
        make_release.build(repo, b)
        self.assertEqual((a / "blotter-0.3.0.zip").read_bytes(), (b / "blotter-0.3.0.zip").read_bytes())
        self.assertEqual(m["changes"], ["One.", "Two, which goes on."])
        body = (a / "blotter-0.3.0.zip").read_bytes()
        self.assertEqual(m["sha256"], hashlib.sha256(body).hexdigest())
        with zipfile.ZipFile(a / "blotter-0.3.0.zip") as z:
            names = z.namelist()
            self.assertEqual(z.read("blotter-0.3.0/setup.bat"), b"@echo off\r\n")
        self.assertEqual(sorted(names), ["blotter-0.3.0/CHANGES.txt", "blotter-0.3.0/blotter/__init__.py",
                                         "blotter-0.3.0/setup.bat", "blotter-0.3.0/tools/false_alarm_test.py"])
        self.assertEqual(json.loads((a / "blotter-0.3.0.json").read_text())["version"], "0.3.0")

    def test_refuses_unsaved_work_private_files_and_missing_notes(self):
        repo = self.repo()
        (repo / "setup.bat").write_text("changed")
        with self.assertRaises(make_release.ReleaseError):
            make_release.build(repo, Path(tempfile.mkdtemp()))
        for extra in ({"notes/STATUS.md": "private"}, {"keys/release.pem": "x"}):
            with self.assertRaises(make_release.ReleaseError, msg=extra):
                make_release.build(self.repo(extra), Path(tempfile.mkdtemp()))
        repo = self.repo({"blotter/__init__.py": '__version__ = "0.4.0"\n'})
        with self.assertRaises(make_release.ReleaseError):
            make_release.build(repo, Path(tempfile.mkdtemp()))

    def test_real_changes_file_parses(self):
        text = (ROOT / "CHANGES.txt").read_text(encoding="utf-8")
        self.assertTrue(make_release.changes(text, "next"))

    def test_kit_key_signs_and_update_bat_accepts_end_to_end(self):
        kit = Path(tempfile.mkdtemp())
        key_file = kit / "blotter-release-key.pem"
        phrase = "correct horse battery"
        public = sign_release.new_key(key_file, ask=lambda _: phrase)
        self.assertIn(b"ENCRYPTED", key_file.read_bytes())
        self.assertIn(public, (kit / "blotter-release-key.pub.txt").read_text())
        with self.assertRaises(sign_release.Stop):
            sign_release.new_key(key_file, ask=lambda _: phrase)  # never replaced

        out = Path(tempfile.mkdtemp())
        make_release.build(self.repo(), out)
        manifest = out / "blotter-0.3.0.json"
        with quiet():
            with self.assertRaises(sign_release.Stop):
                sign_release.sign(manifest, key_file, ask=lambda _: "wrong passphrase!", confirm=lambda _: "y")
            with self.assertRaises(sign_release.Stop):
                sign_release.sign(manifest, key_file, ask=lambda _: phrase, confirm=lambda _: "n")
            sig = sign_release.sign(manifest, key_file, ask=lambda _: phrase, confirm=lambda _: "y")
        signing.verify(public, signing.RELEASE, manifest.read_bytes(), sig.read_text())

        zip_path = out / "blotter-0.3.0.zip"
        url = "https://github.com/notblindmedia/blotter/releases/download/v0.3.0/"
        release = {"tag_name": "v0.3.0", "assets": [{"name": p.name, "browser_download_url": url + p.name}
                                                     for p in (manifest, sig, zip_path)]}
        files = {url + p.name: p.read_bytes() for p in (manifest, sig, zip_path)}
        with mock.patch.object(signing, "CODE_KEY", public), fake_web(files):
            m, zip_url = selfupdate.check(release, (0, 2, 0))
        self.assertEqual(zip_url, url + zip_path.name)
        self.assertEqual(m["sha256"], hashlib.sha256(zip_path.read_bytes()).hexdigest())

    def test_kit_refuses_a_zip_that_doesnt_match(self):
        out = Path(tempfile.mkdtemp())
        make_release.build(self.repo(), out)
        with open(out / "blotter-0.3.0.zip", "ab") as f:
            f.write(b"x")
        with self.assertRaises(sign_release.Stop):
            sign_release.check_release(out / "blotter-0.3.0.json")


# ---- the page: browsers must not offer to save keys or archive passwords ----

class SecretFieldTests(unittest.TestCase):
    def test_no_password_fields_only_masked_text_fields(self):
        """A password-type field makes Edge and Chrome offer to save what was typed (into the user's account)."""
        page = (ROOT / "blotter" / "static" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(page, r'type="password"')
        fields = re.findall(r"<input[^>]*>", page)
        for name in ("key-virustotal", "key-malwarebazaar", "archive-password"):
            [field] = [f for f in fields if f'id="{name}"' in f]
            for attribute in ('class="secret"', 'type="text"', 'autocomplete="off"', 'data-lpignore="true"'):
                self.assertIn(attribute, field, name)
        self.assertIn("-webkit-text-security: disc", (ROOT / "blotter" / "static" / "style.css").read_text(encoding="utf-8"))


# ---- setup.bat's key step ----

class KeySetupTests(unittest.TestCase):
    def test_paste_or_skip_each_key(self):
        answers = iter(["has space in it", "a" * 64, ""])

        def put(name, value):
            if " " in value:
                raise ValueError("That doesn't look like an API key.")

        with mock.patch.object(keysetup.keys, "backend_ok", return_value=True), \
                mock.patch.object(keysetup.keys, "put", side_effect=put) as put, \
                mock.patch.object(keysetup.settings, "update") as update, quiet():
            self.assertEqual(keysetup.run(ask=lambda _: next(answers)), 0)
        self.assertEqual([c.args[0] for c in put.call_args_list], ["virustotal", "virustotal"])
        update.assert_called_once_with({"setup_done": True})

    def test_skipping_everything_saves_nothing(self):
        with mock.patch.object(keysetup.keys, "backend_ok", return_value=True), \
                mock.patch.object(keysetup.keys, "put") as put, \
                mock.patch.object(keysetup.settings, "update") as update, quiet():
            keysetup.run(ask=lambda _: "")
        put.assert_not_called()
        update.assert_not_called()


if __name__ == "__main__":
    unittest.main()
