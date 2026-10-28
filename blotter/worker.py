"""Runs one check on one file in a separate Python process, so a file built to crash or hang
a parser can only take down that process, never Blotter itself.

Checks that parse the file (SANDBOX = True, the default) run inside a Windows AppContainer
(sandbox.py): no network, and no access to anything but the one file and its own work folder.
Checks that only hand the file to an antivirus engine (Defender, ClamAV) run as a normal worker.

Each run gets its own work folder in %LOCALAPPDATA%\\Blotter\\incoming. The runner writes
request.json there ({"module", "path", "name", "sha256", "password"}), starts
    python -I -B -c BOOT <request.json>
and reads result.json ({"findings": [...]} or {"error": "..."}). -I (isolated mode) keeps Python from
loading anything from the current folder or user settings; -B stops it writing cache files.
The work folder, with the request in it, is deleted afterwards.
"""

import importlib
import json
import os
import shutil
import site
import sys
import time
import uuid
from pathlib import Path

from . import config, procs, sandbox
from .findings import LEVELS, Finding

PREFIX = "blotter.checks."
# Where Blotter's code and packages are. Worked out once in Blotter itself and handed down
# (BLOTTER_PATHS), because inside the sandbox Python is the private runtime copy without the packages.
if os.environ.get("BLOTTER_PATHS"):
    PATHS = json.loads(os.environ["BLOTTER_PATHS"])
else:
    PATHS = [str(config.ROOT), *(p for p in site.getsitepackages() if p.lower().endswith("site-packages"))]
BOOT = f"import sys; sys.path[:0] = {PATHS!r}; import blotter.worker as w; w.main()"


def command(request_file=None, sandboxed=False) -> list[str]:
    python = sandbox.python() if sandboxed else sys.executable
    return [python, "-I", "-B", "-c", BOOT] + ([str(request_file)] if request_file else [])


def module_command(module: str, args: list[str]) -> list[str]:
    """Run a package's command line (capa) the same way, from inside a worker: `python -m module args`."""
    code = (f"import sys, runpy; sys.path[:0] = {PATHS!r}; sys.argv = [{module!r}] + sys.argv[1:]; "
            f"runpy.run_module({module!r}, run_name='__main__')")
    return [sys.executable, "-I", "-B", "-c", code, *args]


def _env(workdir: Path) -> dict:
    return {**os.environ, "TEMP": str(workdir), "TMP": str(workdir), "BLOTTER_HOME": str(config.HOME),
            "BLOTTER_WORK": str(workdir), "BLOTTER_PATHS": json.dumps(PATHS)}


def run(module: str, path, name, sha256, timeout: float, sandboxed=True, password=None):
    """Run module.scan(path) in a worker. Returns a list of Findings or raises TimeoutError / RuntimeError."""
    workdir = config.INCOMING / f"work-{uuid.uuid4().hex}"
    workdir.mkdir(parents=True)
    try:
        request = workdir / "request.json"
        request.write_text(json.dumps({"module": module, "path": str(path), "name": name, "sha256": sha256,
                                       "password": password}), encoding="utf-8")
        start = time.monotonic()
        if sandboxed:
            sandbox.prepare()
            if sandbox.mode() == "appcontainer" and Path(path).exists():
                sandbox.grant(path, sandbox.sid())  # the one file this check may read
            code = sandbox.run(command(request, sandboxed=True), workdir, _env(workdir), timeout,
                               memory_limit=config.WORKER_MEMORY)
            err = b""
        else:
            code, _, err = procs.run(command(request), timeout=timeout, memory_limit=config.WORKER_MEMORY,
                                     env=_env(workdir))
        if code is None:
            raise TimeoutError(f"after {time.monotonic() - start:.0f} s")
        result = workdir / "result.json"
        if not result.is_file():
            tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [f"exit code {code}"]
            raise RuntimeError(f"the worker stopped without an answer ({tail[0][:200]})")
        answer = json.loads(result.read_text(encoding="utf-8"))
        if "error" in answer:
            raise RuntimeError(answer["error"])
        return [Finding.from_dict(d) for d in answer["findings"]]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> None:
    request_file = Path(sys.argv[1])
    sys.stdout = sys.stderr  # nothing goes to stdout; the answer is result.json
    try:
        request = json.loads(request_file.read_text(encoding="utf-8"))
        module_name = request["module"]
        if not module_name.startswith(PREFIX) or not module_name[len(PREFIX):].isidentifier():
            raise ValueError("not a Blotter check")
        from . import hashing
        hashing.remember(request["path"], request["sha256"], request.get("name"), request.get("password"))
        module = importlib.import_module(module_name)
        findings = module.scan(request["path"])
        if not all(isinstance(f, Finding) and f.level in LEVELS for f in findings):
            raise ValueError("bad findings")
        answer = {"findings": [f.to_dict() for f in findings]}
    except Exception as e:  # report, don't crash: the runner turns this into "Couldn't check"
        answer = {"error": f"{type(e).__name__}: {e}"[:300]}
    (request_file.parent / "result.json").write_text(json.dumps(answer), encoding="utf-8")
    os._exit(0)  # skip slow interpreter shutdown (capa and vivisect leave a lot behind)
