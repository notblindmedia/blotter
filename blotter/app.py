"""The local web app: one page, a small JSON API, reachable only from this PC."""

import hashlib
import hmac
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, clamav, config, keys, network, procs, quarantine, sandbox, settings, updates
from .cache import Cache
from .checks import load_checks
from .checks.defender import find_scanner
from .runner import Runner
from .trust import TrustList

STATIC = Path(__file__).parent / "static"
VIRUS_BLOCKED = (225, 226)  # Windows: "contains a virus" / "virus deleted" while saving
CHUNK = 1024 * 1024

# A native Windows "Open" dialog, in its own process. Prints the chosen path (or nothing).
PICK = ("import sys, tkinter, tkinter.filedialog as d; sys.stdout.reconfigure(encoding='utf-8'); "
        "r = tkinter.Tk(); r.withdraw(); r.attributes('-topmost', True); "
        "print(d.askopenfilename(title='Choose a file for Blotter to check') or '')")


TOKEN_COOKIE = "blotter_token"
TOKEN_HEADER = "x-blotter-token"
NEEDS_TOKEN_PAGE = """<!doctype html><meta charset="utf-8"><title>Blotter</title>
<body style="font:16px system-ui;max-width:560px;margin:60px auto;padding:0 16px">
<h1>Open Blotter from its window</h1>
<p>For your safety Blotter only answers pages it opened itself, with a code that changes every time it
starts. Double-click <b>Start Blotter.bat</b> again; it opens this page with the right code.</p></body>"""


def create_app(checks=None, cache=None, trust=None, token=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    token = token or secrets.token_urlsafe(32)  # new every start; see __main__.py
    app.state.token = token
    trust = trust or TrustList(config.TRUST_PATH)
    runner = Runner(cache or Cache(config.DB_PATH), checks if checks is not None else load_checks(), trust=trust)
    hosts = {f"127.0.0.1:{config.PORT}", f"localhost:{config.PORT}"}
    origins = {f"http://{h}" for h in hosts}
    update_state = {"running": False, "lines": [], "at": None}

    def refuse(why: str):
        return JSONResponse({"app": "blotter", "error": f"Request refused: {why}."}, status_code=403)

    def valid(value) -> bool:
        return bool(value) and hmac.compare_digest(str(value).encode(), token.encode())

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        # Other websites open in the browser, and other programs, must not be able to use Blotter.
        if request.headers.get("host", "") not in hosts:
            return refuse("Blotter only answers on this PC, at its own address")
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return refuse("it came from another website")
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return refuse("it came from another website")
        if request.method == "GET" and request.url.path == "/" and "token" in request.query_params:
            if not valid(request.query_params["token"]):
                return HTMLResponse(NEEDS_TOKEN_PAGE, status_code=403)
            # Swap the code in the address for a cookie only this site can use, and drop it from the address.
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(TOKEN_COOKIE, token, httponly=True, samesite="strict", path="/")
            response.headers["Cache-Control"] = "no-store"
            return response
        header, cookie = request.headers.get(TOKEN_HEADER), request.cookies.get(TOKEN_COOKIE)
        if request.method in ("GET", "HEAD"):
            if not (valid(header) or valid(cookie)):
                if request.url.path == "/":
                    return HTMLResponse(NEEDS_TOKEN_PAGE, status_code=403)
                return refuse("the Blotter code is missing or out of date")
        elif not valid(header):  # anything that changes something needs the header, a cookie alone isn't enough
            return refuse("the Blotter code is missing or out of date")
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        return response

    @app.get("/")
    def index():
        page = (STATIC / "index.html").read_text(encoding="utf-8")
        meta = f'<meta name="blotter-token" content="{token}">'
        return HTMLResponse(page.replace("<head>", "<head>\n" + meta, 1))

    @app.get("/api/ping")
    def ping():
        return {"app": "blotter", "version": __version__}

    @app.get("/api/status")
    def status():
        scanner = find_scanner()
        forge = config.YARA_FORGE
        return {
            "keys": keys.status(),
            "key_store_ok": keys.backend_ok(),
            "settings": settings.load(),
            "defender": str(scanner) if scanner else None,
            "clamav": clamav.service.status(),
            "sandbox": {"mode": sandbox.mode(), "why": sandbox.public_state().get("why", "")},
            "rules": {
                "yara_forge": time.strftime("%Y-%m-%d", time.localtime(forge.stat().st_mtime)) if forge.is_file() else None,
                "capa": config.CAPA_RULES.is_dir(),
                "updating": update_state["running"],
                "last_update": update_state["lines"],
            },
            "network": {"lookups": network.LOOKUPS, "downloads": network.DOWNLOADS},
            "checks": [{"id": c.ID, "name": c.NAME} for c in runner.checks],
            "trusted": trust.all(),
            "quarantine": quarantine.entries(),
        }

    @app.post("/api/settings")
    async def save_settings(request: Request):
        body = await request.json()
        try:
            new = settings.update(body if isinstance(body, dict) else {})
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        if "clamav" in body:
            if new["clamav"]:
                clamav.service.start()
            else:
                clamav.service.stop()
        return {"settings": new}

    @app.post("/api/keys")
    async def save_key(request: Request):
        body = await request.json()
        if not keys.backend_ok():
            return JSONResponse({"error": "Windows Credential Manager isn't available, so the key was not saved."},
                                status_code=500)
        try:
            keys.put(str(body.get("service", "")), str(body.get("key", "")))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {"keys": keys.status()}

    @app.post("/api/keys/{service}/remove")
    def delete_key(service: str):
        try:
            keys.remove(service)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {"keys": keys.status()}

    @app.post("/api/scan")
    async def scan(request: Request):
        name = urllib.parse.unquote(request.headers.get("x-file-name", ""))[:255] or "unnamed file"
        force = request.headers.get("x-force") == "1"
        declared = int(request.headers.get("content-length") or 0)
        if declared > config.MAX_UPLOAD:
            return JSONResponse({"error": "That file is bigger than 2 GB, which Blotter doesn't handle yet."},
                                status_code=413)
        config.INCOMING.mkdir(parents=True, exist_ok=True)
        # Neutral name and extension: the copy is only ever read as bytes, nothing will open it.
        path = config.INCOMING / f"{uuid.uuid4().hex}.blotter"
        digest, size, save_error, blocked = hashlib.sha256(), 0, None, False
        out = open(path, "wb")
        try:
            async for chunk in request.stream():
                size += len(chunk)
                if size > config.MAX_UPLOAD:
                    out.close()
                    path.unlink(missing_ok=True)
                    return JSONResponse({"error": "That file is bigger than 2 GB."}, status_code=413)
                digest.update(chunk)
                if out and not out.closed:
                    try:
                        out.write(chunk)
                    except OSError as e:
                        blocked, save_error = _save_failed(e, out, path)
        finally:
            if not out.closed:
                try:
                    out.close()
                except OSError as e:
                    blocked, save_error = _save_failed(e, out, path)
        if blocked:
            save_error = None  # Defender stopped the save: the Defender check reports that as a detection
        job = runner.start(path, name, size, digest.hexdigest(), save_error=save_error, force=force)
        return job.to_dict()

    @app.post("/api/scan-path")
    async def scan_path(request: Request):
        """Check a file on this PC by its path. Blotter copies it first and checks the copy."""
        body = await request.json()
        source = Path(str(body.get("path", "")).strip().strip('"'))
        if not source.is_absolute() or not source.is_file():
            return JSONResponse({"error": "That isn't a file Blotter can find. Check the path."}, status_code=400)
        if source.stat().st_size > config.MAX_UPLOAD:
            return JSONResponse({"error": "That file is bigger than 2 GB."}, status_code=413)
        config.INCOMING.mkdir(parents=True, exist_ok=True)
        path = config.INCOMING / f"{uuid.uuid4().hex}.blotter"
        digest, size, save_error = hashlib.sha256(), 0, None
        try:
            with open(source, "rb") as src, open(path, "wb") as out:
                while chunk := src.read(CHUNK):
                    digest.update(chunk)
                    size += len(chunk)
                    try:
                        out.write(chunk)
                    except OSError as e:
                        save_error = e.strerror or str(e)
                        break
        except OSError as e:
            if getattr(e, "winerror", None) in VIRUS_BLOCKED:
                return JSONResponse({"error": "Windows refused to read this file because Microsoft Defender "
                                              "recognises it as a threat."}, status_code=409)
            return JSONResponse({"error": f"Blotter couldn't read that file ({e.strerror or e})."}, status_code=400)
        job = runner.start(path, source.name, size, digest.hexdigest(), save_error=save_error,
                           force=bool(body.get("force")), source_path=str(source))
        return job.to_dict()

    @app.post("/api/pick")
    def pick():
        code, out, _ = procs.run([sys.executable, "-I", "-c", PICK], timeout=600)
        chosen = out.decode("utf-8", "replace").strip() if code == 0 else ""
        return {"path": str(Path(chosen)) if chosen else None}

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        found = runner.get(job_id)
        if not found:
            return JSONResponse({"error": "Unknown scan."}, status_code=404)
        return found.to_dict()

    @app.post("/api/jobs/{job_id}/password")
    async def archive_password(job_id: str, request: Request):
        """A locked archive: check it again with the password the person typed. The password stays in memory."""
        body = await request.json()
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str) or not password or len(password) > 256:
            return JSONResponse({"error": "Type the archive's password first."}, status_code=400)
        new = runner.retry_with_password(job_id, password)
        if not new:
            return JSONResponse({"error": "Blotter no longer has this archive's copy (it keeps it 30 minutes). "
                                          "Check the archive again."}, status_code=404)
        return new.to_dict()

    @app.post("/api/jobs/{job_id}/trust")
    async def trust_job(job_id: str, request: Request):
        found = runner.get(job_id)
        if not found or found.state != "done":
            return JSONResponse({"error": "Unknown or unfinished scan."}, status_code=404)
        body = await request.json()
        if body.get("trusted") and (found.verdict or {}).get("verdict") == "malicious":
            return JSONResponse({"error": "Blotter doesn't let you trust a file that a check recognises as malware."},
                                status_code=409)
        if body.get("trusted"):
            trust.add(found.sha256, found.name)
        else:
            trust.remove(found.sha256)
        runner.rescore(found)
        return found.to_dict()

    @app.post("/api/trusted/{sha256}/remove")
    def untrust(sha256: str):
        trust.remove(sha256.lower())
        return {"trusted": trust.all()}

    @app.post("/api/jobs/{job_id}/quarantine")
    def quarantine_job(job_id: str):
        found = runner.get(job_id)
        if not found or found.state != "done":
            return JSONResponse({"error": "Unknown or unfinished scan."}, status_code=404)
        if not found.source_path:
            return JSONResponse({"error": "Blotter only has a copy of this file (it was dropped on the page), so "
                                          "it can't move the original. Use \"Choose a file on this PC\" instead."},
                                status_code=400)
        try:
            entry = quarantine.put(found.source_path, found.sha256)
        except quarantine.QuarantineError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        found.source_path = None
        return {"entry": entry, "job": found.to_dict()}

    @app.post("/api/quarantine/{entry_id}/restore")
    def restore(entry_id: str):
        try:
            entry = quarantine.restore(entry_id)
        except quarantine.QuarantineError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        return {"entry": entry, "quarantine": quarantine.entries()}

    @app.post("/api/updates")
    def run_updates():
        if update_state["running"]:
            return {"running": True}
        update_state["running"] = True

        def work():
            try:
                update_state["lines"] = updates.rules(force=True)
                from .analyze import yararules
                yararules.load()  # compile here: sandboxed workers can't refresh the cache themselves
            finally:
                update_state.update(running=False, at=time.time())

        threading.Thread(target=work, daemon=True).start()
        return {"running": True}

    @app.get("/favicon.ico")
    def favicon():
        return Response(status_code=204)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def _save_failed(error: OSError, out, path):
    try:
        out.close()
    except OSError:
        pass
    blocked = getattr(error, "winerror", None) in VIRUS_BLOCKED
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return blocked, None if blocked else (error.strerror or str(error))


def clean_incoming() -> None:
    """Remove copies (and unpacked archive folders) left behind if Blotter was closed mid-scan."""
    import shutil
    if config.INCOMING.is_dir():
        for leftover in config.INCOMING.glob("*.blotter"):
            try:
                leftover.unlink()
            except OSError:
                pass
        for folder in config.INCOMING.glob("unpack-*"):
            shutil.rmtree(folder, ignore_errors=True)
