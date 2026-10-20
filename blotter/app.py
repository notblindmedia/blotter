"""The local web app: one page, a small JSON API, reachable only from this PC."""

import hashlib
import urllib.parse
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, config, keys
from .cache import Cache
from .checks import load_checks
from .checks.defender import find_scanner
from .runner import Runner

STATIC = Path(__file__).parent / "static"
VIRUS_BLOCKED = (225, 226)  # Windows: "contains a virus" / "virus deleted" while saving


def create_app(checks=None, cache=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    runner = Runner(cache or Cache(config.DB_PATH), checks if checks is not None else load_checks())
    hosts = {f"127.0.0.1:{config.PORT}", f"localhost:{config.PORT}"}
    origins = {f"http://{h}" for h in hosts}

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        # Other websites open in the browser must not be able to use Blotter.
        if request.headers.get("host", "") not in hosts:
            return JSONResponse({"error": "Blotter only answers on this PC."}, status_code=403)
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if request.headers.get("x-blotter") != "1" or (origin and origin not in origins):
                return JSONResponse({"error": "Request refused."}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        return response

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/ping")
    def ping():
        return {"app": "blotter", "version": __version__}

    @app.get("/api/status")
    def status():
        scanner = find_scanner()
        return {
            "keys": keys.status(),
            "key_store_ok": keys.backend_ok(),
            "defender": str(scanner) if scanner else None,
            "checks": [{"id": c.ID, "name": c.NAME} for c in runner.checks],
        }

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

    @app.delete("/api/keys/{service}")
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

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        found = runner.get(job_id)
        if not found:
            return JSONResponse({"error": "Unknown scan."}, status_code=404)
        return found.to_dict()

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
    """Remove copies left behind if Blotter was closed mid-scan."""
    if config.INCOMING.is_dir():
        for leftover in config.INCOMING.glob("*.blotter"):
            try:
                leftover.unlink()
            except OSError:
                pass
