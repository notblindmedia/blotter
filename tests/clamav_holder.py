"""A stand-in Blotter for test_clamav_shared.py: holds ClamAV through clamav.Service like the app does, with a fake
clamd (this file with --fake-clamd: answers PING and VERSION on Blotter's ClamAV port, nothing else). Reads one
command per line (wake, release, idle, stop) and answers each with the service's state."""

import os
import socketserver
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # runs as a plain script, not from the tests package

from blotter import clamav, config  # noqa: E402


class _Answer(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while not data.endswith(b"\0") and (chunk := self.request.recv(64)):
            data += chunk
        reply = {b"zPING\0": b"PONG", b"zVERSION\0": b"ClamAV 0.0.0/1/fake"}.get(data, b"UNKNOWN COMMAND")
        self.request.sendall(reply + b"\0")


def fake_clamd():
    with open(config.HOME / "fake-clamd-starts.txt", "a", encoding="ascii") as f:
        f.write(f"{os.getpid()}\n")
    with socketserver.ThreadingTCPServer(("127.0.0.1", config.CLAMD_PORT), _Answer) as server:
        server.serve_forever()


def wait_for(service, states, timeout=30):
    deadline = time.monotonic() + timeout
    while service.state not in states and time.monotonic() < deadline:
        time.sleep(0.05)


def holder():
    clamav.installed = lambda: True
    clamav.has_signatures = lambda: True
    clamav.signatures_age = lambda: 0
    clamav.TICK = 0.1
    clamav.clamd_command = lambda conf: [sys.executable, str(Path(__file__)), "--fake-clamd"]
    config.CLAMAV_DIR.mkdir(parents=True, exist_ok=True)
    service = clamav.Service()
    for line in sys.stdin:
        command = line.strip()
        if command == "wake":
            service.wake()
            wait_for(service, ("ready", "failed"))
        elif command == "release":
            service.release()
        elif command == "idle":
            clamav.IDLE_STOP = 0
            service.release()
            wait_for(service, ("sleeping",))
        elif command == "stop":
            service.stop("stopped")
        print(service.state, flush=True)


if __name__ == "__main__":
    fake_clamd() if "--fake-clamd" in sys.argv else holder()
