"""Test helper for the worker process: misbehaves on purpose, depending on the file's text.

Not a real check: the leading underscore keeps it out of load_checks(). Only tests use it.
"""

import os
import socket
import time

from ..findings import CLEAR, Finding


def scan(path):
    action = open(path, "rb").read().strip()
    if action == b"sleep":
        time.sleep(120)
    elif action == b"crash":
        raise RuntimeError("broken on purpose")
    elif action == b"memory":
        hog = bytearray(1500 * 1024 * 1024)  # more than the test's memory limit
        del hog
    elif action == b"exit":
        os._exit(3)
    elif action == b"print":
        print("noise that must not confuse the runner")
    elif action.startswith(b"net "):  # net <host> <port>
        _, host, port = action.decode().split()
        try:
            socket.create_connection((host, int(port)), timeout=5).close()
            return [Finding("probe", CLEAR, "network: open")]
        except OSError as e:
            return [Finding("probe", CLEAR, f"network: blocked ({type(e).__name__})")]
    elif action.startswith(b"read "):  # read <path>
        try:
            open(action[5:].decode(), "rb").read(1)
            return [Finding("probe", CLEAR, "read: allowed")]
        except OSError as e:
            return [Finding("probe", CLEAR, f"read: blocked ({type(e).__name__})")]
    elif action.startswith(b"write "):  # write <path>
        try:
            open(action[6:].decode(), "wb").write(b"x")
            return [Finding("probe", CLEAR, "write: allowed")]
        except OSError as e:
            return [Finding("probe", CLEAR, f"write: blocked ({type(e).__name__})")]
    return [Finding("probe", CLEAR, "The probe ran fine.")]
