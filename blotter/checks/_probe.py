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
    elif action in (b"eicar-engines", b"eicar-engines-unnamed"):
        return _eicar_engines(named=action == b"eicar-engines")
    return [Finding("probe", CLEAR, "The probe ran fine.")]


def _eicar_engines(named: bool):
    """What Defender, ClamAV and YARA report for EICAR, made by their real code inside this worker.
    EICAR stays in memory (on disk, Defender would remove it)."""
    from ..analyze import yararules
    from . import clamav, defender
    eicar = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"]).encode()
    if named:
        found = defender.interpret(2, "Found 1 threats.\r\nThreat                  : Virus:DOS/EICAR_Test_File\r\n",
                                   still_there=False)
    else:
        found = defender.interpret(2147942402, "CmdTool: Failed with hr = 0x80070002", still_there=False)
    found += clamav.interpret("stream: Eicar-Test-Signature FOUND", "ClamAV 1.5.4/28167/Wed Oct 28 07:24:17 2026")
    found += yararules.scan_target(yararules.load(), "yara", data=eicar)
    return found
