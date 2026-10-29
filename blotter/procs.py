"""Run helper programs inside a Windows "job object".

A job object is a box around a process and everything it starts. Blotter uses it so that
- a check that hangs is killed together with anything it started (capa, PowerShell),
- a check that blows up in memory (a file built to choke a parser) is stopped at a limit,
- ClamAV, which Blotter starts, ends when Blotter ends, even if Blotter's window is just closed.
No admin rights are needed for any of this.
"""

import ctypes
import subprocess
import sys
import threading
from ctypes import wintypes

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
BELOW_NORMAL = 0x4000  # BELOW_NORMAL_PRIORITY_CLASS: the deep check yields the CPU to everything else

_KILL_ON_CLOSE = 0x2000
_PRIORITY_CLASS = 0x20
_JOB_MEMORY = 0x200
_DIE_ON_UNHANDLED_EXCEPTION = 0x400
_EXTENDED_LIMIT_INFORMATION = 9


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    _k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    _k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _k32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _k32.CloseHandle.argtypes = (wintypes.HANDLE,)


class Job:
    """Processes added to a Job die when the Job is closed (or when Blotter exits). With `priority`
    (BELOW_NORMAL), every process in it, and everything they start, runs at that priority."""

    def __init__(self, memory_limit: int | None = None, priority: int | None = None):
        self.handle = None
        if sys.platform != "win32":
            return
        handle = _k32.CreateJobObjectW(None, None)
        if not handle:
            return
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = _KILL_ON_CLOSE | _DIE_ON_UNHANDLED_EXCEPTION
        if memory_limit:
            info.BasicLimitInformation.LimitFlags |= _JOB_MEMORY
            info.JobMemoryLimit = memory_limit
        if priority:
            info.BasicLimitInformation.LimitFlags |= _PRIORITY_CLASS
            info.BasicLimitInformation.PriorityClass = priority
        if not _k32.SetInformationJobObject(handle, _EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)):
            _k32.CloseHandle(handle)
            return
        self.handle = handle

    def add(self, popen: subprocess.Popen) -> bool:
        return self.add_handle(int(popen._handle))

    def add_handle(self, process_handle) -> bool:
        if not self.handle:
            return False
        return bool(_k32.AssignProcessToJobObject(self.handle, process_handle))

    def kill(self) -> None:
        if self.handle:
            _k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)
            self.handle = None


def run(command, input_bytes=b"", timeout=60, memory_limit=None, env=None, priority=None, cancel=None):
    """Run a command in its own job. Returns (exit code or None if it timed out, stdout bytes, stderr bytes).
    `cancel` (a threading.Event) stops it early, like a timeout."""
    job = Job(memory_limit, priority)
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=NO_WINDOW | (priority or 0), env=env)
    job.add(proc)
    finished = threading.Event()
    if cancel is not None:  # watch for a cancel while communicate() waits
        threading.Thread(target=_watch, args=(cancel, finished, job, proc), daemon=True).start()
    try:
        out, err = proc.communicate(input_bytes, timeout=timeout)
        if cancel is not None and cancel.is_set():
            return None, out, err
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        job.kill()
        proc.kill()
        out, err = proc.communicate()
        return None, out, err
    finally:
        finished.set()
        job.close()


def _watch(cancel, finished, job, proc) -> None:
    while not finished.wait(0.25):
        if cancel.is_set():
            job.kill()
            proc.kill()
            return
