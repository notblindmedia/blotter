"""Run helper programs inside a Windows "job object".

A job object is a box around a process and everything it starts. Blotter uses it so that
- a check that hangs is killed together with anything it started (capa, PowerShell),
- a check that blows up in memory (a file built to choke a parser) is stopped at a limit,
- ClamAV, which Blotter starts, ends when the last Blotter using it ends, even if its window is just closed or it
  crashes (a named job: every Blotter on this PC that uses ClamAV holds it, and Windows ends ClamAV with the last hold).
No admin rights are needed for any of this.
"""

import contextlib
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
_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_QUERY = 0x4
_WAIT_ABANDONED = 0x80  # the last holder crashed: Windows hands the lock on
_QUERY_LIMITED_INFORMATION = 0x1000
_TCP_TABLE_OWNER_PID_LISTENER = 3
_AF_INET = 2


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


class _Accounting(ctypes.Structure):
    _fields_ = [(n, ctypes.c_int64) for n in ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime",
                                              "ThisPeriodTotalKernelTime")] +               [(n, wintypes.DWORD) for n in ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses",
                                             "TotalTerminatedProcesses")]


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
    _k32.QueryInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.c_void_p)
    _k32.OpenJobObjectW.restype = wintypes.HANDLE
    _k32.OpenJobObjectW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
    _k32.CreateMutexW.restype = wintypes.HANDLE
    _k32.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _k32.ReleaseMutex.argtypes = (wintypes.HANDLE,)
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _k32.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD))
    _iphlp = ctypes.WinDLL("iphlpapi")
    _iphlp.GetExtendedTcpTable.restype = wintypes.DWORD
    _iphlp.GetExtendedTcpTable.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                           wintypes.ULONG, ctypes.c_int, wintypes.ULONG)


class Job:
    """Processes added to a Job die when the Job is closed (or when Blotter exits). With `priority`
    (BELOW_NORMAL), every process in it, and everything they start, runs at that priority. With a `name`, every
    process on this PC that makes a Job with that name holds the same one: it is closed, and its processes die,
    when the last of them closes it or ends."""

    def __init__(self, memory_limit: int | None = None, priority: int | None = None, name: str | None = None):
        self.handle = None
        if sys.platform != "win32":
            return
        handle = _k32.CreateJobObjectW(None, name)
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

    def active(self) -> int:
        """How many processes run in it now."""
        info = _Accounting()
        if not self.handle or not _k32.QueryInformationJobObject(self.handle, _BASIC_ACCOUNTING_INFORMATION,
                                                                 ctypes.byref(info), ctypes.sizeof(info), None):
            return 0
        return info.ActiveProcesses

    @staticmethod
    def held(name: str) -> bool:
        """True while some process still holds the named Job."""
        if sys.platform != "win32":
            return False
        handle = _k32.OpenJobObjectW(_JOB_OBJECT_QUERY, False, name)
        if handle:
            _k32.CloseHandle(handle)
        return bool(handle)

    def kill(self) -> None:
        if self.handle:
            _k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)
            self.handle = None


@contextlib.contextmanager
def named_lock(name: str, timeout=60):
    """One process on this PC at a time (a named Windows mutex; if its holder crashes, Windows lets the next one in)."""
    if sys.platform != "win32":
        yield
        return
    handle = _k32.CreateMutexW(None, False, name)
    if not handle:
        raise OSError(ctypes.get_last_error(), "couldn't create the lock")
    try:
        if _k32.WaitForSingleObject(handle, int(timeout * 1000)) not in (0, _WAIT_ABANDONED):
            raise TimeoutError(f"another program held the lock for over {timeout} seconds")
        try:
            yield
        finally:
            _k32.ReleaseMutex(handle)
    finally:
        _k32.CloseHandle(handle)


def listeners(port: int) -> list[int]:
    """Process IDs listening for TCP connections on this port (IPv4, on 127.0.0.1 or every address)."""
    if sys.platform != "win32":
        return []
    size = wintypes.DWORD(0)
    for _ in range(5):  # the table can grow between asking for its size and reading it
        buffer = ctypes.create_string_buffer(size.value or 1)
        code = _iphlp.GetExtendedTcpTable(buffer, ctypes.byref(size), False, _AF_INET,
                                          _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if code == 0:
            break
        if code != 122:  # ERROR_INSUFFICIENT_BUFFER
            raise OSError(code, "couldn't read the list of listening ports")
    else:
        raise OSError(122, "couldn't read the list of listening ports")
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(ctypes.addressof(buffer) + 4, ctypes.POINTER(wintypes.DWORD * 6))
    found = []
    for i in range(count):
        _, address, row_port, _, _, pid = rows[i]
        if ((row_port & 0xFF) << 8 | (row_port >> 8) & 0xFF) == port and address in (0, 0x0100007F):
            found.append(pid)
    return found


def program_path(pid: int) -> str | None:
    """The full path of the program a process runs, or None when Windows won't say."""
    if sys.platform != "win32":
        return None
    handle = _k32.OpenProcess(_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        return buffer.value if _k32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)) else None
    finally:
        _k32.CloseHandle(handle)


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
