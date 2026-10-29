"""Run file-reading workers in a Windows AppContainer: no network, and no access to your files.

An AppContainer is the sandbox Windows uses for Store apps. A process inside one
- has no network at all (Blotter gives it no capabilities, so not even internetClient),
- can only open files and folders whose permissions name the container: Windows' own system files
  (readable by every container) plus what Blotter grants below, nothing in your user folders.
No admin rights are needed: creating the container and granting it access to Blotter's own folders
is allowed for a normal user.

What the container may read: Blotter's private copy of the Python runtime (%LOCALAPPDATA%\\Blotter\\runtime),
the Blotter program folder (code, its packages, our rules), the downloaded rules, and the ONE file
being checked. What it may write: its own work folder for that one check (deleted afterwards).

If the container can't be created, Blotter falls back to a low-integrity restricted token: the worker
then can't write anywhere outside its work folder or change anything on the PC, but it can still read
files and reach the network. The status page says which one is in use.
"""

import ctypes
import os
import shutil
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

from . import config, procs

NAME = "Blotter.Checker"
# Shared by every Blotter folder setting (tests too), so the runtime is copied and granted only once.
SHARED = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Blotter"
RUNTIME = SHARED / "runtime"
GRANTS = SHARED / "sandbox-grants.txt"
ICACLS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"

_EXTENDED_STARTUPINFO = 0x00080000
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_SECURITY_CAPABILITIES_ATTR = 0x00020009
_ALREADY_EXISTS = 0x800700B7 - 2 ** 32
_LOW_INTEGRITY = "S-1-16-4096"
_lock = threading.Lock()
_state = {"mode": None, "sid": None, "why": ""}


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]


class _StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _env = ctypes.WinDLL("userenv")
    _env.CreateAppContainerProfile.restype = ctypes.c_long
    _env.CreateAppContainerProfile.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                               ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
    _env.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    _env.DeriveAppContainerSidFromAppContainerName.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    _adv.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    _adv.ConvertStringSidToSidW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    _k32.InitializeProcThreadAttributeList.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                       ctypes.POINTER(ctypes.c_size_t))
    _k32.UpdateProcThreadAttribute.argtypes = (ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                               ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p)
    _k32.DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
    _k32.CreateProcessW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                    ctypes.c_void_p, ctypes.POINTER(_ProcessInfo))
    _adv.CreateProcessAsUserW.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                          ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(_ProcessInfo))
    _adv.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    _adv.CreateRestrictedToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.POINTER(wintypes.HANDLE))
    _adv.SetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    _adv.GetLengthSid.argtypes = (ctypes.c_void_p,)
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    _k32.ResumeThread.argtypes = (wintypes.HANDLE,)
    _k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _k32.CloseHandle.argtypes = (wintypes.HANDLE,)


def _container_sid():
    sid = ctypes.c_void_p()
    hr = _env.CreateAppContainerProfile(NAME, "Blotter file checker", "Blotter reads files here, sandboxed",
                                        None, 0, ctypes.byref(sid))
    if hr == _ALREADY_EXISTS:
        hr = _env.DeriveAppContainerSidFromAppContainerName(NAME, ctypes.byref(sid))
    if hr != 0:
        raise OSError(f"AppContainer not available (0x{hr & 0xFFFFFFFF:08x})")
    text = wintypes.LPWSTR()
    if not _adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    return sid, text.value


def _icacls(path, *args):
    result = subprocess.run([str(ICACLS), str(path), *args], capture_output=True,
                            creationflags=procs.NO_WINDOW, timeout=600)
    if result.returncode:
        raise OSError(f"icacls {path}: {result.stdout.decode('mbcs', 'replace').strip()[-200:]}")


def grant(path, sid, write=False, inherit=True):
    """Let the container read (or also write) one file or folder of Blotter's own."""
    rights = "(M)" if write else "(RX)"
    flags = "(OI)(CI)" if inherit and Path(path).is_dir() else ""
    _icacls(path, "/grant", f"*{sid}:{flags}{rights}", "/Q")


def _copy_runtime():
    """Blotter's private copy of the Python runtime (no site-packages, no test suite)."""
    base = Path(sys.base_prefix)
    marker = RUNTIME / ".from"
    if marker.is_file() and marker.read_text() == f"{base}|{sys.version}":
        return
    tmp = RUNTIME.with_name("runtime.new")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    for item in base.iterdir():
        if item.is_file() and item.suffix.lower() in (".exe", ".dll"):
            shutil.copy2(item, tmp / item.name)
    shutil.copytree(base / "DLLs", tmp / "DLLs")
    shutil.copytree(base / "Lib", tmp / "Lib", ignore=shutil.ignore_patterns(
        "site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip"))
    (tmp / ".from").write_text(f"{base}|{sys.version}")
    shutil.rmtree(RUNTIME, ignore_errors=True)
    os.replace(tmp, RUNTIME)
    _forget_grant(RUNTIME)


def _granted() -> set:
    try:
        return set(GRANTS.read_text(encoding="utf-8").splitlines())
    except OSError:
        return set()


def _forget_grant(path):
    GRANTS.write_text("\n".join(g for g in _granted() if not g.endswith(f"|{path}")), encoding="utf-8")


def _ensure_grant(path, sid):
    """Grant a folder once (icacls walks the whole folder, which takes a moment for big ones)."""
    key = f"{sid}|{path}"
    if key not in _granted():
        Path(path).mkdir(parents=True, exist_ok=True)
        grant(path, sid)
        GRANTS.parent.mkdir(parents=True, exist_ok=True)
        GRANTS.write_text("\n".join(sorted(_granted() | {key})), encoding="utf-8")


def prepare():
    """Set up the container once per start. Returns {'mode': 'appcontainer'|'low-integrity'|'job-only', ...}."""
    with _lock:
        if _state["mode"]:
            return public_state()
        why = []
        try:
            if sys.platform != "win32":
                raise OSError("not Windows")
            _copy_runtime()
            sid_ptr, sid = _container_sid()
            for folder in (RUNTIME, config.ROOT, config.HOME / "rules"):
                _ensure_grant(folder, sid)
            _state.update(mode="appcontainer", sid=sid, sid_ptr=sid_ptr)
            if _works():
                _state["why"] = ""
                return public_state()
            why.append("an AppContainer worker couldn't start")
        except Exception as e:  # e.g. AppContainers switched off by a policy, or a drive without permissions
            why.append(f"AppContainer: {str(e)[:200]}")
        _state.update(mode="low-integrity", sid=None, sid_ptr=None)
        try:
            if _works():
                _state["why"] = "; ".join(why)
                return public_state()
            why.append("a low-integrity worker can't read the Blotter folder")
        except Exception as e:
            why.append(f"low integrity: {str(e)[:200]}")
        # Last resort: the job box only (time and memory limits, no access limits).
        _state.update(mode="job-only", why="; ".join(why))
        return public_state()


def public_state() -> dict:
    return {k: v for k, v in _state.items() if k != "sid_ptr"}


def _works() -> bool:
    """Start a tiny worker in the current mode: can it load Blotter and write its answer?"""
    from . import worker
    workdir = config.INCOMING / f"probe-{os.getpid()}-{threading.get_ident()}"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    try:
        code = (f"import sys; sys.path[:0] = {worker.PATHS!r}; import blotter.worker; "
                "open('ok.txt', 'w').write('ok')")
        run([python(), "-I", "-B", "-c", code], workdir, {**os.environ, "TEMP": str(workdir)}, 60, _probing=True)
        return (workdir / "ok.txt").is_file()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def mode() -> str | None:
    return _state["mode"]


def sid() -> str | None:
    return _state["sid"]


def python() -> str:
    """The interpreter a sandboxed worker runs: the private runtime copy, or for the low-integrity
    fallback the real python.exe (the .venv one is only a launcher that starts it)."""
    if _state["mode"] == "appcontainer":
        return str(RUNTIME / "python.exe")
    return getattr(sys, "_base_executable", sys.executable)


def _env_block(env: dict):
    text = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    return ctypes.create_unicode_buffer(text, len(text))


def run(command: list, workdir: Path, env: dict, timeout: float, memory_limit=None, _probing=False, priority=None,
        cancel=None):
    """Start command sandboxed, wait up to timeout. Returns the exit code, or None if it was stopped (timeout,
    or `cancel`, a threading.Event, was set). `priority` (procs.BELOW_NORMAL) holds for it and its children."""
    state = public_state() if _probing else prepare()
    if state["mode"] == "job-only":
        code, _, _ = procs.run(command, timeout=timeout, memory_limit=memory_limit, env=env, priority=priority,
                               cancel=cancel)
        return code
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
    flags = _EXTENDED_STARTUPINFO | _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT | procs.NO_WINDOW | (priority or 0)
    pi = _ProcessInfo()
    block = _env_block(env)
    if state["mode"] == "appcontainer":
        grant(workdir, state["sid"], write=True)
        caps = _SecurityCapabilities(_state["sid_ptr"], None, 0, 0)
        size = ctypes.c_size_t()
        _k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attrs = ctypes.create_string_buffer(size.value)
        if not _k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _k32.UpdateProcThreadAttribute(attrs, 0, _SECURITY_CAPABILITIES_ATTR, ctypes.byref(caps),
                                                  ctypes.sizeof(caps), None, None):
                raise ctypes.WinError(ctypes.get_last_error())
            si = _StartupInfoEx()
            si.StartupInfo.cb = ctypes.sizeof(si)
            si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
            ok = _k32.CreateProcessW(None, cmdline, None, None, False, flags, block, str(workdir),
                                     ctypes.byref(si), ctypes.byref(pi))
        finally:
            _k32.DeleteProcThreadAttributeList(attrs)
    else:
        _icacls(workdir, "/setintegritylevel", "(OI)(CI)low", "/Q")
        token = _low_token()
        si = _StartupInfoEx()
        si.StartupInfo.cb = ctypes.sizeof(_StartupInfo)
        ok = _adv.CreateProcessAsUserW(token, None, cmdline, None, None, False,
                                       flags & ~_EXTENDED_STARTUPINFO, block, str(workdir),
                                       ctypes.byref(si.StartupInfo), ctypes.byref(pi))
        _k32.CloseHandle(token)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    job = procs.Job(memory_limit, priority)
    try:
        job.add_handle(pi.hProcess)
        _k32.ResumeThread(pi.hThread)
        if not _wait(pi.hProcess, timeout, cancel):
            job.kill()
            _k32.TerminateProcess(pi.hProcess, 1)
            return None
        code = wintypes.DWORD()
        _k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        return code.value
    finally:
        job.close()
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)


def _wait(process, timeout, cancel) -> bool:
    """True when the process ended by itself within `timeout`; False on a timeout or a cancel."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or (cancel is not None and cancel.is_set()):
            return False
        if _k32.WaitForSingleObject(process, int(min(left, 0.25 if cancel is not None else left) * 1000)) == 0:
            return True


def _low_token():
    """A copy of Blotter's own token with every privilege removed and integrity set to Low."""
    own = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), 0x0001 | 0x0002 | 0x0008 | 0x0080, ctypes.byref(own)):
        raise ctypes.WinError(ctypes.get_last_error())
    restricted = wintypes.HANDLE()
    ok = _adv.CreateRestrictedToken(own, 0x1, 0, None, 0, None, 0, None, ctypes.byref(restricted))
    _k32.CloseHandle(own)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    low = ctypes.c_void_p()
    _adv.ConvertStringSidToSidW(_LOW_INTEGRITY, ctypes.byref(low))
    label = _SidAndAttributes(low, 0x20)  # SE_GROUP_INTEGRITY
    size = ctypes.sizeof(label) + _adv.GetLengthSid(low)
    if not _adv.SetTokenInformation(restricted, 25, ctypes.byref(label), size):
        raise ctypes.WinError(ctypes.get_last_error())
    return restricted
