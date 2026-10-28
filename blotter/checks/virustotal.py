"""VirusTotal hash lookup. Only the SHA-256 is sent; the file is never uploaded."""

import asyncio
import collections
import datetime
import threading
import time

import aiohttp
import vt

from .. import hashing, keys
from ..findings import CLEAR, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, UNKNOWN, UNKNOWN_ONLINE, Finding, detected

ID = "virustotal"
NAME = "VirusTotal"
ORDER = 10
TIMEOUT = 100          # includes waiting up to MAX_WAIT for a free slot
CACHE = True
NEEDS_FILE = False

REQUEST_TIMEOUT = 20
PER_MINUTE = 4         # the free public API allows 4 lookups a minute
MAX_WAIT = 65
MALICIOUS_AT = 3       # 3+ engines = Malicious; 1-2 = Suspicious (single hits are often false alarms)


class RateLimiter:
    """At most `limit` calls in any `window` seconds; callers wait for a free slot."""

    def __init__(self, limit, window=60.0, clock=time.monotonic, sleep=time.sleep):
        self.limit, self.window, self.clock, self.sleep = limit, window, clock, sleep
        self._calls = collections.deque()
        self._lock = threading.Lock()

    def acquire(self, max_wait: float) -> bool:
        deadline = self.clock() + max_wait
        while True:
            with self._lock:
                now = self.clock()
                while self._calls and now - self._calls[0] >= self.window:
                    self._calls.popleft()
                if len(self._calls) < self.limit:
                    self._calls.append(now)
                    return True
                wait = self._calls[0] + self.window - now
            if now + wait > deadline:
                return False
            self.sleep(wait + 0.05)


limiter = RateLimiter(PER_MINUTE)


def scan(path) -> list[Finding]:
    key = keys.get(ID)
    if not key:
        # "Not checked", never "never seen": without a key Blotter knows nothing about what VirusTotal has
        # seen, so this carries no UNKNOWN_ONLINE signal and can't raise the verdict.
        return [Finding(ID, SKIPPED, "VirusTotal wasn't asked because no API key is set (optional, see Settings). "
                                     "\"Open on VirusTotal\" looks the file up in your browser instead.",
                        {"not_checked": "no_key"})]
    sha = hashing.sha256_file(path)
    if not limiter.acquire(MAX_WAIT):
        return [Finding(ID, ERROR, "VirusTotal wasn't checked: the limit of 4 lookups a minute is used up. Try again in a minute.")]
    try:
        data = asyncio.run(_lookup(key, sha))
    except vt.APIError as e:
        return [_api_error(e)]
    except (asyncio.TimeoutError, TimeoutError):
        return [Finding(ID, ERROR, f"VirusTotal didn't answer within {REQUEST_TIMEOUT} seconds.")]
    except (aiohttp.ClientError, OSError):
        return [Finding(ID, ERROR, "VirusTotal couldn't be reached. Is the internet connected?")]
    if data is None:
        return [Finding(ID, UNKNOWN,
                        "VirusTotal has no record of this file, so no antivirus engines there have looked at it.",
                        {"link": _link(sha)}, [UNKNOWN_ONLINE])]
    return interpret(sha, data)


async def _lookup(key: str, sha: str):
    async with vt.Client(key, timeout=REQUEST_TIMEOUT) as client:
        try:
            return await asyncio.wait_for(client.get_json_async(f"/files/{sha}"), REQUEST_TIMEOUT + 5)
        except vt.APIError as e:
            if e.code == "NotFoundError":
                return None
            raise


def _api_error(e) -> Finding:
    code = getattr(e, "code", "")
    if code in ("WrongCredentialsError", "AuthenticationRequiredError", "ForbiddenError"):
        text = "VirusTotal rejected the API key. Check it under Keys."
    elif code in ("QuotaExceededError", "TooManyRequestsError"):
        text = "VirusTotal says the key's quota is used up (free keys: 4 a minute, 500 a day). Try again later."
    else:
        text = f"VirusTotal answered with an error ({code or 'unknown'})."
    return Finding(ID, ERROR, text, {"error": code})


def _link(sha: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha}"


def _engines(n: int) -> str:
    return "1 antivirus engine" if n == 1 else f"{n} antivirus engines"


def interpret(sha: str, data: dict) -> list[Finding]:
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
    flagged = sorted(
        (
            {"engine": name, "category": r.get("category"), "result": r.get("result")}
            for name, r in (attrs.get("last_analysis_results") or {}).items()
            if r.get("category") in ("malicious", "suspicious")
        ),
        key=lambda r: (r["category"] != "malicious", r["engine"].lower()),
    )
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    stamp = attrs.get("last_analysis_date")
    date = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).date().isoformat() if stamp else None
    details = {
        "malicious": mal, "suspicious": sus, "engines": total, "flagged": flagged,
        "label": label, "last_analysis": date, "names": (attrs.get("names") or [])[:5], "link": _link(sha),
    }
    flags = "flags" if mal == 1 else "flag"
    if total == 0:
        return [Finding(ID, UNKNOWN, "VirusTotal knows this file but has no finished engine results for it yet.", details)]
    if mal >= MALICIOUS_AT:
        name = f" (most common name: {label})" if label else ""
        text = f"VirusTotal: {mal} of {_engines(total)} {flags} this file as malicious{name}."
        return [detected(Finding(ID, MALICIOUS, text, details), "VirusTotal", label)]
    if mal:
        text = (f"VirusTotal: {mal} of {_engines(total)} {flags} this file as malicious. "
                "One or two hits are often false alarms, but it is a warning sign.")
        return [detected(Finding(ID, SUSPICIOUS, text, details), "VirusTotal", label)]
    if sus:
        verb = "calls" if sus == 1 else "call"
        text = f"VirusTotal: {sus} of {_engines(total)} {verb} this file suspicious, and none call it malicious."
        return [detected(Finding(ID, SUSPICIOUS, text, details), "VirusTotal", label)]
    when = f" (last scanned there {date})" if date else ""
    text = f"VirusTotal: none of the {_engines(total)} that scanned this file flag it{when}."
    return [Finding(ID, CLEAR, text, details)]
