"""Every internet address Blotter may contact. Nothing else is ever contacted.

Lookups send only a file's SHA-256 fingerprint, never the file or its name.
Downloads fetch rules and tools; they send nothing about your files.
A test (tests/test_network.py) fails if any address in the code is missing from this list.
"""

from urllib.parse import urlsplit

import requests

LOOKUPS = {
    "www.virustotal.com": "VirusTotal hash lookup (only with your key)",
    "mb-api.abuse.ch": "MalwareBazaar hash lookup (only with your key)",
    "hashlookup.circl.lu": "CIRCL hashlookup: is this a known, common file? (no key)",
}

DOWNLOADS = {
    "api.github.com": "finds the newest YARA Forge rules release and its checksum, and Blotter's own releases",
    "github.com": "YARA Forge rules, the ClamAV program, Blotter's signed releases and intel pack (release downloads)",
    "release-assets.githubusercontent.com": "GitHub's file storage behind those downloads",
    "objects.githubusercontent.com": "GitHub's older file storage behind those downloads",
    "codeload.github.com": "capa's rules (a fixed version, checked by checksum)",
    "raw.githubusercontent.com": "capa's library signatures (fixed version, checked by checksum)",
    "database.clamav.net": "ClamAV's daily signature updates (fetched by ClamAV's own freshclam)",
}

# Pages you can open in your browser from a result. Blotter itself doesn't contact them.
LINKS = {
    "www.virustotal.com": "the file's page on VirusTotal (the fingerprint is in the address)",
    "bazaar.abuse.ch": "the file's page on MalwareBazaar",
    "auth.abuse.ch": "where you get a MalwareBazaar key (named by setup.bat's key step)",
}

ALLOWED = set(LOOKUPS) | set(DOWNLOADS)
USER_AGENT = "Blotter"


class NotAllowed(Exception):
    pass


def check(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise NotAllowed(f"Blotter may not contact {parts.hostname or url}")
    return url


def get(url, **kwargs) -> requests.Response:
    return _request("GET", url, **kwargs)


def post(url, **kwargs) -> requests.Response:
    return _request("POST", url, **kwargs)


def _request(method, url, max_redirects=5, **kwargs) -> requests.Response:
    """requests, but every hop (redirects too) must be on the list above."""
    headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
    for _ in range(max_redirects + 1):
        response = requests.request(method, check(url), headers=headers, allow_redirects=False, **kwargs)
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
            url = requests.compat.urljoin(url, response.headers["location"])
            response.close()
            if response.status_code == 303:
                method = "GET"
            continue
        return response
    raise requests.TooManyRedirects(url)
