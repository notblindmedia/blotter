"""CIRCL hashlookup: is this a known, common file (from software collections such as NIST's NSRL)?

No key, no account. Only the SHA-256 is sent. A hit lowers suspicion; a miss means nothing
(most files, mods especially, aren't in these collections).
"""

import requests

from .. import hashing, network
from ..findings import CLEAR, ERROR, KNOWN_GOOD, NOTE, UNKNOWN, Finding

ID = "hashlookup"
NAME = "CIRCL hashlookup"
ORDER = 25
TIMEOUT = 30
CACHE = True
NEEDS_FILE = False

API_URL = "https://hashlookup.circl.lu/lookup/sha256/"
REQUEST_TIMEOUT = (5, 15)


def scan(path) -> list[Finding]:
    sha = hashing.sha256_file(path)
    try:
        response = network.get(API_URL + sha, headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT)
    except requests.Timeout:
        return [Finding(ID, ERROR, "CIRCL hashlookup didn't answer in time.")]
    except requests.RequestException:
        return [Finding(ID, ERROR, "CIRCL hashlookup couldn't be reached. Is the internet connected?")]
    if response.status_code == 404:
        return [Finding(ID, UNKNOWN, "CIRCL hashlookup doesn't list this file. That's normal: it only knows "
                                     "common software, not most downloads or mods.")]
    if response.status_code != 200:
        return [Finding(ID, ERROR, f"CIRCL hashlookup answered with an error (HTTP {response.status_code}).")]
    try:
        return interpret(response.json())
    except ValueError:
        return [Finding(ID, ERROR, "CIRCL hashlookup sent an answer Blotter couldn't read.")]


def interpret(body: dict) -> list[Finding]:
    name = body.get("FileName") or body.get("ProductName") or ""
    product = body.get("ProductName") or ""
    sources = body.get("source") or body.get("db") or ""
    details = {"file_name": name, "product": product, "source": sources,
               "known_malicious": body.get("KnownMalicious")}
    if body.get("KnownMalicious"):
        return [Finding(ID, NOTE, f"CIRCL hashlookup lists this file, but one of its sources ({body['KnownMalicious']}) "
                                  "marks it as malicious, so it doesn't count as known-good.", details)]
    what = f" as {name}" if name else ""
    also = f" ({product})" if product and product != name else ""
    return [Finding(ID, CLEAR, f"CIRCL hashlookup knows this file{what}{also} from a collection of known, common "
                               "software. That lowers suspicion, though it isn't a guarantee.", details, [KNOWN_GOOD])]
