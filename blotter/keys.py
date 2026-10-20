"""API keys, kept in Windows Credential Manager through the keyring library. Never in files."""

import keyring
import keyring.errors

from . import config

KNOWN = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar"}


def backend_name() -> str:
    backend = keyring.get_keyring()
    return f"{type(backend).__module__}.{type(backend).__name__}"


def backend_ok() -> bool:
    """True when keys would really go to Windows Credential Manager."""
    return "WinVaultKeyring" in backend_name()


def get(name: str) -> str | None:
    try:
        return keyring.get_password(config.KEYRING_SERVICE, name) or None
    except keyring.errors.KeyringError:
        return None


def put(name: str, value: str) -> None:
    if name not in KNOWN:
        raise ValueError("unknown key name")
    value = (value or "").strip()
    if not value or len(value) > 200 or any(c.isspace() or not c.isprintable() for c in value):
        raise ValueError("That doesn't look like an API key (empty, too long, or has spaces).")
    keyring.set_password(config.KEYRING_SERVICE, name, value)


def remove(name: str) -> None:
    if name not in KNOWN:
        raise ValueError("unknown key name")
    try:
        keyring.delete_password(config.KEYRING_SERVICE, name)
    except keyring.errors.PasswordDeleteError:
        pass  # already gone


def status() -> dict:
    return {name: get(name) is not None for name in KNOWN}
