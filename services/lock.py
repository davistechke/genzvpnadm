"""Locked configs: AES-256-GCM, so the file or API reply is unreadable without the key."""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOCKED = "genzvpn-locked"


def _key(secret):
    return hashlib.sha256(("genzvpn-config:" + secret).encode()).digest()


def lock(plain: bytes, secret: str) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(_key(secret)).encrypt(nonce, plain, LOCKED.encode())
    return json.dumps({"format": LOCKED, "v": 1, "nonce": base64.b64encode(nonce).decode(),
                       "data": base64.b64encode(ct).decode()}, separators=(",", ":")).encode()


def is_locked(obj) -> bool:
    return isinstance(obj, dict) and obj.get("format") == LOCKED


def unlock(obj: dict, secret: str) -> bytes:
    if not secret:
        raise ValueError("This file is locked. Set CONFIG_KEY on the server to open it.")
    try:
        return AESGCM(_key(secret)).decrypt(base64.b64decode(obj["nonce"]), base64.b64decode(obj["data"]),
                                            LOCKED.encode())
    except (InvalidTag, KeyError, ValueError) as e:
        raise ValueError("This file was locked with a different key.") from e
