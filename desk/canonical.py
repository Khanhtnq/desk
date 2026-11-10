"""Canonical JSON and domain-separated digests for everything the desk signs or hashes itself.

Same conventions as the DAO harness. The protocol's own formats live in `xe/`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

# Domain tags. Each kind of signed payload gets its own tag so a signature can never be replayed
# as a different kind of thing.
DOMAIN_EVENT = b"xe-desk/event/v1\x00"
DOMAIN_EVENT_V2 = b"xe-desk/event/v2\x00"  # adds public and ref to the hashed envelope
DOMAIN_LOGIN = b"xe/desk/login/v1\x00"
DOMAIN_PAYOUT = b"xe/desk/payout/v1\x00"
DOMAIN_WITHDRAW = b"xe/desk/withdraw/v1\x00"

DOMAINS = {
    "xe/desk/login/v1": DOMAIN_LOGIN,
    "xe/desk/payout/v1": DOMAIN_PAYOUT,
    "xe/desk/withdraw/v1": DOMAIN_WITHDRAW,
}


def same_secret(a: str, b: str) -> bool:
    """Constant-time equality of two secrets given as text. `hmac.compare_digest` raises TypeError on
    a str with a non-ASCII character in it, and a header is whatever the client sent, so one byte
    over 0x7f in a signature or token header was a 500 (XE-1033 fixed that for the TOTP code alone).
    Compared as bytes here, for every caller: a value that is not the secret is not equal, and that
    is all."""
    return hmac.compare_digest(a.encode("utf-8", "backslashreplace"), b.encode("utf-8", "backslashreplace"))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(domain: bytes, value: Any) -> bytes:
    """sha256(domain || canonical_json(value)); 32 bytes. This is what gets signed."""
    return hashlib.sha256(domain + canonical_json(value)).digest()


def digest_hex(domain: bytes, value: Any) -> str:
    return digest(domain, value).hex()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
