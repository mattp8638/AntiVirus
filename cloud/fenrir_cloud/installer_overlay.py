"""Unique customer-specific overlays for precompiled unsigned FenrirSetup.exe.

The immutable Windows PE template is built automatically in the Ubuntu Docker
image. Each download gets a new token and therefore a different executable.
No customer credential is written to persistent disk or a public URL.

Wire format, appended at the end of the PE file:
  ASCII https-origin + '\\n' + ASCII fet_token + '\\n'
  SHA-256(payload) [32 bytes]
  uint32 little-endian payload byte count
  b'FENRIR01' [8 bytes]
The SHA-256 detects accidental corruption. It is NOT a digital signature and
does not authenticate the publisher of an unsigned executable.
"""
from __future__ import annotations

import hashlib
import struct

MAGIC = b"FENRIR01"
MAX_PAYLOAD = 4096


def personalise(template: bytes, server: str, token: str) -> bytes:
    if not template.startswith(b"MZ"):
        raise ValueError("Windows installer template is not a PE executable")
    if any(c in server for c in "\r\n\x00") or any(c in token for c in "\r\n\x00"):
        raise ValueError("Invalid enrollment values")
    try:
        payload = (server + "\n" + token + "\n").encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("Cloud origin and enrollment token must be ASCII") from exc
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("Embedded enrollment data exceeds its size limit")
    return template + payload + hashlib.sha256(payload).digest() + struct.pack("<I", len(payload)) + MAGIC


def inspect(candidate: bytes) -> tuple[str, str]:
    """Tooling/tests only: verify a generated file and read its two fields."""
    if len(candidate) < 44 or candidate[-8:] != MAGIC:
        raise ValueError("Installer has no cloud enrollment overlay")
    size = struct.unpack("<I", candidate[-12:-8])[0]
    if size <= 0 or size > MAX_PAYLOAD or len(candidate) < size + 44:
        raise ValueError("Invalid cloud enrollment overlay size")
    payload = candidate[-44-size:-44]
    if hashlib.sha256(payload).digest() != candidate[-44:-12]:
        raise ValueError("Cloud enrollment overlay integrity check failed")
    parts = payload.decode("ascii").split("\n")
    if len(parts) != 3 or parts[2] or not parts[0] or not parts[1]:
        raise ValueError("Invalid cloud enrollment overlay fields")
    return parts[0], parts[1]
