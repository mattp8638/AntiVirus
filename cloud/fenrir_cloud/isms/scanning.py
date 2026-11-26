"""Virus scanning of uploaded evidence with ClamAV (the same clamd the mail gateway uses: FENRIR_CLAMD_HOST).

Without a scanner, production keeps files pending (they cannot be downloaded) until one is configured and the hourly
job rescans them; development marks them clean with a note that they were not scanned.
"""

from __future__ import annotations

import os
import re
import socket
import struct

BLOCKED_EXTENSIONS = re.compile(r"\.(exe|msi|bat|cmd|com|scr|ps1|vbs|js|jar|sh|dll|app|apk)$", re.I)


def configured() -> bool:
    return bool(os.environ.get("FENRIR_CLAMD_HOST"))


def scan(data: bytes) -> tuple[str, str | None]:
    """(clean | infected | failed, detail). ``failed`` means the scanner could not give an answer."""
    host = os.environ.get("FENRIR_CLAMD_HOST")
    if not host:
        return "failed", "No virus scanner is configured."
    try:
        with socket.create_connection((host, int(os.environ.get("FENRIR_CLAMD_PORT", "3310"))), timeout=60) as sock:
            sock.sendall(b"zINSTREAM\0")
            for start in range(0, len(data), 65536):
                chunk = data[start:start + 65536]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            reply = sock.recv(4096).decode("utf-8", "replace").strip("\0 \n")
    except OSError as exc:
        return "failed", f"The virus scanner could not be reached ({exc.__class__.__name__})."
    if reply.endswith("OK"):
        return "clean", None
    found = re.search(r":\s*(.+?)\s+FOUND$", reply)
    if found:
        return "infected", found.group(1)[:200]
    return "failed", f"Unexpected scanner reply: {reply[:200]}"
