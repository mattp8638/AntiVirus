#!/usr/bin/env python3
"""Make mixed-case Windows SDK #includes portable to Linux MinGW builds.

Windows filesystems generally resolve Windows.h/windows.h interchangeably.
MinGW sysroot headers on Linux are case-sensitive. Rather than change hundreds
of existing Windows-native source files, create build-only case aliases that
point to the installed, trusted MinGW SDK (never to downloaded headers).

Only create aliases for a header that exists in the local SDK with identical
casefolded spelling. All other includes still fail normally at compile time.
"""
from pathlib import Path
import os
import re
import sys

sdk = Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/x86_64-w64-mingw32/include")
source = Path(sys.argv[2] if len(sys.argv) > 2 else "/src/agent/windows")
output = Path(sys.argv[3] if len(sys.argv) > 3 else "/opt/fenrir-windows-compat")

headers = {}
for existing in sdk.rglob("*"):
    if existing.is_file():
        relative = existing.relative_to(sdk).as_posix()
        headers.setdefault(relative.casefold(), existing)

pattern = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", re.MULTILINE)
count = 0
for path in source.rglob("*"):
    if path.suffix.lower() not in {".cpp", ".c", ".h", ".hpp", ".rc"} or not path.is_file():
        continue
    source_text = path.read_text(encoding="utf-8", errors="replace")
    for spelling in pattern.findall(source_text):
        key = spelling.replace("\\", "/")
        original = sdk / key
        resolved = headers.get(key.casefold())
        if original.exists() or resolved is None or original == resolved:
            continue
        alias = output / key
        if alias.exists() or alias.is_symlink():
            continue
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(resolved)
        count += 1

print(f"MinGW SDK header case aliases prepared: {count}")
