"""Fail unless each Mach-O file carries a code signature (LC_CODE_SIGNATURE with a valid superblob).

Apple Silicon refuses to run arm64 code with no signature at all. Go's linker adds an ad-hoc one, which is all a
script-installed agent needs (no notarisation: a file fetched by curl and installed with sudo never gets Gatekeeper's
quarantine flag). Anything that rewrites the binary after linking would break that signature and the agent would be
killed on launch, so CI checks the binaries actually shipped. Usage: check_macho_signature.py FILE..."""

import struct
import sys

LC_CODE_SIGNATURE, SUPERBLOB = 0x1D, 0xFADE0CC0


def signed(data: bytes) -> bool:
    if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:  # 64-bit little-endian Mach-O
        raise ValueError("not a 64-bit Mach-O file")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", data, off + 8)
            return datasize > 12 and dataoff + datasize <= len(data) and struct.unpack_from(">I", data, dataoff)[0] == SUPERBLOB
        off += size
    return False


if __name__ == "__main__":
    bad = 0
    for path in sys.argv[1:]:
        ok = signed(open(path, "rb").read())
        print(f"{'PASS' if ok else 'FAIL'}: {path} {'has' if ok else 'has NO'} code signature")
        bad += not ok
    sys.exit(1 if bad else 0)
