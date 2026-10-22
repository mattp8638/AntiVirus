"""EMBER v2 static PE features, reimplemented without LIEF.

This is the reference implementation. The Go (agent/linux/pkg/ml) and C++
(agent/windows/service/src/MlFeatures.cpp) ports must produce identical
vectors; tests/parity checks that.

The layout matches the EMBER v2 / SOREL-20M feature vectors the model is
trained on (2381 floats):

    byte histogram 256 | byte-entropy histogram 256 | strings 104 | general 10 |
    header 62 | sections 255 | imports 1280 | exports 128 | data directories 30

Where LIEF 0.9 behaviour differs from the PE spec we follow LIEF 0.9, because
that is what produced the training data (notably: the "entry section" is the
first executable section, since LIEF 0.9's section_from_offset(entrypoint)
lookup almost never succeeds).
"""

from __future__ import annotations

import array
import math
import re
import struct
from dataclasses import dataclass, field

DIM = 2381

# --------------------------------------------------------------------------- hashing (sklearn FeatureHasher)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, returned as a signed int32 like sklearn."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    n = len(data)
    nblocks = n // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def hash_into(out: list[float], offset: int, n: int, items) -> None:
    """FeatureHasher(n, alternate_sign=True). items: iterable of (token, value)."""
    for token, value in items:
        h = murmur3_32(token.encode("utf-8"))
        if h == -2147483648:
            index = (2147483647 - (n - 1)) % n
        else:
            index = abs(h) % n
        out[offset + index] += value if h >= 0 else -value


# --------------------------------------------------------------------------- PE parsing

MACHINES = {0x0: "UNKNOWN", 0x14C: "I386", 0x162: "R3000", 0x166: "R4000", 0x168: "R10000", 0x169: "WCEMIPSV2", 0x184: "ALPHA",
            0x1A2: "SH3", 0x1A3: "SH3DSP", 0x1A6: "SH4", 0x1A8: "SH5", 0x1C0: "ARM", 0x1C2: "THUMB", 0x1C4: "ARMNT", 0x1D3: "AM33",
            0x1F0: "POWERPC", 0x1F1: "POWERPCFP", 0x200: "IA64", 0x266: "MIPS16", 0x366: "MIPSFPU", 0x466: "MIPSFPU16",
            0x520: "TRICORE", 0xEBC: "EBC", 0x8664: "AMD64", 0x9041: "M32R", 0xAA64: "ARM64", 0xC0EE: "CEE"}
HEADER_CHARACTERISTICS = [(0x1, "RELOCS_STRIPPED"), (0x2, "EXECUTABLE_IMAGE"), (0x4, "LINE_NUMS_STRIPPED"), (0x8, "LOCAL_SYMS_STRIPPED"),
                          (0x10, "AGGRESSIVE_WS_TRIM"), (0x20, "LARGE_ADDRESS_AWARE"), (0x80, "BYTES_REVERSED_LO"),
                          (0x100, "CHARA_32BIT_MACHINE"), (0x200, "DEBUG_STRIPPED"), (0x400, "REMOVABLE_RUN_FROM_SWAP"),
                          (0x800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"), (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"),
                          (0x8000, "BYTES_REVERSED_HI")]
SUBSYSTEMS = {0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS",
              9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
              14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
DLL_CHARACTERISTICS = [(0x20, "HIGH_ENTROPY_VA"), (0x40, "DYNAMIC_BASE"), (0x80, "FORCE_INTEGRITY"), (0x100, "NX_COMPAT"),
                       (0x200, "NO_ISOLATION"), (0x400, "NO_SEH"), (0x800, "NO_BIND"), (0x1000, "APPCONTAINER"),
                       (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE")]
SECTION_CHARACTERISTICS = [(0x8, "TYPE_NO_PAD"), (0x20, "CNT_CODE"), (0x40, "CNT_INITIALIZED_DATA"), (0x80, "CNT_UNINITIALIZED_DATA"),
                           (0x100, "LNK_OTHER"), (0x200, "LNK_INFO"), (0x800, "LNK_REMOVE"), (0x1000, "LNK_COMDAT"), (0x8000, "GPREL"),
                           (0x20000, "MEM_PURGEABLE"), (0x40000, "MEM_LOCKED"), (0x80000, "MEM_PRELOAD"),
                           (0x1000000, "LNK_NRELOC_OVFL"), (0x2000000, "MEM_DISCARDABLE"), (0x4000000, "MEM_NOT_CACHED"),
                           (0x8000000, "MEM_NOT_PAGED"), (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"),
                           (0x40000000, "MEM_READ"), (0x80000000, "MEM_WRITE")]
ALIGNMENTS = {1: "ALIGN_1BYTES", 2: "ALIGN_2BYTES", 3: "ALIGN_4BYTES", 4: "ALIGN_8BYTES", 5: "ALIGN_16BYTES", 6: "ALIGN_32BYTES",
              7: "ALIGN_64BYTES", 8: "ALIGN_128BYTES", 9: "ALIGN_256BYTES", 10: "ALIGN_512BYTES", 11: "ALIGN_1024BYTES",
              12: "ALIGN_2048BYTES", 13: "ALIGN_4096BYTES", 14: "ALIGN_8192BYTES"}


@dataclass
class Section:
    name: str
    raw_size: int
    raw_offset: int
    vsize: int
    rva: int
    characteristics: int
    entropy: float = 0.0
    props: list[str] = field(default_factory=list)


@dataclass
class PE:
    machine: int = 0
    timestamp: int = 0
    characteristics: int = 0
    number_of_symbols: int = 0
    magic: int = 0
    major_linker: int = 0
    minor_linker: int = 0
    sizeof_code: int = 0
    image_base: int = 0
    major_os: int = 0
    minor_os: int = 0
    major_image: int = 0
    minor_image: int = 0
    major_subsystem: int = 0
    minor_subsystem: int = 0
    sizeof_image: int = 0
    sizeof_headers: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    sizeof_heap_commit: int = 0
    directories: list[tuple[int, int]] = field(default_factory=list)  # (rva, size)
    sections: list[Section] = field(default_factory=list)
    imports: list[tuple[str, list[str]]] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)


class PEError(ValueError):
    pass


def _u16(b: bytes, o: int) -> int:
    if o < 0 or o + 2 > len(b):
        raise PEError("truncated")
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    if o < 0 or o + 4 > len(b):
        raise PEError("truncated")
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    if o < 0 or o + 8 > len(b):
        raise PEError("truncated")
    return struct.unpack_from("<Q", b, o)[0]


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _cstr(b: bytes, o: int, limit: int = 4096) -> str:
    if o < 0 or o >= len(b):
        raise PEError("string out of range")
    end = b.find(b"\x00", o, min(len(b), o + limit))
    if end < 0:
        end = min(len(b), o + limit)
    return b[o:end].decode("latin-1")


def parse_pe(data: bytes) -> PE:
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEError("not a PE (no MZ)")
    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("not a PE (no PE signature)")
    pe = PE()
    coff = e_lfanew + 4
    pe.machine = _u16(data, coff)
    nsections = _u16(data, coff + 2)
    pe.timestamp = _u32(data, coff + 4)
    pe.number_of_symbols = _u32(data, coff + 12)
    opt_size = _u16(data, coff + 16)
    pe.characteristics = _u16(data, coff + 18)
    opt = coff + 20
    pe.magic = _u16(data, opt)
    plus = pe.magic == 0x20B
    if pe.magic not in (0x10B, 0x20B):
        raise PEError("bad optional header magic")
    pe.major_linker, pe.minor_linker = data[opt + 2], data[opt + 3]
    pe.sizeof_code = _u32(data, opt + 4)
    pe.image_base = _u64(data, opt + 24) if plus else _u32(data, opt + 28)
    pe.major_os, pe.minor_os = _u16(data, opt + 40), _u16(data, opt + 42)
    pe.major_image, pe.minor_image = _u16(data, opt + 44), _u16(data, opt + 46)
    pe.major_subsystem, pe.minor_subsystem = _u16(data, opt + 48), _u16(data, opt + 50)
    pe.sizeof_image = _u32(data, opt + 56)
    pe.sizeof_headers = _u32(data, opt + 60)
    pe.subsystem = _u16(data, opt + 68)
    pe.dll_characteristics = _u16(data, opt + 70)
    if plus:
        pe.sizeof_heap_commit = _u64(data, opt + 96)
        ndirs_off, dirs_off = opt + 108, opt + 112
    else:
        pe.sizeof_heap_commit = _u32(data, opt + 84)
        ndirs_off, dirs_off = opt + 92, opt + 96
    ndirs = min(_u32(data, ndirs_off), 16)
    for i in range(ndirs):
        if dirs_off + 8 * i + 8 > opt + opt_size or dirs_off + 8 * i + 8 > len(data):
            break
        pe.directories.append((_u32(data, dirs_off + 8 * i), _u32(data, dirs_off + 8 * i + 4)))

    sec = opt + opt_size
    for i in range(min(nsections, 96)):
        o = sec + 40 * i
        if o + 40 > len(data):
            break
        name = data[o:o + 8].split(b"\x00", 1)[0].decode("latin-1")
        s = Section(name=name, vsize=_u32(data, o + 8), rva=_u32(data, o + 12), raw_size=_u32(data, o + 16),
                    raw_offset=_u32(data, o + 20), characteristics=_u32(data, o + 36))
        # LIEF splits raw data into content (up to VirtualSize) and padding; entropy covers content only.
        start = s.raw_offset
        content_size = min(s.raw_size, s.vsize) if s.vsize else s.raw_size
        end = min(len(data), start + content_size)
        s.entropy = byte_entropy(data[start:end]) if start < len(data) and s.raw_size else 0.0
        props = [label for bit, label in SECTION_CHARACTERISTICS if s.characteristics & bit]
        align = (s.characteristics >> 20) & 0xF
        if align in ALIGNMENTS:
            props.append(ALIGNMENTS[align])
        s.props = props
        pe.sections.append(s)

    def rva_to_off(rva: int) -> int:
        for s in pe.sections:
            span = max(s.vsize, s.raw_size)
            if s.rva <= rva < s.rva + span:
                return rva - s.rva + s.raw_offset
        if rva < pe.sizeof_headers:
            return rva
        raise PEError("rva not mapped")

    # Imports
    if len(pe.directories) > 1 and pe.directories[1][0] and pe.directories[1][1]:
        try:
            o = rva_to_off(pe.directories[1][0])
            for _ in range(4096):
                if o + 20 > len(data):
                    break
                oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, o)
                if not (oft or name_rva or ft):
                    break
                o += 20
                try:
                    dll = _cstr(data, rva_to_off(name_rva), 256)
                except PEError:
                    continue
                entries: list[str] = []
                thunk_rva = oft or ft
                try:
                    t = rva_to_off(thunk_rva)
                except PEError:
                    pe.imports.append((dll, entries))
                    continue
                step = 8 if plus else 4
                for _ in range(65536):
                    if t + step > len(data):
                        break
                    value = _u64(data, t) if plus else _u32(data, t)
                    if value == 0:
                        break
                    t += step
                    ordinal_flag = 1 << 63 if plus else 1 << 31
                    if value & ordinal_flag:
                        entries.append("ordinal" + str(value & 0xFFFF))
                    else:
                        try:
                            entries.append(_cstr(data, rva_to_off(value & 0x7FFFFFFF) + 2, 10000))
                        except PEError:
                            continue
                pe.imports.append((dll, entries))
        except PEError:
            pass

    # Exports (named only, as LIEF 0.9 reported them)
    if pe.directories and pe.directories[0][0] and pe.directories[0][1]:
        try:
            o = rva_to_off(pe.directories[0][0])
            n_names = _u32(data, o + 24)
            names_rva = _u32(data, o + 32)
            names_off = rva_to_off(names_rva)
            for i in range(min(n_names, 65536)):
                try:
                    pe.exports.append(_cstr(data, rva_to_off(_u32(data, names_off + 4 * i)), 10000))
                except PEError:
                    continue
        except PEError:
            pass
    return pe


# --------------------------------------------------------------------------- feature blocks

_STRINGS = re.compile(rb"[\x20-\x7f]{5,}")
_PATHS = re.compile(rb"c:\\", re.IGNORECASE)
_URLS = re.compile(rb"https?://", re.IGNORECASE)
_REGISTRY = re.compile(rb"HKEY_")
_MZ = re.compile(rb"MZ")


def _byte_histogram(data: bytes) -> list[float]:
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data)) or 1.0
    return [c / total for c in counts]


def _entropy_bin(block: bytes, window: int) -> tuple[int, list[int]]:
    c = [0] * 16
    for byte in block:
        c[byte >> 4] += 1
    h = 0.0
    for count in c:
        if count:
            p = count / window
            h -= p * math.log2(p)
    hbin = int(h * 2 * 2)
    return min(hbin, 15), c


def _byte_entropy_histogram(data: bytes, step: int = 1024, window: int = 2048) -> list[float]:
    out = [0] * 256
    if len(data) < window:
        hbin, c = _entropy_bin(data, window)
        for j in range(16):
            out[hbin * 16 + j] += c[j]
    else:
        for start in range(0, len(data) - window + 1, step):
            hbin, c = _entropy_bin(data[start:start + window], window)
            for j in range(16):
                out[hbin * 16 + j] += c[j]
    total = float(sum(out)) or 1.0
    return [v / total for v in out]


def _strings(data: bytes) -> list[float]:
    found = _STRINGS.findall(data)
    dist = [0] * 96
    printables = 0
    avlength = 0.0
    entropy = 0.0
    if found:
        avlength = sum(len(s) for s in found) / len(found)
        for s in found:
            for byte in s:
                dist[byte - 0x20] += 1
        printables = sum(dist)
        for count in dist:
            if count:
                p = count / printables
                entropy -= p * math.log2(p)
    divisor = float(printables) if printables else 1.0
    return ([float(len(found)), avlength, float(printables)] + [d / divisor for d in dist] +
            [entropy, float(len(_PATHS.findall(data))), float(len(_URLS.findall(data))),
             float(len(_REGISTRY.findall(data))), float(len(_MZ.findall(data)))])


def _dir_present(pe: PE, index: int) -> int:
    return int(len(pe.directories) > index and pe.directories[index][0] != 0 and pe.directories[index][1] != 0)


def extract(data: bytes) -> list[float]:
    """Return the 2381-float EMBER v2 vector, rounded to float32 like the training data."""
    return list(array.array("f", _extract64(data)))


def _extract64(data: bytes) -> list[float]:
    """Non-PE input yields the PE blocks as zeros."""
    vec = [0.0] * DIM
    vec[0:256] = _byte_histogram(data)
    vec[256:512] = _byte_entropy_histogram(data)
    vec[512:616] = _strings(data)
    try:
        pe = parse_pe(data)
    except PEError:
        vec[616] = float(len(data))
        return vec

    imported = sum(len(entries) for _, entries in pe.imports)
    vec[616:626] = [float(len(data)), float(pe.sizeof_image), float(_dir_present(pe, 6)), float(len(pe.exports)), float(imported),
                    float(_dir_present(pe, 5)), float(_dir_present(pe, 2)), float(_dir_present(pe, 4)), float(_dir_present(pe, 9)),
                    float(pe.number_of_symbols)]

    # header 626..688
    o = 626
    vec[o] = float(pe.timestamp)
    hash_into(vec, o + 1, 10, [(MACHINES.get(pe.machine, "UNKNOWN"), 1.0)])
    hash_into(vec, o + 11, 10, [(label, 1.0) for bit, label in HEADER_CHARACTERISTICS if pe.characteristics & bit])
    hash_into(vec, o + 21, 10, [(SUBSYSTEMS.get(pe.subsystem, "UNKNOWN"), 1.0)])
    hash_into(vec, o + 31, 10, [(label, 1.0) for bit, label in DLL_CHARACTERISTICS if pe.dll_characteristics & bit])
    hash_into(vec, o + 41, 10, [("PE32_PLUS" if pe.magic == 0x20B else "PE32", 1.0)])
    vec[o + 51:o + 62] = [float(v) for v in (pe.major_image, pe.minor_image, pe.major_linker, pe.minor_linker, pe.major_os,
                                             pe.minor_os, pe.major_subsystem, pe.minor_subsystem, pe.sizeof_code,
                                             pe.sizeof_headers, pe.sizeof_heap_commit)]

    # sections 688..943
    o = 688
    secs = pe.sections
    vec[o:o + 5] = [float(len(secs)), float(sum(1 for s in secs if s.raw_size == 0)), float(sum(1 for s in secs if s.name == "")),
                    float(sum(1 for s in secs if "MEM_READ" in s.props and "MEM_EXECUTE" in s.props)),
                    float(sum(1 for s in secs if "MEM_WRITE" in s.props))]
    hash_into(vec, o + 5, 50, [(s.name, float(s.raw_size)) for s in secs])
    hash_into(vec, o + 55, 50, [(s.name, s.entropy) for s in secs])
    hash_into(vec, o + 105, 50, [(s.name, float(s.vsize)) for s in secs])
    entry = next((s.name for s in secs if "MEM_EXECUTE" in s.props), "")
    hash_into(vec, o + 155, 50, [(ch, 1.0) for ch in entry])  # EMBER hashes the entry name character by character
    hash_into(vec, o + 205, 50, [(p, 1.0) for s in secs if s.name == entry for p in s.props])

    # imports 943..2223
    o = 943
    libraries = sorted({lib.lower() for lib, _ in pe.imports})
    hash_into(vec, o, 256, [(lib, 1.0) for lib in libraries])
    hash_into(vec, o + 256, 1024, [(lib.lower() + ":" + e, 1.0) for lib, entries in pe.imports for e in entries])

    # exports 2223..2351
    hash_into(vec, 2223, 128, [(name, 1.0) for name in pe.exports])

    # data directories 2351..2381 (first 15, positional)
    for i, (rva, size) in enumerate(pe.directories[:15]):
        vec[2351 + 2 * i] = float(size)
        vec[2351 + 2 * i + 1] = float(rva)
    return vec


def is_pe(data: bytes) -> bool:
    try:
        parse_pe(data)
        return True
    except PEError:
        return False
