"""Independent EMBER-v2 extraction with LIEF, used only to cross-check features.py.

Follows the published EMBER v2 feature code, adapted to the LIEF 0.14+ API,
emulating LIEF 0.9 where the training data depended on it (entry section).
"""
import lief
import numpy as np
from sklearn.feature_extraction import FeatureHasher

from fenrir_ml import features as F

lief.logging.disable()


def _hash(n, kind, items):
    return FeatureHasher(n, input_type=kind).transform([items]).toarray()[0]


def extract(data: bytes) -> np.ndarray:
    vec = np.zeros(F.DIM, dtype=np.float64)
    vec[0:512] = np.asarray(F.extract(data)[0:512])  # byte blocks are trivial; checked separately
    vec[512:616] = np.asarray(F.extract(data)[512:616])
    b = lief.PE.parse(list(data))
    if b is None:
        return vec
    dirs = {d.type: d for d in b.data_directories}

    def present(t):
        d = dirs.get(t)
        return int(d is not None and d.rva != 0 and d.size != 0)

    D = lief.PE.DataDirectory.TYPES
    imports = {}
    for lib in b.imports:
        imports.setdefault(lib.name, [])
        for e in lib.entries:
            imports[lib.name].append("ordinal" + str(e.ordinal) if e.is_ordinal else e.name[:10000])
    exports = [e.name for e in b.get_export().entries if e.name] if b.has_exports else []
    vec[616:626] = [len(data), b.optional_header.sizeof_image, present(D.DEBUG_DIR), len(exports),
                    sum(len(v) for v in imports.values()), present(D.BASE_RELOCATION_TABLE), present(D.RESOURCE_TABLE),
                    present(D.CERTIFICATE_TABLE), present(D.TLS_TABLE), b.header.numberof_symbols]
    h, o = b.header, b.optional_header
    machine = F.MACHINES.get(int(h.machine), "UNKNOWN")
    chars = [lbl for bit, lbl in F.HEADER_CHARACTERISTICS if int(h.characteristics) & bit]
    dllc = [lbl for bit, lbl in F.DLL_CHARACTERISTICS if int(o.dll_characteristics) & bit]
    magic = "PE32_PLUS" if int(o.magic) == 0x20B else "PE32"
    vec[626:688] = np.hstack([h.time_date_stamps, _hash(10, "string", [machine]), _hash(10, "string", chars),
                              _hash(10, "string", [F.SUBSYSTEMS.get(int(o.subsystem), "UNKNOWN")]), _hash(10, "string", dllc),
                              _hash(10, "string", [magic]), o.major_image_version, o.minor_image_version, o.major_linker_version,
                              o.minor_linker_version, o.major_operating_system_version, o.minor_operating_system_version,
                              o.major_subsystem_version, o.minor_subsystem_version, o.sizeof_code, o.sizeof_headers,
                              o.sizeof_heap_commit])
    secs = []
    for s in b.sections:
        props = [lbl for bit, lbl in F.SECTION_CHARACTERISTICS if s.characteristics & bit]
        align = (s.characteristics >> 20) & 0xF
        if align in F.ALIGNMENTS:
            props.append(F.ALIGNMENTS[align])
        secs.append({"name": s.name, "size": s.sizeof_raw_data, "entropy": s.entropy, "vsize": s.virtual_size, "props": props})
    entry = next((s["name"] for s in secs if "MEM_EXECUTE" in s["props"]), "")
    vec[688:943] = np.hstack([
        [len(secs), sum(1 for s in secs if s["size"] == 0), sum(1 for s in secs if s["name"] == ""),
         sum(1 for s in secs if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
         sum(1 for s in secs if "MEM_WRITE" in s["props"])],
        _hash(50, "pair", [(s["name"], s["size"]) for s in secs]), _hash(50, "pair", [(s["name"], s["entropy"]) for s in secs]),
        _hash(50, "pair", [(s["name"], s["vsize"]) for s in secs]), _hash(50, "string", list(entry)),
        _hash(50, "string", [p for s in secs if s["name"] == entry for p in s["props"]])])
    vec[943:2223] = np.hstack([_hash(256, "string", list({k.lower() for k in imports})),
                               _hash(1024, "string", [k.lower() + ":" + e for k, v in imports.items() for e in v])])
    vec[2223:2351] = _hash(128, "string", exports)
    for i, d in enumerate(list(b.data_directories)[:15]):
        vec[2351 + 2 * i], vec[2351 + 2 * i + 1] = d.size, d.rva
    return vec
