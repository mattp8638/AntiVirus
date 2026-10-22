"""Convert a fenrir-gbdt-1 JSON model into the FGBT binary format used by the Windows agent.

    python ml/export_model.py ml/models/fenrir-pe-v1.json.gz ml/models/fenrir-pe-v1.fgbt

Layout (little-endian): "FGBT", u32 format=1, u32 numFeatures, u32 numTrees,
f64 thr_fpr1, f64 thr_fpr01, f64 thr_fpr001, u32 len + version bytes, then per
tree: u32 nodes, u32 leaves, i32 feature[nodes], f64 threshold[nodes],
i32 left[nodes], i32 right[nodes], f64 leaf[leaves].
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fenrir_ml.model import Model  # noqa: E402


def to_fgbt(model: Model) -> bytes:
    doc = model.doc
    thr = doc.get("thresholds", {})
    version = str(doc.get("version", "")).encode()
    out = [b"FGBT", struct.pack("<III", 1, doc["numFeatures"], len(model.trees)),
           struct.pack("<ddd", thr.get("fpr1", 1.0), thr.get("fpr01", 1.0), thr.get("fpr001", 1.0)),
           struct.pack("<I", len(version)), version]
    for tree in model.trees:
        n, leaves = len(tree["f"]), len(tree["v"])
        out.append(struct.pack("<II", n, leaves))
        out.append(struct.pack(f"<{n}i", *tree["f"]))
        out.append(struct.pack(f"<{n}d", *tree["t"]))
        out.append(struct.pack(f"<{n}i", *tree["l"]))
        out.append(struct.pack(f"<{n}i", *tree["r"]))
        out.append(struct.pack(f"<{leaves}d", *tree["v"]))
    return b"".join(out)


if __name__ == "__main__":
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.write_bytes(to_fgbt(Model.load(src)))
    print(f"wrote {dst} ({dst.stat().st_size / 1e6:.1f} MB)")
