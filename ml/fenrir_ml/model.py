"""Fenrir gradient-boosted tree model format and a dependency-free evaluator.

Format "fenrir-gbdt-1" (JSON, usually gzipped):

    {
      "format": "fenrir-gbdt-1",
      "features": "ember-v2", "numFeatures": 2381,
      "trees": [ {"f": [...], "t": [...], "l": [...], "r": [...], "v": [...]}, ... ],
      "thresholds": {"fpr1": p, "fpr01": p, "fpr001": p},
      "metrics": {...}
    }

Per tree, internal node i tests x[f[i]] <= t[i]; l[i]/r[i] are child indices,
where a value < 0 means leaf ~value (index into v). The score is
sigmoid(sum of leaf values). Go: agent/linux/pkg/ml; C++: MlScanner.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path


class Model:
    def __init__(self, doc: dict):
        if doc.get("format") != "fenrir-gbdt-1":
            raise ValueError("unsupported model format")
        self.doc = doc
        self.trees = doc["trees"]
        self.thresholds = doc.get("thresholds", {})
        self.num_features = doc["numFeatures"]

    @classmethod
    def load(cls, path: str | Path) -> "Model":
        path = Path(path)
        raw = path.read_bytes()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return cls(json.loads(raw))

    def raw_score(self, x) -> float:
        total = 0.0
        for tree in self.trees:
            f, t, left, right, values = tree["f"], tree["t"], tree["l"], tree["r"], tree["v"]
            if not f:  # single-leaf tree
                total += values[0]
                continue
            node = 0
            while node >= 0:
                node = left[node] if float(x[f[node]]) <= t[node] else right[node]
            total += values[~node]
        return total

    def predict(self, x) -> float:
        return 1.0 / (1.0 + math.exp(-self.raw_score(x)))


def from_lightgbm(booster) -> list[dict]:
    """Convert a LightGBM booster's dump into fenrir-gbdt trees."""
    dump = booster.dump_model()
    trees = []
    for info in dump["tree_info"]:
        f, t, left, right, values = [], [], [], [], []

        def visit(node) -> int:
            if "leaf_value" in node:
                values.append(node["leaf_value"])
                return ~(len(values) - 1)
            if node["decision_type"] != "<=":
                raise ValueError(f"unsupported decision type {node['decision_type']}")
            if node.get("missing_type") not in ("None", "NaN", None):
                raise ValueError(f"unsupported missing type {node.get('missing_type')}")
            index = len(f)
            f.append(node["split_feature"])
            t.append(float(node["threshold"]))
            left.append(0)
            right.append(0)
            left[index] = visit(node["left_child"])
            right[index] = visit(node["right_child"])
            return index

        visit(info["tree_structure"])
        trees.append({"f": f, "t": t, "l": left, "r": right, "v": values})
    return trees
