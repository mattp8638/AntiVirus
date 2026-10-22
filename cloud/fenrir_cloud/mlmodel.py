"""Serves the static PE model to agents and scores files for analysts.

The model and feature code live in ml/ (fenrir_ml); this module only finds the
newest model, caches it, and exposes it.
"""

from __future__ import annotations

import hashlib
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from .config import get_settings

_ML_ROOT = Path(__file__).resolve().parents[2] / "ml"
if str(_ML_ROOT) not in sys.path:
    sys.path.insert(0, str(_ML_ROOT))


@dataclass
class ModelBundle:
    version: str
    fgbt_path: Path
    json_path: Path
    sha256: str
    size: int
    metrics: dict


_lock = threading.Lock()
_cache: dict[str, object] = {}


def current() -> ModelBundle | None:
    model_dir = get_settings().model_dir
    candidates = sorted(model_dir.glob("fenrir-pe-v*.fgbt"))
    if not candidates:
        return None
    fgbt = candidates[-1]
    version = fgbt.stem
    json_path = model_dir / f"{version}.json.gz"
    data = fgbt.read_bytes()
    metrics_path = model_dir / f"{version}.metrics.json"
    import json

    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
    return ModelBundle(version, fgbt, json_path, hashlib.sha256(data).hexdigest(), len(data), metrics)


def score_bytes(data: bytes) -> dict:
    from fenrir_ml import features
    from fenrir_ml.model import Model

    bundle = current()
    if bundle is None or not bundle.json_path.exists():
        return {"available": False, "reason": "no model installed"}
    if not features.is_pe(data):
        return {"available": True, "pe": False, "reason": "not a Windows PE file"}
    with _lock:
        model = _cache.get(bundle.version)
        if model is None:
            model = Model.load(bundle.json_path)
            _cache.clear()
            _cache[bundle.version] = model
    score = model.predict(features.extract(data))
    thresholds = model.thresholds
    verdict = ("malicious" if score >= thresholds.get("fpr001", 1) else "likely-malicious" if score >= thresholds.get("fpr01", 1)
               else "suspicious" if score >= thresholds.get("fpr1", 1) else "clean")
    return {"available": True, "pe": True, "score": round(score, 6), "verdict": verdict, "model": bundle.version,
            "thresholds": thresholds, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
