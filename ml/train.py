"""Train the Fenrir static PE malware model on SOREL-20M EMBER-v2 features.

    python ml/sorel_sample.py train 700000 data/train
    python ml/sorel_sample.py validation 50000 data/valid
    python ml/sorel_sample.py test 150000 data/test --seed 11
    python ml/train.py data/ --out ml/models/fenrir-pe-v1.json.gz

Thresholds are chosen on the validation split for 1%, 0.1% and 0.01% false
positive rates, then reported on the test split. SOREL's test split is later
in time than train/validation, so the test numbers are an out-of-time
estimate, not a best case.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fenrir_ml.model import Model, from_lightgbm  # noqa: E402


def load(split: Path):
    return np.load(split / "X.npy", mmap_mode="r"), np.load(split / "y.npy").astype(np.int8)


def threshold_for_fpr(scores: np.ndarray, y: np.ndarray, fpr: float) -> float:
    benign = np.sort(scores[y == 0])
    index = int(np.ceil((1 - fpr) * len(benign))) - 1
    return float(benign[min(max(index, 0), len(benign) - 1)])


def rates(scores, y, threshold):
    flagged = scores > threshold
    return {"threshold": threshold, "tpr": float(flagged[y == 1].mean()), "fpr": float(flagged[y == 0].mean())}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data", type=Path)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "models" / "fenrir-pe-v1.json.gz")
    ap.add_argument("--rounds", type=int, default=1200)
    ap.add_argument("--leaves", type=int, default=64)
    ap.add_argument("--lr", type=float, default=0.06)
    args = ap.parse_args()

    Xtr, ytr = load(args.data / "train")
    Xva, yva = load(args.data / "valid")
    Xte, yte = load(args.data / "test")
    print(f"train {Xtr.shape} malicious={ytr.mean():.3f}  valid {Xva.shape}  test {Xte.shape}", flush=True)

    params = {
        "objective": "binary", "metric": ["auc", "binary_logloss"], "num_leaves": args.leaves, "learning_rate": args.lr,
        "feature_fraction": 0.5, "bagging_fraction": 0.8, "bagging_freq": 1, "min_data_in_leaf": 100, "lambda_l2": 1.0,
        "max_bin": 255, "zero_as_missing": False, "use_missing": False, "num_threads": 0, "verbose": -1, "seed": 7,
    }
    t0 = time.time()
    train_set = lgb.Dataset(np.asarray(Xtr, dtype=np.float32), label=ytr, free_raw_data=True)
    valid_set = lgb.Dataset(np.asarray(Xva, dtype=np.float32), label=yva, reference=train_set)
    booster = lgb.train(params, train_set, num_boost_round=args.rounds, valid_sets=[valid_set], valid_names=["valid"],
                        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(50)])
    train_seconds = time.time() - t0
    print(f"trained {booster.num_trees()} trees in {train_seconds / 60:.1f} min", flush=True)

    sva = booster.predict(np.asarray(Xva, dtype=np.float32), num_iteration=booster.best_iteration)
    ste = booster.predict(np.asarray(Xte, dtype=np.float32), num_iteration=booster.best_iteration)
    thresholds = {name: threshold_for_fpr(sva, yva, fpr) for name, fpr in (("fpr1", 0.01), ("fpr01", 0.001), ("fpr001", 0.0001))}
    metrics = {
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": "SOREL-20M EMBER-v2 features (sampled)",
        "trainRows": int(len(ytr)), "validRows": int(len(yva)), "testRows": int(len(yte)),
        "trees": booster.best_iteration or booster.num_trees(), "trainMinutes": round(train_seconds / 60, 1),
        "validAuc": float(roc_auc_score(yva, sva)), "testAuc": float(roc_auc_score(yte, ste)),
        "test": {name: rates(ste, yte, thr) for name, thr in thresholds.items()},
    }
    print(json.dumps(metrics, indent=2), flush=True)

    best = booster.best_iteration or booster.num_trees()
    booster_best = lgb.Booster(model_str=booster.model_to_string(num_iteration=best))
    doc = {"format": "fenrir-gbdt-1", "name": "fenrir-pe", "version": args.out.name.split(".")[0], "features": "ember-v2",
           "numFeatures": 2381, "trees": from_lightgbm(booster_best), "thresholds": thresholds, "metrics": metrics}

    # The exported trees must reproduce LightGBM's scores.
    model = Model(doc)
    sample = np.asarray(Xte[:500], dtype=np.float32)
    ours = np.array([model.predict(row) for row in sample])
    theirs = booster_best.predict(sample)
    assert np.allclose(ours, theirs, atol=1e-6), float(np.abs(ours - theirs).max())

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.out, "wt", compresslevel=9) as fh:
        json.dump(doc, fh, separators=(",", ":"))
    (args.out.parent / (args.out.name.split(".")[0] + ".metrics.json")).write_text(json.dumps(metrics, indent=2))
    print(f"wrote {args.out} ({args.out.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
