"""Email security, phase 3: a model that learns from your labels and Microsoft's verdicts.

What it learns from: the numbers Fenrir already keeps for every scanned message (``EmailScan.features``: which checks
fired, link and attachment counts, authentication results, first contact...), never the message content. Microsoft's
own scores are left out of the inputs on purpose, so the model learns to recognise phishing itself and works the same
on mail passing through Fenrir's gateway, where there are no Microsoft headers.

Labels, strongest first:
1. A technician's label: phish or malware = bad; safe or spam = not phishing. Counted three times.
2. Microsoft's verdict: phish or malware = bad; clean with a spam confidence of 1 or less = good. Counted once, with no
   more than ten good messages for every bad one so a quiet tenant does not drown the signal.

How: logistic regression with L2 regularisation, trained in plain Python on sparse features (no extra libraries), on
80% of the examples; the other 20% measure it. It becomes **active** only with at least ``MIN_SAMPLES`` examples,
``MIN_POSITIVES`` bad ones, and, on the held-out 20%, precision of at least ``MIN_PRECISION`` and recall of at least
``MIN_RECALL`` at its threshold. Otherwise it is kept, with the reason, and the rules carry on alone.

How it is used: when active, ``email_security.analyse`` asks it for a probability. At or above the threshold, on a
message the rules did not already flag, it adds a reason ("Looks like the phishing flagged here before"). It never
lowers a score, so it can only catch more, and every verdict still says why.

Retraining: once a day when there are new labels or verdicts, and on demand from the console. One model serves every
customer of the installation (features only, no content, cross the customer boundary).
"""
from __future__ import annotations

import logging
import math
import random
from datetime import timedelta
from time import monotonic

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import EmailModel, EmailScan, utcnow

log = logging.getLogger("fenrir.email.model")

MIN_SAMPLES = 200
MIN_POSITIVES = 30
MIN_PRECISION = 0.90
MIN_RECALL = 0.30
THRESHOLD = 0.80
MAX_SAMPLES = 20000
EPOCHS = 60
LEARNING_RATE = 0.2
L2 = 1e-3
LABEL_WEIGHT = 3.0
RETRAIN_EVERY = timedelta(hours=24)
NUMERIC = ("intel_url", "intel_attachment", "attachments", "url_count", "link_mismatch", "link_ip", "external",
           "free_mail", "first_contact", "scam_phrases", "spf_fail", "dkim_pass", "dmarc_fail", "compauth_fail")
_cache: dict = {"at": 0.0, "model": None}


class Model:
    """A trained model, ready to score features."""

    def __init__(self, row: EmailModel):
        self.id, self.version, self.threshold = row.id, row.version, row.threshold or THRESHOLD
        self.bias = float((row.weights or {}).get("bias", 0.0))
        self.weights = {k: float(v) for k, v in ((row.weights or {}).get("weights") or {}).items()}

    def probability(self, features: dict) -> float:
        z = self.bias + sum(self.weights.get(name, 0.0) * value for name, value in vector(features))
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def vector(features: dict) -> list[tuple[str, float]]:
    """Sparse inputs from stored features: numbers (compressed) and one input per check that fired."""
    out = []
    for name in NUMERIC:
        value = features.get(name)
        if isinstance(value, (int, float)) and value:
            out.append((name, math.log1p(float(value)) if name in ("url_count", "attachments", "intel_url") else float(value)))
    for code in features.get("codes") or []:
        if not str(code).startswith(("model.", "list.")):
            out.append(("code:" + str(code), 1.0))
    return out


def active(db: Session) -> Model | None:
    """The active model, re-read at most once a minute."""
    if monotonic() - _cache["at"] < 60:
        return _cache["model"]
    row = db.execute(select(EmailModel).where(EmailModel.active.is_(True)).order_by(EmailModel.version.desc()).limit(1)).scalar_one_or_none()
    _cache.update(at=monotonic(), model=Model(row) if row else None)
    return _cache["model"]


def forget_cache() -> None:
    _cache.update(at=0.0, model=None)


# --------------------------------------------------------------------------- training

def examples(db: Session) -> list[tuple[list[tuple[str, float]], int, float, str]]:
    """(inputs, 1 = bad / 0 = good, weight, where the label came from)."""
    out = []
    labelled = db.execute(select(EmailScan.features, EmailScan.label).where(EmailScan.label != "")
                          .order_by(EmailScan.received_at.desc()).limit(MAX_SAMPLES)).all()
    for features, label in labelled:
        out.append((vector(features or {}), int(label in ("phish", "malware")), LABEL_WEIGHT, "label"))
    bad = db.execute(select(EmailScan.features).where(EmailScan.label == "", EmailScan.microsoft_verdict.in_(("phish", "malware")))
                     .order_by(EmailScan.received_at.desc()).limit(MAX_SAMPLES // 4)).scalars().all()
    out += [(vector(f or {}), 1, 1.0, "microsoft") for f in bad]
    limit = max(10 * (len(bad) + sum(1 for e in out if e[1] == 1 and e[3] == "label")), 200)
    good = db.execute(select(EmailScan.features, EmailScan.microsoft).where(
        EmailScan.label == "", EmailScan.microsoft_verdict == "clean").order_by(EmailScan.received_at.desc())
        .limit(min(limit, MAX_SAMPLES))).all()
    for features, microsoft in good:
        scl = (microsoft or {}).get("scl")
        if scl is None or scl <= 1:
            out.append((vector(features or {}), 0, 1.0, "microsoft"))
    return out[:MAX_SAMPLES]


def fit(rows: list[tuple[list[tuple[str, float]], int, float, str]], seed: int = 7) -> tuple[float, dict[str, float]]:
    """Weighted logistic regression by stochastic gradient descent on sparse inputs."""
    rng = random.Random(seed)
    weights: dict[str, float] = {}
    positives = sum(w for _, y, w, _ in rows if y == 1) or 1.0
    total = sum(w for _, _, w, _ in rows) or 1.0
    bias = math.log(positives / max(total - positives, 1.0))
    order = list(range(len(rows)))
    for epoch in range(EPOCHS):
        rng.shuffle(order)
        rate = LEARNING_RATE / (1 + epoch * 0.05)
        for i in order:
            inputs, label, weight, _ = rows[i]
            z = bias + sum(weights.get(n, 0.0) * v for n, v in inputs)
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            gradient = (p - label) * weight
            bias -= rate * gradient
            for name, value in inputs:
                current = weights.get(name, 0.0)
                weights[name] = current - rate * (gradient * value + L2 * current)
    return bias, {k: round(v, 5) for k, v in weights.items() if abs(v) > 1e-4}


def evaluate(bias: float, weights: dict[str, float], rows, threshold: float) -> dict:
    tp = fp = fn = tn = 0
    for inputs, label, _, _ in rows:
        z = bias + sum(weights.get(n, 0.0) * v for n, v in inputs)
        flagged = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z)))) >= threshold
        if flagged and label:
            tp += 1
        elif flagged:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None, "tested": len(rows)}


def train(db: Session, actor: str = "system:email-model") -> EmailModel:
    """Train a new version, measure it on held-out examples and make it active only if it is good enough."""
    rows = examples(db)
    rng = random.Random(11)
    bad = [r for r in rows if r[1] == 1]
    good = [r for r in rows if r[1] == 0]
    rng.shuffle(bad)
    rng.shuffle(good)
    cut_bad, cut_good = int(len(bad) * 0.8), int(len(good) * 0.8)
    train_rows, test_rows = bad[:cut_bad] + good[:cut_good], bad[cut_bad:] + good[cut_good:]
    version = (db.execute(select(func.max(EmailModel.version))).scalar() or 0) + 1
    labelled = sum(1 for r in rows if r[3] == "label")
    row = EmailModel(version=version, samples=len(rows), positives=len(bad), labelled=labelled, threshold=THRESHOLD,
                     trained_by=actor, active=False)
    if len(rows) < MIN_SAMPLES or len(bad) < MIN_POSITIVES:
        row.reason = (f"Not enough examples yet: {len(rows)} messages ({len(bad)} phishing or malware). It needs "
                      f"{MIN_SAMPLES} and {MIN_POSITIVES}. Keep scanning, and label what the two sides disagree on.")
        row.weights, row.metrics = {}, {}
    else:
        bias, weights = fit(train_rows)
        metrics = evaluate(bias, weights, test_rows, THRESHOLD)
        row.weights, row.metrics = {"bias": round(bias, 5), "weights": weights}, metrics
        good_enough = (metrics["precision"] or 0) >= MIN_PRECISION and (metrics["recall"] or 0) >= MIN_RECALL
        if good_enough:
            row.active = True
            row.reason = (f"Active: on {metrics['tested']} held-back messages it was right {round(100 * (metrics['precision'] or 0))}% "
                          f"of the times it flagged one, and caught {round(100 * (metrics['recall'] or 0))}% of the phishing.")
        else:
            row.reason = (f"Not accurate enough to use yet (precision {metrics['precision']}, recall {metrics['recall']} on "
                          f"{metrics['tested']} held-back messages; it needs {MIN_PRECISION} and {MIN_RECALL}). The rules carry on alone.")
    if row.active:
        db.query(EmailModel).filter(EmailModel.active.is_(True)).update({"active": False})
    db.add(row)
    db.flush()
    forget_cache()
    log.info("email model v%s: %s", version, row.reason)
    return row


def maybe_retrain(db: Session) -> EmailModel | None:
    """Daily, when there is anything new to learn from."""
    last = db.execute(select(EmailModel).order_by(EmailModel.version.desc()).limit(1)).scalar_one_or_none()
    now = utcnow()
    if last and now - last.created_at < RETRAIN_EVERY:
        return None
    since = last.created_at if last else now - timedelta(days=3650)
    fresh = db.execute(select(func.count()).select_from(EmailScan).where(
        (EmailScan.labelled_at >= since) | (EmailScan.scanned_at >= since))).scalar() or 0
    if last and fresh == 0:
        return None
    return train(db)


def view(row: EmailModel | None) -> dict | None:
    if row is None:
        return None
    top = sorted(((row.weights or {}).get("weights") or {}).items(), key=lambda kv: -kv[1])
    return {"id": row.id, "version": row.version, "createdAt": row.created_at.isoformat() + "Z", "samples": row.samples,
            "positives": row.positives, "labelled": row.labelled, "metrics": row.metrics or {}, "threshold": row.threshold,
            "active": row.active, "reason": row.reason, "trainedBy": row.trained_by,
            "strongestSignals": [{"input": k, "weight": v} for k, v in top[:8] if v > 0]}
