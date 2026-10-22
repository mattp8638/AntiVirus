import json
from pathlib import Path

import pytest

from fenrir_ml import features as F
from fenrir_ml.model import Model

ROOT = Path(__file__).resolve().parents[1]


def test_golden_vectors_are_stable():
    golden = json.loads((ROOT / "testdata" / "golden-features.json").read_text())
    for name, want in golden.items():
        assert F.extract((ROOT / "testdata" / name).read_bytes()) == want


def test_lief_reference_agrees():
    pytest.importorskip("lief")
    import numpy as np

    from tests import lief_reference as R

    for name in ("hello64.exe", "hello32.exe"):
        data = (ROOT / "testdata" / name).read_bytes()
        assert np.allclose(np.asarray(F.extract(data))[616:], R.extract(data)[616:], rtol=1e-4, atol=1e-3)


def test_model_scores_test_programs_as_clean():
    model = Model.load(ROOT / "models" / "fenrir-pe-v1.json.gz")
    for name in ("hello64.exe", "hello32.exe"):
        assert model.predict(F.extract((ROOT / "testdata" / name).read_bytes())) < model.thresholds["fpr1"]
