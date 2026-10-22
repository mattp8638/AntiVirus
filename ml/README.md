# Fenrir static PE model

A gradient-boosted tree classifier for Windows executables, trained on the
public [SOREL-20M](https://github.com/sophos/SOREL-20M) EMBER-v2 features and
run on the endpoint with no file uploads.

| Piece | Where |
|---|---|
| Reference feature extractor (EMBER v2, no LIEF) | `fenrir_ml/features.py` |
| Go port (Linux agent) | `agent/linux/pkg/ml` |
| C++ port (Windows agent) | `agent/windows/service/src/MlStaticModel.cpp` |
| Model format + evaluator | `fenrir_ml/model.py` (JSON), `export_model.py` (FGBT binary) |
| Trained model | `models/fenrir-pe-v1.*` |

## Results (fenrir-pe-v1)

Trained on 700k SOREL train rows, thresholds chosen on 50k validation rows,
measured on 150k rows of SOREL's **later** test period (out-of-time):

| Policy sensitivity | Threshold | Detection rate | False-positive rate |
|---|---|---|---|
| aggressive (`fpr1`) | 0.399 | 97.4% | 0.71% |
| balanced (`fpr01`, default) | 0.854 | 94.6% | 0.064% |
| cautious (`fpr001`) | 0.973 | 90.4% | 0.014% |

Test AUC 0.9983. On 423 real clean Windows binaries (MSVC/MinGW DLLs and EXEs
from public packages) the highest score was 0.068: zero false positives at
every threshold.

## Parity

All three extractors produce bit-identical float32 vectors on the 423-file
corpus, and the Python extractor matches an independent LIEF-based
implementation. The C++ build was also checked as a Windows binary under Wine.

```bash
python -m pytest ml/tests                      # Python vs LIEF (needs lief)
cd agent/linux && go test ./pkg/ml/           # Go golden vectors
```

## Retraining

```bash
pip install -r ml/requirements.txt
python ml/sorel_sample.py train 700000 data/train
python ml/sorel_sample.py validation 50000 data/valid
python ml/sorel_sample.py test 150000 data/test --seed 11
python ml/train.py data --out ml/models/fenrir-pe-v2.json.gz
python ml/export_model.py ml/models/fenrir-pe-v2.json.gz ml/models/fenrir-pe-v2.fgbt
```

Fenrir Cloud serves the newest `fenrir-pe-v*.fgbt` at `/api/v1/agent/model`;
agents verify the SHA-256 from `/api/v1/agent/model/manifest` before installing.

## Limits

- Windows PE files only (EMBER has no ELF/Mach-O equivalent).
- Static features can be evaded by packing or padding; this is one layer next
  to signatures, behaviour rules and cloud reputation, not a replacement.
- SOREL samples date from 2017–2019. Retrain on fresher data as it becomes available.
