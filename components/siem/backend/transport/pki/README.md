# PKI (Transport)

Scope: Transport-managed public key infrastructure for platform mTLS.

Goals (MVP-1):
- Root CA created offline.
- Intermediate CA managed by the platform.
- Strict TLS 1.3 and mTLS enforcement.
- Certificate pinning in the agent.

## Offline CA Generation (Python)
This helper script is intended for offline CA creation. It writes PEM files to
an output directory you control (never commit private keys).

```bash
cd transport/pki
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python tools/generate_ca.py --output ./output
```

To generate an intermediate CA using an existing root:

```bash
python tools/generate_ca.py \
  --output ./output \
  --root-key /secure/root/root-ca.key.pem \
  --root-cert /secure/root/root-ca.cert.pem
```

Constraints:
- No direct network operations outside the /transport module.
- Private key material must be stored in OS-managed secret stores.

