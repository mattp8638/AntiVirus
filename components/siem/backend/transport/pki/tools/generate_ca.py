"""Offline PKI helper to generate root and intermediate CAs.

This script is intended to be run on an offline host for the root CA, then on
an isolated platform host for the intermediate CA. It writes keys and
certificates to a specified output directory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_VALIDITY_DAYS = 3650


def _build_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANISATION_NAME, "Palmertech"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _write_pem(path: Path, data: bytes, description: str) -> None:
    path.write_bytes(data)
    print(f"Wrote {description}: {path}")


def generate_root_ca(common_name: str, output_dir: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = _build_name(common_name)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=DEFAULT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path = output_dir / "root-ca.key.pem"
    cert_path = output_dir / "root-ca.cert.pem"

    _write_pem(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        "root CA key",
    )
    _write_pem(cert_path, cert.public_bytes(serialization.Encoding.PEM), "root CA cert")

    return key_path, cert_path


def generate_intermediate_ca(
    common_name: str,
    root_key_path: Path,
    root_cert_path: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    root_key = serialization.load_pem_private_key(root_key_path.read_bytes(), None)
    root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = _build_name(common_name)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=DEFAULT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    key_path = output_dir / "intermediate-ca.key.pem"
    cert_path = output_dir / "intermediate-ca.cert.pem"

    _write_pem(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        "intermediate CA key",
    )
    _write_pem(
        cert_path,
        cert.public_bytes(serialization.Encoding.PEM),
        "intermediate CA cert",
    )

    return key_path, cert_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate root and intermediate CAs")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--root-cn", default="Palmertech Root CA")
    parser.add_argument("--intermediate-cn", default="Palmertech Platform CA")
    parser.add_argument("--root-key", help="Existing root key path")
    parser.add_argument("--root-cert", help="Existing root cert path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.root_key and args.root_cert:
        root_key_path = Path(args.root_key).expanduser().resolve()
        root_cert_path = Path(args.root_cert).expanduser().resolve()
    else:
        root_key_path, root_cert_path = generate_root_ca(args.root_cn, output_dir)

    generate_intermediate_ca(
        args.intermediate_cn,
        root_key_path,
        root_cert_path,
        output_dir,
    )


if __name__ == "__main__":
    main()

