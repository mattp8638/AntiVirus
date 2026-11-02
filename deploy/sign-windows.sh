#!/bin/sh
# Authenticode-sign Windows binaries during the image build (deploy/Dockerfile).
#
#   sign-windows.sh <file-or-directory>...
#
# The certificate comes from BuildKit secrets so it never lands in an image layer:
#   codesign_pfx       the .pfx (an empty file means: build unsigned)
#   codesign_password  its password (optional; empty for a password-less .pfx)
# Keys are extracted to a private temporary directory and removed when the script exits.
# Files that already carry a signature (for example Microsoft's WebView2Loader.dll) are left alone.
# Writes /out/windows/signing.json and the public certificate /out/windows/fenrir-codesign.cer.
set -eu

PFX=${CODESIGN_PFX:-/run/secrets/codesign_pfx}
PASSWORD_FILE=${CODESIGN_PASSWORD_FILE:-/run/secrets/codesign_password}
OUT=${SIGN_OUT:-/out/windows}
mkdir -p "$OUT"

PROFILE=${FENRIR_BUILD_PROFILE:-production}
case "$PROFILE" in production|lab) ;; *) echo "sign-windows: FENRIR_BUILD_PROFILE must be 'production' or 'lab' (got '$PROFILE')" >&2; exit 2 ;; esac

if [ ! -s "$PFX" ]; then
  if [ "$PROFILE" = "production" ]; then
    cat >&2 <<'MSG'
sign-windows: ERROR: the production build profile needs a Windows code-signing certificate, and none was supplied.
  Fix one of:
    - put the certificate at deploy/signing/codesign.pfx (and its password in deploy/signing/codesign.password), or
    - point FENRIR_CODESIGN_PFX / FENRIR_CODESIGN_PASSWORD_FILE at them, or
    - for a test/lab server only, set FENRIR_BUILD_PROFILE=lab in deploy/.env (or add -f deploy/docker-compose.lab.yml)
      to build clearly-labelled unsigned agents.
  See docs/CODE_SIGNING.md.
MSG
    exit 3
  fi
  echo "sign-windows: lab profile: no code-signing certificate; the Windows build is UNSIGNED (unsigned-lab)."
  [ -f "$OUT/signing.json" ] || echo '{"signed": false, "profile": "lab"}' > "$OUT/signing.json"
  exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
PASS=""
[ -s "$PASSWORD_FILE" ] && PASS=$(cat "$PASSWORD_FILE")
# PEM files: osslsigncode cannot read the legacy (3DES) .pfx that Windows exports.
(umask 077
 openssl pkcs12 -in "$PFX" -passin "pass:$PASS" -nokeys 2>/dev/null | openssl x509 -out "$WORK/cert.pem"
 openssl pkcs12 -in "$PFX" -passin "pass:$PASS" -nocerts -nodes 2>/dev/null | openssl pkey -out "$WORK/key.pem") || {
  echo "sign-windows: could not read the certificate (wrong password?)" >&2; exit 1; }

SUBJECT=$(openssl x509 -in "$WORK/cert.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
SHA1=$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
EXPIRES=$(openssl x509 -in "$WORK/cert.pem" -noout -enddate | sed 's/notAfter=//')
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$OUT/fenrir-codesign.cer"

sign_one() {
  f=$1
  if osslsigncode verify -in "$f" >/dev/null 2>&1 || osslsigncode extract-signature -in "$f" -out "$WORK/existing.sig" >/dev/null 2>&1; then
    echo "sign-windows: already signed, kept: $f"; return 0
  fi
  # A timestamp keeps the signature valid after the certificate expires; try two services, then sign without.
  for ts in http://timestamp.digicert.com http://timestamp.sectigo.com; do
    if osslsigncode sign -certs "$WORK/cert.pem" -key "$WORK/key.pem" -n "Fenrir Endpoint" -i "https://fenrir-security.co.uk" \
         -h sha256 -ts "$ts" -in "$f" -out "$f.signed" >/dev/null 2>&1; then
      mv "$f.signed" "$f"; echo "sign-windows: signed (timestamped): $f"; return 0
    fi
    rm -f "$f.signed"
  done
  osslsigncode sign -certs "$WORK/cert.pem" -key "$WORK/key.pem" -n "Fenrir Endpoint" -i "https://fenrir-security.co.uk" \
    -h sha256 -in "$f" -out "$f.signed" >/dev/null
  mv "$f.signed" "$f"
  echo "sign-windows: signed WITHOUT a timestamp (no timestamp service reachable): $f"
}

for target in "$@"; do
  if [ -d "$target" ]; then
    find "$target" -type f \( -iname '*.exe' -o -iname '*.dll' \) | sort | while read -r f; do sign_one "$f"; done
  else
    sign_one "$target"
  fi
done

# Report whether the files named directly (the installer, signed last) carry a timestamp.
ts_json=true
for target in "$@"; do
  if [ -f "$target" ] && ! osslsigncode verify -CAfile "$WORK/cert.pem" -in "$target" 2>/dev/null | grep -qi "timestamp time"; then
    ts_json=false
  fi
done
printf '{"signed": true, "profile": "%s", "signer": "%s", "signerSha1": "%s", "expires": "%s", "timestamped": %s}\n' \
  "$PROFILE" "$SUBJECT" "$SHA1" "$EXPIRES" "$ts_json" > "$OUT/signing.json"
