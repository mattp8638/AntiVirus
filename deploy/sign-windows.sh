#!/bin/sh
# Authenticode-sign Windows binaries during the image build (deploy/Dockerfile).
#
#   sign-windows.sh <file-or-directory>...     (no arguments: only check the signing set-up)
#
# Two ways to sign, both passed as BuildKit secrets so nothing lands in an image layer:
#
#   codesign_azure     Azure Trusted Signing (Microsoft's managed signing service; recommended). A small KEY=VALUE file:
#                        AZURE_TENANT_ID=...            the Entra tenant of the signing account
#                        AZURE_CLIENT_ID=...            an app registration with the "Trusted Signing Certificate
#                        AZURE_CLIENT_SECRET=...          Profile Signer" role on the certificate profile
#                        TRUSTED_SIGNING_ENDPOINT=weu.codesigning.azure.net   (the account's region endpoint)
#                        TRUSTED_SIGNING_ACCOUNT=...    the Trusted Signing account name
#                        TRUSTED_SIGNING_PROFILE=...    the certificate profile name
#                      Signing uses jsign (downloaded and checked against a pinned SHA-256) and a Java runtime.
#   codesign_pfx       a .pfx certificate (OV/EV from a certificate authority, or self-signed for a lab)
#   codesign_password  its password (optional; empty for a password-less .pfx)
#
# An empty secret means "not used". Azure Trusted Signing wins when both are given.
# Keys and tokens stay in a private temporary directory or the environment and are gone when the script exits.
# Files that already carry a signature (for example Microsoft's WebView2Loader.dll) are left alone.
# Writes /out/windows/signing.json and the signer's public certificate /out/windows/fenrir-codesign.cer.
set -eu

PFX=${CODESIGN_PFX:-/run/secrets/codesign_pfx}
PASSWORD_FILE=${CODESIGN_PASSWORD_FILE:-/run/secrets/codesign_password}
AZURE_FILE=${CODESIGN_AZURE_FILE:-/run/secrets/codesign_azure}
OUT=${SIGN_OUT:-/out/windows}
SIGN_NAME=${FENRIR_CODESIGN_NAME:-Fenrir Endpoint}
SIGN_URL=${FENRIR_CODESIGN_URL:-https://github.com/Palmertech-Webdev/fenrir-security}
JSIGN_VERSION=7.2
JSIGN_SHA256=9a99673bb011cc1d7faf00bc840a6b333fc8a9b596098da2f92946b68297f067
JSIGN=${JSIGN_JAR:-/opt/jsign/jsign-$JSIGN_VERSION.jar}
mkdir -p "$OUT"

PROFILE=${FENRIR_BUILD_PROFILE:-production}
case "$PROFILE" in production|lab) ;; *) echo "sign-windows: FENRIR_BUILD_PROFILE must be 'production' or 'lab' (got '$PROFILE')" >&2; exit 2 ;; esac

if [ -s "$AZURE_FILE" ]; then
  METHOD=azure
elif [ -s "$PFX" ]; then
  METHOD=pfx
else
  if [ "$PROFILE" = "production" ]; then
    cat >&2 <<'MSG'
sign-windows: ERROR: the production build profile needs Windows code signing, and none was set up.
  Fix one of:
    - Azure Trusted Signing (recommended): put its settings in deploy/signing/azure-trusted-signing.env, or
    - put a certificate at deploy/signing/codesign.pfx (and its password in deploy/signing/codesign.password), or
    - point FENRIR_CODESIGN_AZURE / FENRIR_CODESIGN_PFX / FENRIR_CODESIGN_PASSWORD_FILE at them, or
    - for a test/lab server only, set FENRIR_BUILD_PROFILE=lab in deploy/.env (or add -f deploy/docker-compose.lab.yml)
      to build clearly-labelled unsigned agents.
  See docs/CODE_SIGNING.md.
MSG
    exit 3
  fi
  echo "sign-windows: lab profile: no code signing set up; the Windows build is UNSIGNED (unsigned-lab)."
  [ -f "$OUT/signing.json" ] || echo '{"signed": false, "profile": "lab"}' > "$OUT/signing.json"
  exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

# ---------------------------------------------------------------------------------------------------------------------
# Azure Trusted Signing

# One setting from the KEY=VALUE file (read, never sourced), without surrounding quotes or spaces.
azure_setting() {
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$AZURE_FILE" | tail -n 1 | tr -d '\r' \
    | sed 's/[[:space:]]*$//; s/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/'
}

ensure_jsign() {
  if ! command -v java >/dev/null 2>&1; then
    if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null 2>&1; then
      echo "sign-windows: installing a Java runtime for jsign"
      apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends default-jre-headless >/dev/null
    else
      echo "sign-windows: Azure Trusted Signing needs Java (for jsign); install a Java runtime" >&2; exit 1
    fi
  fi
  if [ ! -s "$JSIGN" ]; then
    mkdir -p "$(dirname "$JSIGN")"
    python3 -c 'import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
      "https://github.com/ebourg/jsign/releases/download/$JSIGN_VERSION/jsign-$JSIGN_VERSION.jar" "$JSIGN.part" || {
      echo "sign-windows: could not download jsign $JSIGN_VERSION from github.com" >&2; rm -f "$JSIGN.part"; exit 1; }
    mv "$JSIGN.part" "$JSIGN"
  fi
  if [ "$(sha256sum "$JSIGN" | cut -d' ' -f1)" != "$JSIGN_SHA256" ]; then
    echo "sign-windows: $JSIGN does not match the pinned SHA-256; refusing to use it" >&2; rm -f "$JSIGN"; exit 1
  fi
}

# An access token for the signing service (client credentials). The secret goes through the environment, not argv.
azure_token() {
  AZ_TENANT=$TENANT AZ_CLIENT=$CLIENT AZ_SECRET=$SECRET python3 - <<'PY'
import json, os, sys, urllib.error, urllib.parse, urllib.request
body = urllib.parse.urlencode({
    "grant_type": "client_credentials", "client_id": os.environ["AZ_CLIENT"],
    "client_secret": os.environ["AZ_SECRET"], "scope": "https://codesigning.azure.net/.default"}).encode()
url = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % urllib.parse.quote(os.environ["AZ_TENANT"])
try:
    with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=30) as response:
        print(json.load(response)["access_token"])
except urllib.error.HTTPError as error:
    try:
        detail = json.load(error).get("error_description", "").splitlines()[0]
    except Exception:
        detail = ""
    sys.exit("sign-windows: Entra refused the signing credentials (HTTP %s) %s" % (error.code, detail))
except Exception as error:
    sys.exit("sign-windows: could not reach Entra for a signing token: %s" % error)
PY
}

if [ "$METHOD" = azure ]; then
  TENANT=$(azure_setting AZURE_TENANT_ID); CLIENT=$(azure_setting AZURE_CLIENT_ID); SECRET=$(azure_setting AZURE_CLIENT_SECRET)
  ENDPOINT=$(azure_setting TRUSTED_SIGNING_ENDPOINT | sed 's#^https\{0,1\}://##; s#/*$##')
  ACCOUNT=$(azure_setting TRUSTED_SIGNING_ACCOUNT); CERT_PROFILE=$(azure_setting TRUSTED_SIGNING_PROFILE)
  for pair in "AZURE_TENANT_ID:$TENANT" "AZURE_CLIENT_ID:$CLIENT" "AZURE_CLIENT_SECRET:$SECRET" \
              "TRUSTED_SIGNING_ENDPOINT:$ENDPOINT" "TRUSTED_SIGNING_ACCOUNT:$ACCOUNT" "TRUSTED_SIGNING_PROFILE:$CERT_PROFILE"; do
    if [ -z "${pair#*:}" ]; then echo "sign-windows: ${pair%%:*} is missing from the Azure Trusted Signing settings" >&2; exit 1; fi
  done
  case "$ENDPOINT" in *.codesigning.azure.net) ;; *)
    echo "sign-windows: TRUSTED_SIGNING_ENDPOINT should look like weu.codesigning.azure.net (got '$ENDPOINT')" >&2; exit 1 ;; esac
  ensure_jsign
  # Fetching a token checks the credentials before anything is compiled (the preflight call has no files).
  FENRIR_TS_TOKEN=$(azure_token)
  export FENRIR_TS_TOKEN
  echo "sign-windows: Azure Trusted Signing ready ($ACCOUNT/$CERT_PROFILE at $ENDPOINT)"
else
  PASS=""
  [ -s "$PASSWORD_FILE" ] && PASS=$(cat "$PASSWORD_FILE")
  # PEM files: osslsigncode cannot read the legacy (3DES) .pfx that Windows exports.
  (umask 077
   openssl pkcs12 -in "$PFX" -passin "pass:$PASS" -nokeys 2>/dev/null | openssl x509 -out "$WORK/cert.pem"
   openssl pkcs12 -in "$PFX" -passin "pass:$PASS" -nocerts -nodes 2>/dev/null | openssl pkey -out "$WORK/key.pem") || {
    echo "sign-windows: could not read the certificate (wrong password?)" >&2; exit 1; }
fi

already_signed() {
  osslsigncode verify -in "$1" >/dev/null 2>&1 || osslsigncode extract-signature -in "$1" -out "$WORK/existing.sig" >/dev/null 2>&1
}

sign_azure() {
  f=$1
  # Trusted Signing certificates last three days, so a timestamp is required: without one the file would stop
  # verifying almost at once. Try twice, then fail the build.
  for attempt in 1 2; do
    if java -jar "$JSIGN" --storetype TRUSTEDSIGNING --keystore "$ENDPOINT" --storepass env:FENRIR_TS_TOKEN \
         --alias "$ACCOUNT/$CERT_PROFILE" --alg SHA-256 --tsaurl http://timestamp.acs.microsoft.com --tsmode RFC3161 \
         --name "$SIGN_NAME" --url "$SIGN_URL" "$f" >"$WORK/jsign.log" 2>&1; then
      echo "sign-windows: signed with Azure Trusted Signing (timestamped): $f"; return 0
    fi
    [ "$attempt" = 1 ] && sleep 5
  done
  echo "sign-windows: Azure Trusted Signing failed for $f:" >&2
  sed 's/^/  /' "$WORK/jsign.log" >&2
  exit 1
}

sign_pfx() {
  f=$1
  # A timestamp keeps the signature valid after the certificate expires; try two services, then sign without.
  for ts in http://timestamp.digicert.com http://timestamp.sectigo.com; do
    if osslsigncode sign -certs "$WORK/cert.pem" -key "$WORK/key.pem" -n "$SIGN_NAME" -i "$SIGN_URL" \
         -h sha256 -ts "$ts" -in "$f" -out "$f.signed" >/dev/null 2>&1; then
      mv "$f.signed" "$f"; echo "sign-windows: signed (timestamped): $f"; return 0
    fi
    rm -f "$f.signed"
  done
  osslsigncode sign -certs "$WORK/cert.pem" -key "$WORK/key.pem" -n "$SIGN_NAME" -i "$SIGN_URL" \
    -h sha256 -in "$f" -out "$f.signed" >/dev/null
  mv "$f.signed" "$f"
  echo "sign-windows: signed WITHOUT a timestamp (no timestamp service reachable): $f"
}

sign_one() {
  if already_signed "$1"; then echo "sign-windows: already signed, kept: $1"; return 0; fi
  if [ "$METHOD" = azure ]; then sign_azure "$1"; else sign_pfx "$1"; fi
}

for target in "$@"; do
  if [ -d "$target" ]; then
    find "$target" -type f \( -iname '*.exe' -o -iname '*.dll' \) | sort | while read -r f; do sign_one "$f"; done
  else
    sign_one "$target"
  fi
done

# Preflight (no files named): the set-up works; the record is written once something is signed.
[ "$#" -gt 0 ] || exit 0

if [ "$METHOD" = azure ]; then
  # The signer is whatever certificate the service issued today: read it back from the last file named.
  last=""
  for target in "$@"; do [ -f "$target" ] && last=$target; done
  [ -n "$last" ] || exit 0
  osslsigncode extract-signature -pem -in "$last" -out "$WORK/sig.pem" >/dev/null 2>&1 || {
    echo "sign-windows: could not read back the signature of $last" >&2; exit 1; }
  openssl pkcs7 -in "$WORK/sig.pem" -print_certs -out "$WORK/chain.pem" >/dev/null 2>&1
  # The leaf is the certificate whose subject is not one of Microsoft's issuing CAs.
  awk -v dir="$WORK" '/BEGIN CERT/{n++} {print > (dir "/c" n ".pem")}' "$WORK/chain.pem"
  for c in "$WORK"/c*.pem; do
    subject=$(openssl x509 -in "$c" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//') || continue
    case "$subject" in *Microsoft*) ;; "") ;; *) cp "$c" "$WORK/cert.pem"; break ;; esac
  done
  [ -s "$WORK/cert.pem" ] || { echo "sign-windows: no signer certificate found in $last" >&2; exit 1; }
  MODE_JSON='"method": "azure-trusted-signing", '
else
  MODE_JSON='"method": "pfx", '
fi

SUBJECT=$(openssl x509 -in "$WORK/cert.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
SHA1=$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
EXPIRES=$(openssl x509 -in "$WORK/cert.pem" -noout -enddate | sed 's/notAfter=//')
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$OUT/fenrir-codesign.cer"

# Report whether the files named directly (the installer, signed last) carry a timestamp.
# (Azure signatures always are: sign_azure fails rather than sign without one.)
ts_json=true
if [ "$METHOD" = pfx ]; then
  for target in "$@"; do
    if [ -f "$target" ] && ! osslsigncode verify -CAfile "$WORK/cert.pem" -in "$target" 2>/dev/null | grep -qi "timestamp time"; then
      ts_json=false
    fi
  done
fi
SUBJECT_JSON=$(printf '%s' "$SUBJECT" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '{"signed": true, "profile": "%s", %s"signer": "%s", "signerSha1": "%s", "expires": "%s", "timestamped": %s}\n' \
  "$PROFILE" "$MODE_JSON" "$SUBJECT_JSON" "$SHA1" "$EXPIRES" "$ts_json" > "$OUT/signing.json"
