#!/usr/bin/env bash
#
# Generates cross-check fixtures with real tooling (openssl, keytool, jarsigner)
# and records what that tooling reports, so the integration test compares this
# library's output against an independent implementation rather than its own.
#
# Requires: openssl, keytool, jarsigner, zip. Output goes to test/real/, which is
# gitignored — run this before `node dist/test/integration.js`.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/real"
rm -rf "$out"
mkdir -p "$out/jar/META-INF" "$out/jar/assets"
cd "$out"

# --- Certificates ----------------------------------------------------------

openssl req -x509 -newkey rsa:2048 -keyout rsa-key.pem -out rsa-cert.pem \
  -days 3650 -nodes -sha256 \
  -subj "/C=US/O=Smart Realty Inc/CN=Smart Realty Test" >/dev/null 2>&1
openssl x509 -in rsa-cert.pem -outform DER -out rsa-cert.der

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout ec-key.pem -out ec-cert.pem -days 3650 -nodes -sha256 \
  -subj "/C=GB/O=Realty EC/CN=Realty EC Signing" >/dev/null 2>&1
openssl x509 -in ec-cert.pem -outform DER -out ec-cert.der

# A SignedData carrying the certificate — the same structure a META-INF/*.RSA holds.
openssl crl2pkcs7 -nocrl -certfile rsa-cert.pem -outform DER -out certs.p7b

# --- Signed JAR (the v1 / JAR signing scheme an APK uses) ------------------

printf 'listing data for the smart realty demo\n' > jar/assets/listings.txt
printf 'binary-ish payload %s\n' "$(head -c 512 /dev/zero | tr '\0' 'A')" > jar/assets/blob.bin
printf 'placeholder manifest\n' > jar/AndroidManifest.txt

( cd jar && zip -q -r ../unsigned.jar . -x 'META-INF/*' )
cp unsigned.jar signed.jar

keytool -genkeypair -keystore ks.jks -storepass password -keypass password \
  -alias signer -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 3650 \
  -dname "CN=Smart Realty Test, O=Smart Realty Inc, C=US" >/dev/null 2>&1

jarsigner -keystore ks.jks -storepass password -keypass password \
  -sigalg SHA256withRSA -digestalg SHA-256 signed.jar signer >/dev/null 2>&1

# --- Reference values from the independent tools ---------------------------

rsa_subject="$(openssl x509 -in rsa-cert.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
rsa_issuer="$(openssl x509 -in rsa-cert.pem -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"
rsa_serial="$(openssl x509 -in rsa-cert.pem -noout -serial | sed 's/^serial=//')"
rsa_fingerprint="$(openssl x509 -in rsa-cert.pem -noout -fingerprint -sha256 | sed 's/^.*Fingerprint=//')"
rsa_not_before="$(openssl x509 -in rsa-cert.pem -noout -startdate | sed 's/^notBefore=//')"
rsa_not_after="$(openssl x509 -in rsa-cert.pem -noout -enddate | sed 's/^notAfter=//')"
ec_subject="$(openssl x509 -in ec-cert.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
ec_fingerprint="$(openssl x509 -in ec-cert.pem -noout -fingerprint -sha256 | sed 's/^.*Fingerprint=//')"
jar_cert_fingerprint="$(keytool -list -keystore ks.jks -storepass password -alias signer -v \
  | sed -n 's/.*SHA256: //p' | head -1)"

python3 - "$rsa_subject" "$rsa_issuer" "$rsa_serial" "$rsa_fingerprint" \
  "$rsa_not_before" "$rsa_not_after" "$ec_subject" "$ec_fingerprint" \
  "$jar_cert_fingerprint" <<'PY'
import json, sys, datetime
keys = ["rsaSubject","rsaIssuer","rsaSerial","rsaFingerprintSha256",
        "rsaNotBefore","rsaNotAfter","ecSubject","ecFingerprintSha256",
        "jarCertFingerprintSha256"]
values = sys.argv[1:10]
data = dict(zip(keys, values))
for field in ("rsaNotBefore", "rsaNotAfter"):
    # e.g. "Jan  1 00:00:00 2025 GMT" -> ISO-8601
    parsed = datetime.datetime.strptime(data[field], "%b %d %H:%M:%S %Y %Z")
    data[field] = parsed.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
json.dump(data, open("expected.json", "w"), indent=2)
PY

echo "wrote fixtures to $out"
