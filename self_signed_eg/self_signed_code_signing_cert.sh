#!/usr/bin/env bash
set -e

export PASSPHRASE="${PASSPHRASE:-change me}"
CN="${CN:-Test Code Signing}"

# keyUsage = digitalSignature and extendedKeyUsage = codeSigning are required for code signing cert
local_openssl_config="
[ req ]
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = codesign_dn
x509_extensions = self_signed_code_sign
[ codesign_dn ]
CN = ${CN}
[ self_signed_code_sign ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
basicConstraints = CA:true
keyUsage = digitalSignature, keyCertSign
extendedKeyUsage = codeSigning, anyExtendedKeyUsage
"

openssl req \
  -newkey rsa:2048 \
  -keyout "$CN.key.pem" \
  -x509 -sha256 -days 3650 \
  -config <(echo "$local_openssl_config") \
  -passout env:PASSPHRASE \
  -out "$CN.cert.pem"
openssl pkcs12 \
  -export \
  -inkey "$CN.key.pem" -passin env:PASSPHRASE \
  -in "$CN.cert.pem" \
  -out "$CN.pfx" -passout env:PASSPHRASE
openssl x509 -noout -text -in "$CN.cert.pem"