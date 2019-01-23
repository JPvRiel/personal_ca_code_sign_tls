#!/usr/bin/env bash
set -e

export PASSPHRASE="${PASSPHRASE:-change me}"

if [ -z "$1" ]; then
  hostname="$HOSTNAME"
else
  hostname="$1"
fi

local_openssl_config="
[ req ]
prompt = no
distinguished_name = req_distinguished_name
x509_extensions = san_self_signed
[ req_distinguished_name ]
CN=$hostname
[ san_self_signed ]
subjectAltName = DNS:$hostname, DNS:localhost, DNS:localhost.localdomain, IP:127.0.0.1, IP:0:0:0:0:0:0:0:1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
basicConstraints = critical, CA:true
keyUsage = digitalSignature, keyAgreement, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth, clientAuth, anyExtendedKeyUsage
"

openssl req \
  -newkey rsa:2048 \
  -keyout "$hostname.key.pem" \
  -x509 -sha256 -days 3650 \
  -config <(echo "$local_openssl_config") \
  -out "$hostname.cert.pem" -passout env:PASSPHRASE
openssl pkcs12 \
  -export \
  -inkey "$hostname.key.pem" -passin env:PASSPHRASE \
  -in "$hostname.cert.pem" \
  -out "$hostname.pfx" -passout env:PASSPHRASE
openssl x509 -noout -text -in "$hostname.cert.pem"

