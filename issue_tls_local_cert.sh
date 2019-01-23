#!/usr/bin/env bash
set -e

export CA_PASSPHRASE="${CA_PASSPHRASE:-change me}"
export TLS_PASSPHRASE="${TLS_PASSPHRASE:-change me}"

# check dependancies
type openssl >/dev/null 2>&1 || { echo "openssl is not in PATH or isn't installed. Aborting." >&2; exit 1; }

# source env vars
if [ -z "$1" ]; then
  hostname="$HOSTNAME"
else
  hostname="$1"
fi
. .env
if [ -r vars.env ]; then
. vars.env
fi
CN=${CN:=$hostname}
DN=$(dn)

openssl_tls_cert_req_conf="
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = tls_san_ext
[ req_distinguished_name ]
CN = ${CN}
[ tls_san_ext ]
keyUsage = digitalSignature, keyAgreement, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:$hostname, DNS:localhost, DNS:localhost.localdomain, IP:127.0.0.1, IP:0:0:0:0:0:0:0:1
"

# check CA dir exists
if ! [ -d "$ROOT_CA_DIR" ]; then
  echo "'$ROOT_CA_DIR' directory for the CA does not exist. Aborting." >&2 
  exit 1
fi

# Avoid overwrite of existing keys and / or cert
if [ -e "$CERT_DIR/$CN.cert.pem" ] || [ -e "$KEY_DIR/$CN.key.pem" ]; then
  echo "A file for the cert or key already exists. Aborting." >&2
  exit 1
fi

mkdir -p "$KEY_DIR" "$CERT_DIR" "$PFX_DIR" "$CSR_DIR" 
chmod 0700 "$KEY_DIR" "$PFX_DIR"

# create new csr and private key (not encrypted)
echo "# Generating CSR for '$DN' local TLS authentication cert"
openssl req -config <(echo "$openssl_tls_cert_req_conf") \
  -out "$CSR_DIR/$CN.csr.pem" \
  -subj "$DN" \
  -new -sha256 -days $((${YEARS_VALID:=DEFAULT_YEARS_VALID} * 356)) \
  -newkey rsa:2048 -passout env:TLS_PASSPHRASE \
  -keyout "$KEY_DIR/$CN.key.pem"
echo "# 'Signing '$DN'"
# Issue signed cert from CA (needs CA_PASSPHRASE for CA private key)
openssl ca -batch -config <(echo "$OPENSSL_CONF_MY_CA") \
  -out "$CERT_DIR/$CN.cert.pem" \
  -days $((${YEARS_VALID:=DEFAULT_YEARS_VALID} * 356)) \
  -subj "$DN" \
  -in "$CSR_DIR/$CN.csr.pem" \
  -cert "$ROOT_CA_CERT" \
  -keyfile "$ROOT_CA_KEY" -passin env:CA_PASSPHRASE
echo "# Exporting '$DN' cert to DER format"
openssl x509 -inform pem -in "$CERT_DIR/$CN.cert.pem" -outform der -out "$CERT_DIR/$CN.cert.der" 
echo "# Exporting '$DN' to PKCS12 format"
openssl pkcs12 -export \
  -out "$PFX_DIR/$CN.pfx" -passout env:TLS_PASSPHRASE \
  -inkey "$KEY_DIR/$CN.key.pem" -passin env:TLS_PASSPHRASE \
  -in "$CERT_DIR/$CN.cert.pem" -caname "$CN" \
  -chain -CAfile "$ROOT_CA_CERT"
#openssl x509 -noout -text -in "$CERT_DIR/$CN.cert.pem"
echo
echo "# '$DN' local TLS authentication cert created"
echo "# '$KEY_DIR/$CN.key.pem' private key"
echo "# '$CERT_DIR/$CN.cert.pem' and '$CERT_DIR/$CN.cert.der' signed certifcate formats"
echo "# '$PFX_DIR/$CN.pfx' private key and signed certficate PKCS12 export"