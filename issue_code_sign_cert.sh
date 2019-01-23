#!/usr/bin/env bash
set -e

export CA_PASSPHRASE="${CA_PASSPHRASE:-change me}"
export CODESIGN_PASSPHRASE="${CODESIGN_PASSPHRASE:-change me}"

# check dependancies
type openssl >/dev/null 2>&1 || { echo "openssl is not in PATH or isn't installed. Aborting." >&2; exit 1; }

# source env vars
. .env
if [ -r vars.env ]; then
. vars.env
fi
CN="${CN:-Personal Code Signing}"
DN=$(dn)
YEARS_VALID=${YEARS_VALID:-5}

openssl_tls_cert_req_conf="
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = code_sign_ext
[ req_distinguished_name ]
CN = ${CN}
[ code_sign_ext ]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning, msCodeInd
"

# check CA dir exists
if ! [ -d "$ROOT_CA_DIR" ]; then
  echo >&2 "'$ROOT_CA_DIR' directory for the CA does not exist. Aborting."
  exit 1
fi

# Avoid overwrite of existing keys and / or cert
if [ -e "$CERT_DIR/$CN.cert.pem" ] || [ -e "$KEY_DIR/$CN.key.pem" ]; then
  echo >&2 "A file for the cert or key already exists. Aborting."
  exit 1
fi

mkdir -p "$KEY_DIR" "$CERT_DIR" "$PFX_DIR" "$CSR_DIR" 
chmod 0700 "$KEY_DIR" "$PFX_DIR"

# create new csr and private key (not encrypted)
echo "# Generating CSR for '$DN' code signing cert"
openssl req -config <(echo "$openssl_tls_cert_req_conf") \
  -out "$CSR_DIR/$CN.csr.pem" \
  -subj "$DN" \
  -new -sha256 -days $((${YEARS_VALID:=DEFAULT_YEARS_VALID} * 356)) \
  -newkey rsa:2048 -nodes -keyout "$KEY_DIR/$CN.key.pem" -passout env:CODESIGN_PASSPHRASE
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
  -out "$PFX_DIR/$CN.pfx" -passout env:CODESIGN_PASSPHRASE \
  -inkey "$KEY_DIR/$CN.key.pem" \
  -in "$CERT_DIR/$CN.cert.pem" -caname "$CN" \
  -chain -CAfile "$ROOT_CA_CERT"
#openssl x509 -noout -text -in "$CERT_DIR/$CN.cert.pem"
echo
echo "# '$DN' code signing cert created"
echo "# '$KEY_DIR/$CN.key.pem' private key"
echo "# '$CERT_DIR/$CN.cert.pem' and '$CERT_DIR/$CN.cert.der' signed certifcate formats"
echo "# '$PFX_DIR/$CN.pfx' private key and signed certficate PKCS12 export"