#!/usr/bin/env bash
set -e

export CA_PASSPHRASE="${CA_PASSPHRASE:-change me}"

# source env vars
. .env
if [ -r vars.env ]; then
. vars.env
fi
if [ -n ROOT_CA_DN ]; then
  ROOT_CA_DN=$(dn "$ROOT_CA_CN")
fi

# check dependancies
type openssl >/dev/null 2>&1 || { echo >&2 "openssl is not in PATH or isn't installed. Aborting."; exit 1; }

# avoid overwrite of existing ca
if [ -d "$ROOT_CA_DIR" ]; then
  echo >&2 "'$ROOT_CA_DIR' already exists. Aborting."
  exit 1
fi

# make directories to work from
mkdir -p "$ROOT_CA_DIR"
mkdir -p "$ROOT_CA_DIR"/{certs,certreqs,newcerts,crl,private}
chmod 700 "$ROOT_CA_DIR"/private
touch "$ROOT_CA_DIR"/index.txt

# Create your root certificate authority private key
echo "# Create CA '$ROOT_CA_DN' private key"
openssl genrsa \
  -out "$ROOT_CA_KEY" -aes256 -passout env:CA_PASSPHRASE \
  4096
chmod 700 "$ROOT_CA_KEY"
# Self-sign your root certificate authority
echo "# Create CSR for '$ROOT_CA_DN' CA"
openssl req -config <(echo "$OPENSSL_CONF_MY_CA") \
  -out "$ROOT_CA_DIR/certreqs/$ROOT_CA_FILE_BASENAME.req.pem" \
  -new -subj "$ROOT_CA_DN" \
  -key "$ROOT_CA_KEY" -passin env:CA_PASSPHRASE \
  -days $(($ROOT_CA_YEARS_VALID * 365)) -extensions ca_ext
echo "# Self-sign CSR for '$ROOT_CA_DN' CA"
openssl ca -batch -config <(echo "$OPENSSL_CONF_MY_CA") \
  -out "$ROOT_CA_CERT" \
  -create_serial \
  -subj "$ROOT_CA_DN" \
  -selfsign -days $(($ROOT_CA_YEARS_VALID * 365)) -extensions ca_ext \
  -keyfile "$ROOT_CA_KEY" -passin env:CA_PASSPHRASE \
  -infiles "$ROOT_CA_DIR/certreqs/$ROOT_CA_FILE_BASENAME.req.pem"
echo "# Export '$ROOT_CA_DN' cert to DER format"
openssl x509 -inform pem -in "$ROOT_CA_CERT" -outform der -out "$ROOT_CA_DIR/certs/$ROOT_CA_FILE_BASENAME.cert.der" 
#openssl x509 -noout -text -in "$ROOT_CA_CERT"
echo
echo "# CA '$ROOT_CA_DN' created in '$ROOT_CA_DIR' dir"
echo "# '$ROOT_CA_KEY' private key"
echo "# '$ROOT_CA_CERT' and '$ROOT_CA_DIR/certs/$ROOT_CA_FILE_BASENAME.cert.cer' signed certifcate formats"