#!/usr/bin/env bash

set -e

# source env vars
. .env
if [ -r vars.env ]; then
. vars.env
fi

read -p "About to remove all private keys ('$KEY_DIR'), certifcates ('$CERT_DIR'), CSRs ('$CSR_DIR'), including the CA ('$ROOT_CA_DIR'). Are you sure (y)? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -f -r "$KEY_DIR" "$CERT_DIR" "$PFX_DIR" "$CSR_DIR" "$ROOT_CA_DIR"
fi