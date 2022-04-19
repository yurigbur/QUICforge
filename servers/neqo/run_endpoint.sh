#!/bin/bash

set -ex

export PATH="${PATH}:/neqo/bin"

DB=/neqo/db
CERT=cert
P12CERT=$(mktemp)
mkdir -p "$DB"
certutil -N -d "sql:$DB" --empty-password
openssl pkcs12 -export -nodes -in /mnt/certs/ca_quicly.pem -inkey /mnt/certs/ca.key \
	-name "$CERT" -passout pass: -out "$P12CERT"
pk12util -d "sql:$DB" -i "$P12CERT" -W ''
certutil -L -d "sql:$DB" -n "$CERT"

echo "Neqo version:"
cat /git_version.txt
echo "Starting server..."
RUST_LOG=info RUST_BACKTRACE=1 neqo-server --cc cubic -o -d "$DB" -k "$CERT" 0.0.0.0:12345
