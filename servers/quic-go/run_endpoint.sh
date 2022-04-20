#!/bin/bash
set -e

cp /mnt/certs/ca_quicly.pem /quic-go/internal/testdata/cert.pem
cp /mnt/certs/ca.key /quic-go/internal/testdata/priv.key

echo "QUIC-Go version:"
cat /git_version.txt
echo "Starting server..."

QUIC_GO_LOG_LEVEL=debug ./server -v -bind 0.0.0.0:12345 -www /www
