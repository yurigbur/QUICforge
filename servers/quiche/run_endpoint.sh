#!/bin/bash
set -e

echo "Quiche (Cloudflare) version:"
cat /git_version.txt
echo "Starting  server..."

/quiche/quiche-server --listen 0.0.0.0:12345 --root /www --cert /mnt/certs/ca_quicly.pem --key /mnt/certs/ca.key
