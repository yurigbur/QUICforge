#!/bin/bash

cd /www && python3 -m http.server &

echo 'Chromium (quiche) version'
echo 'HEAD detached at origin/main'
echo 'commit eeb980333af5ce09a48f3dba4c2e2310c239cd2b'
echo 'Starting server'

LD_LIBRARY_PATH="/chromium/libraries" /chromium/quic_server \
  --quic_mode=proxy \
  --quic_proxy_backend_url=http://localhost:8000 \
  --certificate_file=/mnt/certs/out/leaf_cert.pem \
  --key_file=/mnt/certs/out/leaf_cert.pkcs8 \
  --port=12345
