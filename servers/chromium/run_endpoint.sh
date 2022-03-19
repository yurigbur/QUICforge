#!/bin/bash

cd /www && python3 -m http.server &

/chromium/quic_server \
  --quic_mode=proxy \
  --quic_proxy_backend_url=http://localhost:8000 \
  --certificate_file=/mnt/certs/leaf_cert.pem \
  --key_file=/mnt/certs/leaf_cert.pkcs8 \
  --port=12345
