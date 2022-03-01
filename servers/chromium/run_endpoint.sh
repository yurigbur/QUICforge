#!/bin/bash

#Proxy version, needs backend server
#TODO docker compose for quic-server and http backed
/chromium/out/Debug/quic_server --quic_mode=proxy --quic_proxy_backend_url=http://192.168.79.136:9090 --certificate_file=/home/masterserver/quic/certs/out/leaf_cert.pem --key_file=/home/masterserver/quic/certs/out/leaf_cert.pkcs8 --port=12345
