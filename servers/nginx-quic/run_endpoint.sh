#!/bin/bash

echo "Nginx-QUIC version:"
cat /git_version.txt
echo "Starting nginx server..."
/usr/sbin/nginx -V

export LD_LIBRARY_PATH=boringssl/build/ssl:boringssl/build/crypto

/usr/sbin/nginx -c /etc/nginx/nginx.conf.http3
#/usr/sbin/nginx -c /etc/nginx/nginx.conf
