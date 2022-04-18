#!/bin/bash

echo "Lsquic version:"
cat /git_version.txt
echo "Starting server..."

http_server -c www.example.com,/mnt/certs/ca.pem,/mnt/certs/ca.key -r /www -G /mnt/keys -L debug
