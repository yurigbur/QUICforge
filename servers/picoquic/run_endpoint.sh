#!/bin/bash

mkdir /logs

echo "Picoquic version:"
cat /git_version.txt
echo "Starting server..."

./picoquic/picoquicdemo -w /www -L -l /logs/server_log.txt -b /logs/server_log.bin -k /mnt/certs/ca.key -c /mnt/certs/ca_quicly.pem -p 12345
