#!/bin/bash

echo "Starting pquic server"
./picoquicdemo -c /mnt/certs/ca_quicly.pem -k /mnt/certs/ca.key -p 12345 -n example.com -w /www
