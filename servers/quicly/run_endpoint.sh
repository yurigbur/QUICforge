#!/bin/bash


echo "Starting quicly server ..."
/quicly/cli -k /mnt/certs/ca.key -c /mnt/certs/ca_quicly.pem -d 29 -a hq-29 -v 0.0.0.0 12345
