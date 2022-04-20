#!/bin/bash


echo "Quicly version:"
cat /git_version.txt
echo "Starting server ..."
/quicly/cli -k /mnt/certs/ca.key -c /mnt/certs/ca_quicly.pem -v 0.0.0.0 12345
