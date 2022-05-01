#!/bin/bash


echo "Quicly version:"
cat /git_version.txt
echo "Starting server ..."
/quicly/cli -k /mnt/certs/ca.key -c /mnt/certs/ca_quicly.pem -a h3 -v 0.0.0.0 12345 -l /mnt/keys/quicly.log -e /dev/stdout
