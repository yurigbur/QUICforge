#!/bin/bash

LOG_PARAMS=""
if [ -n "$QLOGDIR" ]; then
    LOG_PARAMS="$LOG_PARAMS --quic-log $QLOGDIR"
fi

#file examples/templates/index.html
#head examples/templates/index.html
#tail examples/templates/index.html

echo "Aioquic version"
cat /git_version.txt

echo "Starting server"
python3 examples/http3_server.py \
	--certificate /mnt/certs/ca_quicly.pem \
	--host 0.0.0.0 \
	--port 12345 \
	--private-key /mnt/certs/ca.key \
	--verbose \
	--secrets-log /mnt/keys/aioquic_"$(date +'%b%d-%Y-%H%M%S')".key \
	$LOG_PARAMS \
