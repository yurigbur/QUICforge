#!/bin/bash

# Extra debugging ?
set -x
set -o nounset

DRAFT=29
HQ_CLI=/proxygen/hq
PORT=12345
LOGLEVEL=2

# Unless noted otherwise, test cases use HTTP/0.9 for file transfers.
PROTOCOL="h3"
HTTPVERSION="3.0"

# Default enormous flow control.

CONN_FLOW_CONTROL="107374182"
STREAM_FLOW_CONTROL="107374182"
INVOCATIONS=$(echo ${REQUESTS} | tr " " "\n" | awk -F '/' '{ print "/" $4 }' | paste -sd',')
EARLYDATA="false"
PSK_FILE="" # in memory psk

echo "mvfst version"
cat /git_version.txt
echo "Running QUIC server on 0.0.0.0:${PORT}"
    ${HQ_CLI} \
        --mode=server \
	--cert=/mnt/certs/mvfst.pem \
	--key=/mnt/certs/mvfst.key \
        --port=${PORT} \
	--httpversion=${HTTPVERSION} \
        --h2port=${PORT} \
        --static_root=/www \
        --logdir=/logs \
	--qlogger_path=/logs \
        --host=0.0.0.0 \
        --congestion=bbr \
        --pacing=true \
        --v=${LOGLEVEL} 2>&1 | tee /logs/server.log
