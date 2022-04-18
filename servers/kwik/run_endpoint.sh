#!/bin/bash

echo 'Kwik Version'
cat /git_version.txt
echo 'Starting server'

java -cp kwik.jar net.luminis.quic.run.InteropServer /mnt/certs/ca_quicly.pem /mnt/certs/ca.key 12345 /www --noRetry
