#/bin/bash

java -cp kwik.jar net.luminis.quic.server.Server /mnt/certs/ca_quicly.pem /mnt/certs/ca.key 12345 /www --noRetry