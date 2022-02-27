#!/bin/bash

echo "Starting server"
./bin/quicinteropserver -listen:* -name:example.com -port:12345 -root:/www -file:/mnt/certs/server.cert -key:/mnt/certs/server.key
