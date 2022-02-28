#!/bin/bash

SERVER_BIN="/usr/local/bin/server"
$SERVER_BIN 0.0.0.0 12345 /mnt/certs/ca.key /mnt/certs/ca_quicly.pem -d /www
