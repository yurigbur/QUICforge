# QUICforge

A python attack script built on top of aioquic to perform request forgery with QUIC

## Prerequisites

- Python3 (>3.8)
- Aioquic (>0.9.17)
	1. Pull aioquic 
	2. Checkout a compatible version
	3. Apply the aioquic.diff
	4. Follow the install instructions of aioquic
- Wireshark (>3.5.0) (Optional)

## Installation / Setup

If the prerequisites are met the script should run out of the box

### Installation of lsquic for legacy mode

*Tested on Ubuntu20.04*
- Install dependencies
	```bash
	sudo apt update && sudo apt install -y golang libevent-dev
	```
- Setup boringssl
	```bash
	git clone https://boringssl.googlesource.com/boringssl
	cd boringssl
	git checkout a9670a8b476470e6f874fef3554e8059683e1413
	cmake . &&  make
	BORINGSSL=$PWD
	cd ..
	```
- Compile lsquic
	```bash
	git clone https://github.com/litespeedtech/lsquic.git
	cd lsquic
	git submodule update --init --recursive
	cmake -DBORINGSSL_DIR=$BORINGSSL .
	make
	```
#### Changes to codbase to get a predictable CID of length 20

- In `lsquic/include/lsquic.h`:
	Change 
	```C
	#define LSQUIC_DF_SCID_LEN 8
	```
	to
	```C
	#define LSQUIC_DF_SCID_LEN MAX_CID_LEN
	```
- In `lsquic/src/liblsquic/lsquic_conn.c` create a global set of your wanted CIDs (each CID needs to be unique):
	```C
	static int lsquic_cid_ctr = 0;
	char* data_buffer[10] = {
    		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    		"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    		"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
    		"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
    		"IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
    		"JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
	};
	```
	Furthermore change the function `lsquic_generate_cid` to something similar to:
	```C
	if (!len){
    		len = 20;
    	}
    	//Set counter to the index used as new CID for path challenges.
    	cid->len = len;
    	if(lsquic_cid_ctr < 10){       
    		memcpy(cid->idbuf, data_buffer[lsquic_cid_ctr], cid->len);
    	}
    	else{
    		RAND_bytes(cid->idbuf, len);
    	}
    	lsquic_cid_ctr++;
	```
	With this the all CIDs will be of length 20 and the first 10 generated CIDs will be static.

## Usage


