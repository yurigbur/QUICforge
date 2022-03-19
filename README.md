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
## Usage


