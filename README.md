# QUICforge

A python attack script built on top of aioquic to perform request forgery with QUIC

## Prerequisites

- Python3 (3.8)
- NetfilterQueue and ScaPY
- Aioquic (0.9.20)
	1. Pull aioquic 
	2. Checkout a compatible version
	3. Apply the aioquic.diff
	4. Follow the install instructions of aioquic
- Lsquic (3.0.4) (For legacy support, needed for CMRF)
- Wireshark (3.5.0) (Optional)

## Installation / Setup

If the prerequisites are met the script should run out of the box. The described installation instructions are likely going to change in the future. If the setup instructions fail, please consult the official documentation of the respective software.

### Install NetfilterQueue and ScaPY

```bash
sudo apt install build-essential python-dev libnetfilter-queue-dev
sudo pip install https://github.com/johnteslade/python-netfilterqueue/archive/refs/heads/update-cython-code.zip
sudo pip install scapy 
```

### Installation of aioquic

- Install dependencies
	```bash
	apt-get update && apt-get install -y git-core libssl-dev python3-dev python3-pip
	pip3 install aiofiles asgiref httpbin starlette wsproto werkzeug==2.0.3
	```
- Clone the repository and apply the diff
	```bash
	git clone https://github.com/aiortc/aioquic && cd /aioquic && git checkout tags/0.9.20
	#TODO APPLY DIFF
	pip3 install -e .
	```


### Installation of lsquic for legacy mode

*Tested on Ubuntu20.04*
- Install dependencies
	```bash
	sudo apt update && sudo apt install -y golang libevent-dev libz-dev git cmake binutils
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
	git checkout tags/v3.0.4
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


### Installation of Development Wireshark (Optional)

- Pull Git repository
	```bash
	git clone https://gitlab.com/wireshark/wireshark.git
	cd wireshark
	```
- Install dependencies
	```bash
	sudo ./tools/debian-setup.sh --install-optional --install-deb-deps
	```
- Build Wireshark
	```bash
	mkdir build
	cd build
	cmake -G Ninja ../
	ninja
	sudo ninja install
	```


## Usage

### Generate Certificates
*Some need other formats*
```bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout <name>.key -out <name>.pem -days 365
```

### Use the server docker containers
```bash
sudo docker run -p 12345:12345/udp -v </path/to/certs/>:/mnt/certs/ -v </tls/keys/output/>:/mnt/keys -it --rm <containername>
```


### Use the attack script
More information about the attack script can be viewed with:

```bash
sudo python3 request_forgery.py -h
```



