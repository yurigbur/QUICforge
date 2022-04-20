FROM ubuntu:20.04
 
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        libev4 libjemalloc2 ca-certificates mime-support \
        libasan5 libubsan1

RUN git clone --depth 1 -b OpenSSL_1_1_1k+quic https://github.com/quictls/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl
    
RUN git clone https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    git checkout tags/v0.3.0 && \
    autoreconf -i && \
    ./configure --enable-lib-only \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3
    
RUN git clone https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    git checkout tags/v0.3.1 && \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt && \
    autoreconf -i && \
    ./configure \
        CXXFLAGS=-DNGTCP2_ENABLE_UDP_GSO=0 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && \
    cp examples/server /usr/local/bin && \
    cd .. && \
    rm -rf ngtcp2 && \
    rm -rf /usr/local/lib/libssl.so /usr/local/lib/libcrypto.so /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a /usr/local/lib/pkgconfig/*ssl.pc /usr/local/include/openssl/*
    
RUN apt-get -y purge git g++ make binutils autoconf automake autotools-dev libtool pkg-config \
        libev-dev libjemalloc-dev && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

RUN mkdir /www
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
