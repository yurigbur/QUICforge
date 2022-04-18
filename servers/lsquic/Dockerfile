FROM ubuntu:20.04 as build

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

RUN apt-get update && \
    apt-get install -y build-essential git cmake software-properties-common \
                       zlib1g-dev libevent-dev golang

RUN mkdir /src
WORKDIR /src

RUN git clone https://boringssl.googlesource.com/boringssl && \
    cd boringssl && \
    git checkout a2278d4d2cabe73f6663e3299ea7808edfa306b9 && \
    cmake . && \
    make

RUN git clone https://github.com/litespeedtech/lsquic.git && \
    cd lsquic && \
    git checkout tags/v3.0.4 && \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt && \
    git submodule update --init && \
    cmake -DBORINGSSL_DIR=/src/boringssl . && \
    make


FROM ubuntu:20.04

COPY --from=build /src/lsquic/bin/http_server /usr/bin/
COPY --from=build /git_version.txt /git_version.txt

RUN mkdir /www 
COPY large.html /www/large.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]

