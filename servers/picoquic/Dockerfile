FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential git cmake software-properties-common \
    openssl libssl-dev pkg-config clang

RUN mkdir /src
WORKDIR /src

RUN git clone https://github.com/private-octopus/picoquic.git && \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt


# Perl stuff is for the picotls test code
RUN echo install Test::TCP | perl -MCPAN -
RUN echo install Scope::Guard | perl -MCPAN -

RUN git clone https://github.com/h2o/picotls.git && \
    cd picotls && \
    git submodule init && \
    git submodule update && \
    cmake . && \
    make && \
    make check

RUN cd /src/picoquic && \
    cmake . && \
    make

RUN mkdir /www
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]

