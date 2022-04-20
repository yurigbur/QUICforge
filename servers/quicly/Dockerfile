FROM ubuntu:20.04 as builder

WORKDIR /

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
  apt-get install -y net-tools iputils-ping git gcc clang cmake tcpdump ethtool libssl-dev iperf

ARG CACHEBUST=1
RUN git clone https://github.com/h2o/quicly.git && \
    cd quicly &&  \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt && \
    git submodule update --init --recursive && \
    cmake . && \
    make


FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
  apt-get install -y libssl-dev net-tools

COPY --from=builder /quicly/cli quicly/cli
COPY --from=builder /git_version.txt /git_version.txt

RUN mkdir /www
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
