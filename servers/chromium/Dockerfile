FROM ubuntu:20.04 as builder

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /chromium

#Pull tools, source and dependencies
#TODO

#Build Quic debug server
ninja -C out/Debug quic_server

FROM ubuntu:20.04

WORKDIR /chromium
COPY --from=builder /chromium/out/Debug/quic_server .

RUN mkdir /www
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]

