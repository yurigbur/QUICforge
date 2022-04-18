FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y python3  

WORKDIR /chromium

COPY quic_server .
COPY libraries/ .

RUN mkdir /www
COPY large.html /www/index.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]


