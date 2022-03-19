FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y git-core libssl-dev python3-dev python3-pip
RUN pip3 install aiofiles asgiref httpbin starlette wsproto
RUN git clone https://github.com/aiortc/aioquic && cd /aioquic && git checkout tags/0.9.19
WORKDIR /aioquic
RUN pip3 install -e .

RUN mkdir /logs

#COPY packet.py /aioquic/src/aioquic/quic
#COPY connection.py /aioquic/src/aioquic/quic

COPY large.html examples/templates/index.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
