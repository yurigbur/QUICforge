FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y git-core libssl-dev python3-dev python3-pip
RUN pip3 install aiofiles asgiref httpbin starlette wsproto werkzeug==2.0.3
RUN git clone https://github.com/aiortc/aioquic && cd /aioquic && git checkout tags/0.9.20
WORKDIR /aioquic
RUN git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt
RUN pip3 install -e .

RUN mkdir /logs

#COPY packet.py /aioquic/src/aioquic/quic
#COPY connection.py /aioquic/src/aioquic/quic

COPY large.html examples/templates/index.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
