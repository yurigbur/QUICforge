FROM ubuntu:20.04 as build

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin
RUN apt-get update

# Get and build proxygen with HTTP/3 support
RUN apt-get install --yes wget net-tools iputils-ping tcpdump ethtool iperf git sudo cmake python3 libssl-dev m4 zlib1g-dev gcc g++

RUN git clone https://github.com/facebook/proxygen.git && \
    cd proxygen && \
    git checkout "tags/v2022.04.18.00" && \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt


WORKDIR /proxygen/proxygen
RUN ./build.sh --with-quic

RUN ldd _build/proxygen/httpserver/hq | grep "=> /" | awk '{print $3}' > libs.txt
RUN tar cvf /libs.tar --dereference --files-from=libs.txt


FROM ubuntu:20.04 

COPY --from=build /proxygen/proxygen/_build/proxygen/httpserver/hq /proxygen/hq
COPY --from=build libs.tar /
COPY --from=build /git_version.txt /git_version.txt

RUN tar xvf libs.tar
RUN rm libs.tar

RUN mkdir /logs

RUN mkdir /www 
COPY large.html /www/index.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
