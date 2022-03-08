FROM ubuntu:20.04 as builder

ARG EBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -y git curl wget python3

WORKDIR /chromium

RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git && cd depot_tools 
ENV PATH=$PATH:/chromium/depot_tools


RUN fetch --no-history chromium

RUN cd src && ./build/install-build-deps.sh && glcient runhooks

RUN cd src && gn gen out/Debug ninja -C out/Debug quic_server


FROM unbuntu:20.04

WORKDIR /chromium

COPY --from=builder /chromium/src/out/Debug/quic_server .

RUN mkdir /www
COPY large.html /www/index.html

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "run_endpoint.sh" ]

