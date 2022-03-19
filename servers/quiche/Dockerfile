FROM rust:1.53 as build

WORKDIR /build
RUN apt-get update && apt-get install -y cmake git && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --recursive https://github.com/cloudflare/quiche.git && \
    cd quiche && \
    git checkout tags/0.12.0

RUN cargo build --manifest-path /build/quiche/apps/Cargo.toml


FROM ubuntu:20.04

WORKDIR /quiche

COPY --from=build /build/quiche/target/debug/quiche-server .

ENV RUST_LOG=trace

RUN mkdir /www 
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
