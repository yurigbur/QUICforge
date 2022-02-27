FROM ubuntu:20.04 AS build

# Which branch to build from.
ARG NEQO_BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates coreutils curl git make mercurial ssh \
    build-essential clang llvm libclang-dev lld cargo rustc\
    gyp ninja-build pkg-config zlib1g-dev python curl\
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.45.2

ENV NSS_DIR=/nss \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

RUN set -eux; \
    hg clone https://hg.mozilla.org/projects/nss "$NSS_DIR"; \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

RUN git clone https://github.com/mozilla/neqo.git && cd /neqo && git checkout tags/v0.5.7

RUN set -eux; \
    cd /neqo; \
    RUSTFLAGS="-g -C link-arg=-fuse-ld=lld" cargo build --release \
      --bin neqo-client --bin neqo-server; \
    cp target/release/neqo-client target; \
    cp target/release/neqo-server target; \
    rm -rf target/release

FROM ubuntu:20.04

ENV LD_LIBRARY_PATH=/neqo/lib
RUN apt-get update && apt-get install -y ca-certificates coreutils 

COPY --from=build /neqo/target/neqo-client /neqo/target/neqo-server /neqo/bin/
COPY --from=build /dist/Release/lib/*.so /neqo/lib/
COPY --from=build /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/

RUN mkdir /www
COPY large.html /www/index.html

COPY run_endpoint.sh /neqo/
RUN chmod +x /neqo/run_endpoint.sh
ENTRYPOINT [ "/neqo/run_endpoint.sh" ]
