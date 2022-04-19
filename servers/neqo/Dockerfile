FROM ubuntu:20.04 AS build

ARG NEQO_BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates coreutils curl git make mercurial ssh \
    build-essential clang llvm libclang-dev lld \
    gyp ninja-build pkg-config zlib1g-dev python curl cargo rustc \
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ENV NSS_DIR=/nss \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

RUN set -eux; \
    hg clone https://hg.mozilla.org/projects/nss "$NSS_DIR"; \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

RUN git clone https://github.com/mozilla/neqo.git && cd /neqo && \
    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt


RUN set -eux; \
    cd /neqo; \
    RUSTFLAGS="-g -C link-arg=-fuse-ld=lld" cargo build --release --bin neqo-server; \
    cp target/release/neqo-server target; \
    rm -rf target/release


FROM ubuntu:20.04

ENV LD_LIBRARY_PATH=/neqo/lib
RUN apt-get update && apt-get install -y ca-certificates coreutils 

COPY --from=build /neqo/target/neqo-server /neqo/bin/
COPY --from=build /dist/Release/lib/*.so /neqo/lib/
COPY --from=build /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/
COPY --from=build /git_version.txt /git_version.txt

RUN mkdir /www
COPY large.html /www/index.html

COPY run_endpoint.sh /neqo/
RUN chmod +x /neqo/run_endpoint.sh
ENTRYPOINT [ "/neqo/run_endpoint.sh" ]
