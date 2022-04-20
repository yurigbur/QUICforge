FROM ubuntu:20.04 AS builder

RUN apt-get update && apt-get install -y wget tar git net-tools

RUN wget https://dl.google.com/go/go1.17.linux-amd64.tar.gz && \
  tar xfz go1.17.linux-amd64.tar.gz && \
  rm go1.17.linux-amd64.tar.gz

ENV PATH="/go/bin:${PATH}"

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

RUN git clone https://github.com/lucas-clemente/quic-go && \
  cd quic-go && \
  git checkout tags/v0.27.0 && \
  git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt && \
  go get ./...

WORKDIR /quic-go

RUN git rev-parse HEAD > commit.txt
#RUN go build -o server -ldflags="-X github.com/lucas-clemente/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/server/main.go
#RUN go build -o client -ldflags="-X github.com/lucas-clemente/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/client/main.go
RUN go build -o server example/main.go
#RUN go build -o echo example/echo/echo.go


FROM ubuntu:20.04

WORKDIR /quic-go

COPY --from=builder /quic-go/commit.txt /quic-go/server ./
COPY --from=builder /git_version.txt /git_version.txt

RUN mkdir /logs/ && mkdir /www && mkdir internal && mkdir internal/testdata
COPY large.html /www/index.html
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
