FROM    ubuntu:20.04 as source

ENV     DEBIAN_FRONTEND=noninteractive
RUN     apt-get update -y \
            && apt-get install -y \
            build-essential \
            cmake \
            liblttng-ust-dev \
            wget \
	    git \
        && apt-get clean

RUN	git clone https://github.com/microsoft/msquic.git && \
	    cd msquic && \
	    git checkout tags/v2.0.1 && \
	    git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt && \
	    git submodule update --init --recursive && \
	    cd .. && mv msquic/ /src

FROM    source as build
WORKDIR /src/Debug
RUN     chmod +x /src/scripts/install-powershell-docker.sh
RUN     /src/scripts/install-powershell-docker.sh
ENV     PATH="/root/.dotnet/tools:${PATH}"
RUN     cmake -DQUIC_BUILD_TOOLS=on -DQUIC_ENABLE_LOGGING=on \
              -DQUIC_DISABLE_POSIX_GSO=on ..
RUN     cmake --build .


FROM    ubuntu:20.04

RUN     apt-get update -y \
            && apt-get install -y \
            libatomic1 \
            liblttng-ust-dev \
            lttng-tools \
        wget \
            && apt-get clean
COPY    --from=build /src/Debug/bin/Release /bin
COPY    --from=build /src/Debug/bin/Release/*.so /lib/x86_64-linux-gnu/
#COPY    --from=source /src/scripts/run_endpoint.sh /run_endpoint.sh
COPY    --from=source /src/src/manifest/clog.sidecar /clog.sidecar
COPY    --from=source /src/scripts/install-powershell-docker.sh \
            /install-powershell-docker.sh
COPY	--from=source /git_version.txt /git_version.txt
RUN     chmod +x /install-powershell-docker.sh
RUN     /install-powershell-docker.sh
ENV     PATH="/root/.dotnet/tools:${PATH}"

RUN 	mkdir /www
COPY	large.html /www/index.html
COPY	run_endpoint.sh .
RUN     chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
