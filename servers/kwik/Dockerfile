FROM ubuntu:20.04 as build

ENV     DEBIAN_FRONTEND=noninteractive
RUN     apt-get update -y \
            && apt-get install -y \
            cmake \
            wget \
	    git \
	    openjdk-11-jdk \
	    gradle

RUN 	cd / && git clone https://github.com/ptrd/kwik.git
WORKDIR /kwik
RUN	git submodule update --init --recursive && ./gradlew assemble
RUN	git status | head -n 1 >> /git_version.txt && git log -1 | head -n 1 >> /git_version.txt


FROM openjdk:11

COPY --from=build /kwik/build/libs/kwik.jar .
COPY --from=build /git_version.txt /git_version.txt

RUN mkdir /logs
ENV QLOGDIR=/logs/qlog
RUN mkdir /www 
COPY large.html /www/index.html

COPY	run_endpoint.sh .
RUN     chmod +x /run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
