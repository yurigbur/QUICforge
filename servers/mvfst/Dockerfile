#
# Full build image
#
FROM ubuntu:20.04 

# 19.04 repos got moved
#RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update

RUN apt-get --yes --fix-missing update

# Get and build proxygen with HTTP/3 support
RUN apt-get install --yes wget net-tools iputils-ping tcpdump ethtool iperf git sudo cmake python3 libssl-dev m4 zlib1g-dev gcc g++
RUN git clone https://github.com/facebook/proxygen.git 
RUN cd proxygen && git checkout "tags/v2022.02.21.00" && ./getdeps.sh --no-tests 
RUN ldd /tmp/fbcode_builder_getdeps-ZproxygenZbuildZfbcode_builder-root/build/proxygen/proxygen/httpserver/hq | grep "=> /" | awk '{print $3}' > libs.txt
RUN tar cvf libs.tar --dereference --files-from=libs.txt

#
# Minimal image
#
FROM ubuntu:20.04 
# copy run script
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

# Copy HQ
COPY --from=0 /tmp/fbcode_builder_getdeps-ZproxygenZbuildZfbcode_builder-root/build/proxygen/proxygen/httpserver/hq /proxygen/_build/proxygen/bin/hq
# Copy shared libs
COPY --from=0 libs.tar /
RUN tar xvf libs.tar
RUN rm libs.tar
# Create the logs directory
RUN mkdir /logs

RUN mkdir /www 
COPY large.html /www/index.html

ENTRYPOINT [ "./run_endpoint.sh" ]
