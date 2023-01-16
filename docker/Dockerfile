FROM ubuntu:20.04
ENV TIMEZONE=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TIMEZONE /etc/localtime && echo $TIMEZONE > /etc/timezone

# copy cloned repo into container
WORKDIR /root
RUN mkdir origo
COPY . origo/

# TODO: adjust for deployment scenario
# docker installer script
# WORKDIR /root/origo/docker
# RUN ./install.sh

# setup container
RUN apt-get update && apt-get install -y make git sudo
WORKDIR /root/origo
RUN make init

ENV PATH /usr/local/go/bin:$PATH

# build project
WORKDIR /root/origo
RUN make build

EXPOSE 8080

# start command
CMD ["/bin/bash"]
