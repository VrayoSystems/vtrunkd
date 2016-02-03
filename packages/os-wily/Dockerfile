FROM ubuntu:wily
ADD sources.list /etc/apt/
RUN apt-get update
RUN apt-get install -y build-essential autotools-dev bison flex build-essential liblzo2-dev  zlib1g-dev libssl-dev devscripts git debhelper
RUN apt-get -y upgrade
