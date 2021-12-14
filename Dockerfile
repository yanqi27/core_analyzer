# ==============================================================================================
# FILENAME	:	Dockerfile
# AUTHOR	:	Celthi
# CREATION	:	2021-12-14
# Dockerfile to build enhanced gdb with core analyzer
# ==============================================================================================



FROM ubuntu:18.04
RUN apt update \
    && apt install -y texinfo \
    && apt install -y build-essential \
    && apt install -y wget

WORKDIR /usr/src/app
COPY . .

RUN ./build_gdb.sh
ENTRYPOINT ["gdb"]

