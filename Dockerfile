# ==============================================================================================
# FILENAME	:	Dockerfile
# AUTHOR	:	Celthi
# CREATION	:	2021-12-14
# Dockerfile to build enhanced gdb with core analyzer
# ==============================================================================================

ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt install -y texinfo \
    && apt install -y libgmp-dev \
    && apt install -y build-essential \
    && apt install -y wget \
    && apt install -y python-dev \
    && apt install -y python3-dev \
    && apt install -y dh-autoreconf 



WORKDIR /workspaces/core_analyzer/
COPY . .

RUN ./build_gdb.sh
RUN cd test
RUN make check

