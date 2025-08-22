#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/setup_ubuntu.sh

# The setup script installs the necessary dependencies to build core_analyzer

# Update the package list and install required packages
apt-get update
export DEBIAN_FRONTEND=noninteractive
apt-get install -y \
    texinfo \
    libgmp-dev \
	libmpfr-dev \
    libtool \
    build-essential \
	gawk \
    wget \
    python3-dev \
    python3-pip \
    dh-autoreconf \
    git \
    sudo \
    libc6-dbg

ln -s /usr/bin/python3 /usr/bin/python
