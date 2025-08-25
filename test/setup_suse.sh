#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/setup_suse.sh

# The setup script installs the necessary dependencies to build core_analyzer

# Update the package list and install required packages

zypper install -y gcc gcc-c++ && \
    zypper install -y wget sudo texinfo && \
    zypper install -y tar gzip xz && \
    zypper install -y git make makeinfo m4 automake libtool python3-devel patch

cd /opt && \
    wget https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.xz && \
    tar xvf gmp-6.2.1.tar.xz && \
    cd gmp-6.2.1 && \
    ./configure && make -j 4 && make install

cd /opt && \
    git clone https://gitlab.inria.fr/mpfr/mpfr.git && \
    cd mpfr && \
    ./autogen.sh && ./configure && make -j 4 && make install

zypper mr -ea && \
    zypper install -y glibc-debuginfo

ln -s /usr/bin/python3 /usr/bin/python

zypper install -y gdb python3-distro
