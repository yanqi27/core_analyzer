#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/setup_redhat.sh

# The setup script installs the necessary dependencies to build core_analyzer

# Update the package list and install required packages

yum install -y wget procps-ng git autoconf gettext \
    gcc gcc-c++ make automake zlib-devel libtool diffutils \
    libcurl-devel sqlite-devel xz \
    python3-devel python3-pip sudo yum-utils cpan patch

pip install distro && python3 ./test/extra_setup.py

ln -sf /usr/bin/python3 /usr/bin/python

debuginfo-install -y glibc


cd /opt && \
    wget https://ftp.gnu.org/pub/gnu/gettext/gettext-0.21.tar.gz && \
    tar xvf gettext-0.21.tar.gz && \
    cd gettext-0.21 && \
    ./configure && make -j 4 && make install

cd /opt && \
    wget https://www.libarchive.org/downloads/libarchive-3.6.1.tar.gz && \
    tar xvf libarchive-3.6.1.tar.gz && \
    cd libarchive-3.6.1 && \
    ./configure --prefix=/usr && make -j 4 && make install

cd /opt && \
    wget https://ftp.gnu.org/gnu/texinfo/texinfo-7.0.3.tar.gz && \
    tar xvf texinfo-7.0.3.tar.gz && \
    cd texinfo-7.0.3 && \
    ./configure && make -j 4 && make install

cd /opt && \
    wget https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.xz && \
    tar xvf gmp-6.2.1.tar.xz && \
    cd gmp-6.2.1 && \
    ./configure && make -j 4 && make install

cd /opt && \
    git clone https://gitlab.inria.fr/mpfr/mpfr.git && \
    cd mpfr && \
    ./autogen.sh && ./configure && make -j 4 && make install
