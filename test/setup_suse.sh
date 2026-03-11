#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/setup_suse.sh

# The setup script installs the necessary dependencies to build core_analyzer

# Update the package list and install required packages

zypper install -y gcc gcc-c++ && \
    zypper install -y wget sudo texinfo && \
    zypper install -y tar gzip xz && \
    zypper install -y gmp-devel mpfr-devel && \
    zypper install -y git make makeinfo m4 automake libtool python3-devel patch

zypper mr -ea && \
    zypper install -y glibc-debuginfo && \
    zypper ref && \
    zypper dup -y

ln -s /usr/bin/python3 /usr/bin/python

zypper install -y gdb python3-distro
