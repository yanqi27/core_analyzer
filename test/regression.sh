#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/regression.sh

# The regression test suite includes the following scenarios:
#
# gdb
#   16.3, 12.1, 9.2
#
# ptmalloc
#   2.41 - 2.27
#
# tcmalloc
#   2.16, 2.15, 2.14
#
# jemalloc
#   5.3.0, 5.2.1, 5.2.0
#
# distros
#   ubuntu:24.04, ubuntu:22.04, ubuntu:20.04
#   debian:trixie(13), debian:bookworm(12) (debian:bullseye(11) fails for tcmalloc 2.16 due to gcc/g++ version)
#   redhat/ubi10, redhat/ubi9 (redhat/ubi8 fails because tcache_entry is mangled, presumably for security reasons)
#   fedora:41, fedora:40 (fedora:42 fails due to default gcc, EXTRA_CFLAGS=-std=gnu17 may fix)
#   opensuse/leap:15.6, opensuse/leap:15.5
#

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:24.04" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:22.04" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:trixie" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:bookworm" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_ubuntu .

#docker system prune -af > /dev/null
#docker build --build-arg VARIANT="debian:bullseye" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="redhat/ubi10" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="redhat/ubi9" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_redhat .

# docker system prune -af > /dev/null
# docker build --build-arg VARIANT="redhat/ubi8" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:41" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:40" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

#docker system prune -af > /dev/null
#docker build --build-arg VARIANT="opensuse/tumbleweed" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.6" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.5" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_gdb_9_2 .

echo "Success!"
