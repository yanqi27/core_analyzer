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
#   2.43 - 2.27
#
# tcmalloc
#   2.18, 2.17, 2.16 (2.15 not tested any more)
#
# jemalloc
#   5.3.0, 5.2.1, 5.2.0
#
# distros
#   ubuntu:24.04, ubuntu:22.04, ubuntu:20.04
#   debian:trixie(13), debian:bookworm(12) (debian:bullseye(11) fails for tcmalloc 2.16 due to gcc/g++ version)
#   redhat/ubi10, redhat/ubi9 (redhat/ubi8 fails because its ptmalloc(glibc 2.28) cherry-picks Safe-Linking feature from later glibc 2.32 and later)
#   fedora:43, fedora:42, fedora:41
#   opensuse/leap:16.0, opensuse/leap:15.6, opensuse/leap:15.5
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
# docker build --build-arg VARIANT="redhat/ubi8" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:43" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:42" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:41" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/tumbleweed" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:16.0" --build-arg GDB_VERSION="16.3" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.6" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.5" --build-arg GDB_VERSION="12.1" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_gdb_9_2 .

echo "Success!"
