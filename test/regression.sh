#!/bin/bash

set -ex

# run the script from the root path
# $ ./test/regression.sh

# The regression test suite includes the following scenarios:
#
# gdb
#   12.1, 9.2
#
# ptmalloc
#   2.37      ubuntu:23.04
#   2.36      debian:bookworm
#   2.35      ubuntu:22.04
#   2.31      debian:bullseye, ubuntu:20.04
#   2.28      redhat/ubi8
#   2.27      ubuntu:18.04
#
# tcmalloc
#   2.10, 2.9, 2.8, 2.7
#
# jemalloc
#   5.3.0, 5.2.1, 5.2.0

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:22.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:23.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:bullseye" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:bookworm" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="redhat/ubi8" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:18.04" -t ca_test -q -f test/DockerfileTest_gdb_9_2 .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_gdb_9_2 .
