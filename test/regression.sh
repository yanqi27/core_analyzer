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
#   2.40 - 2.27
#
# tcmalloc
#   2.15 - 2.7
#
# jemalloc
#   5.3.0, 5.2.1, 5.2.0
#
# distros
#   ubuntu:24.04, ubuntu:22.04, ubuntu:20.04
#   debian:bookworm(12), debian:bullseye(11)
#   redhat/ubi9, redhat/ubi8 (failed because tcache_entry is mangled presumably for security reasons)
#   fedora:39
#   opensuse/tumbleweed, opensuse/leap:15.5, opensuse/leap:15.6
#

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:22.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:24.04" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:bullseye" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="debian:bookworm" -t ca_test -q -f test/DockerfileTest_ubuntu .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="redhat/ubi9" -t ca_test -q -f test/DockerfileTest_redhat .

# docker system prune -af > /dev/null
# docker build --build-arg VARIANT="redhat/ubi8" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="fedora:39" -t ca_test -q -f test/DockerfileTest_redhat .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/tumbleweed" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.5" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="opensuse/leap:15.6" -t ca_test -q -f test/DockerfileTest_suse .

docker system prune -af > /dev/null
docker build --build-arg VARIANT="ubuntu:20.04" -t ca_test -q -f test/DockerfileTest_gdb_9_2 .

echo "Success!"
