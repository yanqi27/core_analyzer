#!/usr/bin/env bash

# =============================================================================
# FILENAME	:	build_jemalloc.sh
# AUTHOR	:	Michael Yan
# CREATION	:	2023-03-18
# Script to build jemalloc with specified version.
#
# This script will the do the following steps
# 1. Create working directory
# 2. clone the jemalloc source
# 3. checkout the desired release version
# 4. configure, build and install
# =============================================================================
set -e

if [ "$#" -ne 1 ]
then
  echo "Usage: $0 <jemalloc version>"
  echo "    For example, \"$0 5.3.0\""
  echo "    Please refer to https://github.com/jemalloc/jemalloc"
  exit 1
fi

PROJECT_FOLDER=$(pwd)
release_tag=$1
echo "Current project folder is $PROJECT_FOLDER"
build_folder=$PROJECT_FOLDER/build
mkdir -p $build_folder
cd $build_folder
scr_dir="jemalloc"
if [ ! -d $scr_dir ]
then
    echo "cloning jemalloc ..."
    git clone https://github.com/jemalloc/jemalloc.git
fi
cd $scr_dir

echo "checkout $release_tag"
branch_name=jemalloc-$release_tag
if [ -n "$(git branch --list ${branch_name})" ]
then
    echo "Branch name $branch_name already exists."
else
    git checkout tags/$release_tag -b $branch_name
fi

echo "building..."
./autogen.sh
./configure
make clean && make -j 4 && sudo make install
