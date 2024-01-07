#!/usr/bin/env bash

# =============================================================================
# FILENAME	:	build_tcmalloc.sh
# AUTHOR	:	Michael Yan
# CREATION	:	2022-05-30
# Script to build gperftools/libtcmalloc with specified version.
#
# This script will the do the following steps
# 1. Create working directory
# 2. clone the tcmalloc source
# 3. checkout the desired release version
# 4. configure, build and install
# =============================================================================
set -e

if [ "$#" -ne 1 ]
then
  echo "Usage: $0 <gperftools version>"
  echo "    For example, \"$0 2.7\""
  echo "    Please refer to https://github.com/gperftools/gperftools/releases"
  exit 1
fi

PROJECT_FOLDER=$(pwd)
release_tag=$1
echo "Current project folder is $PROJECT_FOLDER"
build_folder=$PROJECT_FOLDER/build
mkdir -p $build_folder
cd $build_folder

# workaround the problem of multi builds from the same source folder, for example, 2.15 and 2.14
rm -rf ./gperftools

scr_dir="gperftools"
if [ ! -d $scr_dir ]
then
    echo "cloning gperftools ..."
    git clone https://github.com/gperftools/gperftools.git
fi
cd $scr_dir

echo "checkout $release_tag"
branch_name=gperftools-$release_tag
if [ -n "$(git branch --list ${branch_name})" ]
then
    echo "Branch name $branch_name already exists."
else
    git checkout tags/$branch_name -b $branch_name
fi

echo "building..."
./autogen.sh
./configure
make clean && make -j 4 && sudo make install
