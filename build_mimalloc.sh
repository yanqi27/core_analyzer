#!/usr/bin/env bash

# =============================================================================
# FILENAME	:	build_mimalloc.sh
# AUTHOR	:	Michael Yan
# CREATION	:	2026-04-02
# Script to build microsoft/mimalloc with specified version.
#
# This script will the do the following steps
# 1. Create working directory
# 2. clone the mimalloc source
# 3. checkout the desired release version
# 4. configure, build and install
# =============================================================================
set -e

if [ "$#" -ne 1 ]
then
  echo "Usage: $0 <mimalloc version>"
  echo "    For example, \"$0 2.2.7\""
  echo "    Please refer to https://github.com/microsoft/mimalloc/tags"
  exit 1
fi

PROJECT_FOLDER=$(pwd)
release_tag=$1
# prefix release tag with 'v' if not already
if [[ $release_tag != v* ]]; then
    release_tag="v$release_tag"
fi

echo "Current project folder is $PROJECT_FOLDER"
build_folder=$PROJECT_FOLDER/build
mkdir -p $build_folder
cd $build_folder

# workaround the problem of multi builds from the same source folder, for example, 2.15 and 2.14
rm -rf ./mimalloc

scr_dir="mimalloc"
if [ ! -d $scr_dir ]
then
    echo "cloning mimalloc ..."
    git clone https://github.com/microsoft/mimalloc.git
fi
cd $scr_dir

echo "checkout $release_tag"
branch_name=mimalloc-$release_tag
if [ -n "$(git branch --list ${branch_name})" ]
then
    echo "Branch name $branch_name already exists."
else
    git checkout tags/$release_tag -b $branch_name
fi

mkdir -p out/release
cd out/release

echo "building..."
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo  ../..
make clean && make -j 4 && sudo make install
