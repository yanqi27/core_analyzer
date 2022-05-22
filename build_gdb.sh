# ==============================================================================================
# FILENAME	:	build_gdb.sh
# AUTHOR	:	Celthi
# CREATION	:	2021-12-14
# Script to build the custom gdb with core analyzer.
# This script will the do the following steps
# 1. Create working directory
# 2. download the gdb from gnu.org
# 3. copy the core analyzer code to the gdb
# 4. build the gdb
# you can modify the gdb_version to build the version you like.
# ==============================================================================================
set -e

gdb_version='9.2'
PROJECT_FOLDER=$(pwd)
echo "Current project folder is $PROJECT_FOLDER"
echo "installing gdb $gdb_version..."
build_space=$PROJECT_FOLDER/build
mkdir -p $build_space
cd $build_space
gdb_to_install="gdb-$gdb_version"
tar_gdb="${gdb_to_install}.tar.gz"
if [ ! -f $tar_gdb ]
then
    wget http://ftp.gnu.org/gnu/gdb/$tar_gdb
fi
if [ ! -d $gdb_to_install ]
then
    tar -xvf $tar_gdb
fi

echo "copying the core analyzer files into the gdb folder"
destination="$build_space/$gdb_to_install/gdb"
source="$PROJECT_FOLDER/src"
cd $PROJECT_FOLDER
python $PROJECT_FOLDER/copy_gdb_before_building.py $source $destination

echo "make out-of-source build folder"
build_folder=$build_space/$gdb_to_install/build
mkdir -p $build_folder
cd $build_folder

echo "building..."
PWD=$(pwd)
# if you prefer the gdb with debug symbol use commented line to build
# $PWD/../configure -disable-binutils --with-python --disable-ld --disable-gold --disable-gas --disable-sim --disable-gprof CXXFLAGS='-g  -std=gnu++17' CFLAGS='-g' --prefix=/usr

$PWD/../configure
make  && make install && rm -rf $build_folder
