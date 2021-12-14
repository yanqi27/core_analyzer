# ==============================================================================================
# FILENAME	:	build_gdb.sh
# AUTHOR	:	Celthi
# CREATION	:	2021-12-14
# Script to build the custom gdb with core analyzer.
# This script will the do the following steps
# 1. Create working directory
# 2. download the gdb 9.2 from gnu.org
# 3. copy the core analyzer code to the gdb
# 4. build the gdb
# ==============================================================================================

PROJECT_FOLDER=$(pwd)
echo "Current project folder is $PROJECT_FOLDER"
echo "installing gdb 9.2..."
temp_folder='gdb_download'
mkdir -p /tmp/$temp_folder
cd /tmp/$temp_folder
gdb_to_install='gdb-9.2'
tar_gdb="${gdb_to_install}.tar.gz"
if [ ! -f $tar_gdb ]
then
    wget http://ftp.gnu.org/gnu/gdb/$tar_gdb
fi
if [ ! -d $tar_gdb ]
then
    tar -xf $tar_gdb
fi
cd $gdb_to_install
cp -rLv $PROJECT_FOLDER/gdbplus/gdb-9.2/gdb . 
mkdir build
cd build
PWD=$(pwd)
# if you prefer the gdb with debug symbol use commented line to build
# $PWD/../configure -disable-binutils --disable-ld --disable-gold --disable-gas --disable-sim --disable-gprof CXXFLAGS='-g' CFLAGS='-g' --prefix=/usr
$PWD/../configure
make && make install && rm -rf /tmp/$temp_folder
