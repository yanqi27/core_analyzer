Introduction
=====================================================
gdbplus is an extension to the formal releases of GNU debugger gdb (http://www.gnu.org/software/gdb/) with core analyzer incorporated. It supports the same functions, such as heap scan, object reference search, memory pattern analysis, etc., with the additional power of debug symbols. The result is clear picture of the memory layout and object relationship of data objects. These added features may shed light on tough issues such as memory corruption, debugging highly optimized code, race condition, etc. The current implementation is tested on x86_64 architecture including RedHat/SUSE both 32-bit and 64-bit, MacOSX 64-bit only. It won't be difficult to port to other platforms if necessary.

Features
=====================================================
A set of gdb commands are added to this custom build. Detail description of these functions may be found in the project's website: http://core-analyzer.sourceforge.net/

How to Build
=====================================================
The source bundle includes the executable "gdb" at gdbplus/gdb-7.5.1/gdb/gdb (RedHat/SUSE) or gdbplus/gdb-1824/src/gdb/gdb (MacOSX). If you want to build by yourself, you will need to download the corresponding verion of gdb (http://www.gnu.org/software/gdb/download/). Copy gdbplus source and header files (gdbplus/gdb-7.5.1/gdb) into the respective subfoler of downloaded source. Then build as usual.

$./configure
$make
