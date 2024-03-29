# Core Analyzer [![Docker Image CI](https://github.com/yanqi27/core_analyzer/actions/workflows/docker-image.yml/badge.svg)](https://github.com/yanqi27/core_analyzer/actions/workflows/docker-image.yml)
A power tool to debug memory issues. By parsing the memory image of a process's core dump file or its live address space, core analyzer is able to scan the target's heap data for memory corruption, search the whole address space for data object's references, or analyze memory pattern. It is thorough, labor-free, and insightful. It is proved to be invaluable to debug many tough issues.

# Features
* Heap Memory
    - Scan heap and report memory corruption and memory usage statistics
    - Display the layout of memory blocks surrounding a given address
    - Display the memory block status containing a given address
    - Show top heap memory blocks with biggest size (potential memory hog)
* Object Reference
    - Find an object’s size, type and symbol associated with a given memory address
    - Search and report all references to a given object with any levels of indirection
* Others
    - Find all object instances of a given C++ class
    - Display objects shared by selected or all threads
    - Display disassembled instructions annotated with data object  context
    - Data pattern within a range of memory region
    - Detail process map including all segments and their attributes

The tool supports x86_64 architecture including Windows/RedHat/SUSE/MacOSX. It integrates with gdb and Windbg debuggers and supports gdb's python extension.

# How to build it
To build it, just run the `./build_gdb.sh`, it will build the gdb with core analyzer support. You can modified the `build_gdb.sh` to configure how the gdb is built and which version you would like to build.

# How to use it
For more information, please see the project's web site http://core-analyzer.sourceforge.net/

# Tested Platforms
The latest release passed the build and sanity tests (with a few exceptions) on the following platforms with various versions of heap manager, gdb and OS.

* Heap Manager
    - glibc/ptmalloc 2.17, 2.27 - 2.37
	- gperftools/tcmalloc 2.7 - 2.10
	- jemalloc 5.3.0, 5.2.1, 5.2.0
	- Windows/mscrt 9, 10, 11
	- Darwin

* gdb
    - 7.1.11, 8.1, 9.2, 12.1
	- 1824 (Darwin)

* OS
    - Ubuntu 16.04, 18.04, 20.04, 22.04, 23.04; Debian 11, 12
	- Redhat 8, 9; CentOS 7, 8; fedora 36, 37
	- Suse 15
	- Windows 9, 10, 11

* Compiler
    - gcc
	- VS2019
