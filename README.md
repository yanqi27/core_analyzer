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

| Heap Manager | gdb | OS | Compiler |
| ----------- | ----------- | ----------- | ----------- |
| glibc/ptmalloc 2.17, 2.27, 2.31, 2.35   | 7.1.11, 8.1, 9.2, 12.1| Ubuntu 16.04, 18.04, 20.04, 22.04 | gcc 5, 7, 9, 12 |
| gperftools/tcmalloc 2.7, 2.8, 2.9 | 1824 (Darwin)     | CentOS 7.6, 8.5 | VS2019 |
| Windows/mscrt 9, 10, 11           |                       | Windows 9, 10, 11 | 
| Darwin                            |
