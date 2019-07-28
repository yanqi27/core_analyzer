### Introduction
gdbplus is an extension to the formal releases of GNU debugger gdb
(http://www.gnu.org/software/gdb/) with core analyzer embedded. It supports
the same functions, such as heap scan, object reference search, memory pattern
analysis, etc., with the additional power of debug symbols. It has additional
features like disassembling optimized code with the context of heap objects. The
current implementation supports x86_64 architecture. However, it won't be
difficult to port to other architectures and platforms if necessary.

### Features
A set of gdb commands are added to this custom build. Detail description of
these functions may be found in the project's website:
http://core-analyzer.sourceforge.net/

### How to Build
The source bundle includes an executable "gdb" under `bin` directory. This is for
evaluation and testing purpose. It is recommended to build your own executable
in your environment. You will need to download the corresponding verion of gdb
(http://www.gnu.org/software/gdb/download/). Copy gdbplus source and header
files (gdbplus/gdb-7.11.1/gdb) into the respective subfoler of downloaded
source. Then build as usual.
```
$ ./configure --with-python --prefix=/usr/local
$ make
```

### Useful Command Options

#### data-directory
If you use gdb python, you will need to install python scripts which are usually
under `/usr/share/gdb` for many Linux distros. The `gdb` binary included in this
repo has a different path `/usr/local/share/gdb`. You may use `--data-directory` option
to specify the installed python script path on your host.
```
gdb --data-directory=/usr/share/gdb
```

#### Debug Symbols of Heap Structures
Core analyzer extracts heap metadata with the help of debug symbols. Without the
matching debug symbols, its functions are limited or don't work at all. For
example, Linux heap data structures are defined in libc.so which debug symbols
are required. On Ubuntu, this is package `libc6-dbg` which is installed out of box.
On CentOS, you can run command `sudo debuginfo-install -y glibc`.
libc.so debug symbols are installed at /usr/lib/debug by default. If gdb doesn't find
it, you can add the following line in you `.gdbinit` file.
```
set debug-file-directory /usr/lib/debug
```
