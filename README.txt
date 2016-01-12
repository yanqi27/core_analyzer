This project is compressed in a 7z file. You need the tool (http://www.7-zip.org/) to uncompress it.
Please refer to the project's web site http://core-analyzer.sourceforge.net/ for detail.

Version 2.16 adds functions to display top variables that consume the most heap memory, and how much heap memory a variable references directly or indirectly, which helps identify memory hogs in a program. Function "decode" is rewritten to enhance relationship of symbols and types with a register table. Commands are streamlined for easier use, e.g., "tref" is replaced by "ref /t" and "block" is now "heap /b".

Version 2.15 adds functions to display memory histogram and memory leaks, as well as miscellaneous buf fixes.

Version 2.14 supports MacOSX platform. It also enhances "decode" command for multiple frames.

Version 2.13 adds support to 32-bit Vista/Windows 2008 programs, and Windbg "decode" command.

Version 2.12 adds support to 32-bit program of Linux/x86 platform

Version 2.11 supports python extension for gdb debugger.

Version 2.10 adds a feature to display the top n heap memory blocks in terms of size. It also tries to reveal which other objects have references to these big memory blocks. The function sheds some light on how process's memory is used.

Version 2.9 adds "decode" command to gdb extension, which displays disassembled instructions annotated with data object  context. It helps to understand what happens at machine instruction level with ease even for highly optimized code. A couple of bug fixes are also included.

Version 2.8 adds a search function of shared objects among threads. It provides an unique view of how involved threads synchronize and share data. If race condition is suspected, a full list of candidates is ready for verification.

Version 2.7 adds C++ object search function. Given an expression, it returns all instances (and their references) of the class as long as its object starts with a pointer to the class's virtual table.

Version 2.6 fixes heap data structures for Linux glibc 2.5 and later, i.e. RedHat 5.x and 6.x. It also adds command "set/unset" to repair damaged heap in order to search for suspects where it is otherwise impossible.

Version 2.5 fixes miscellaneous defects of Windows heap.

Version 2.4 adds support for Windows Vista, Windows 7 and Windows 2008 server.

Version 2.3 includes the stand-alone tool and integration with gdb and windbg debuggers. At the root of the source bundle, you will see the following three folders:
/app              #console-based standalone tool
/gdbplus          #integration with gdb debugger
/Windbg_ext       #integration with Windbg as an extension DLL

There is a README file in each of the folder for more detailed information. The download includes binary executables on Linux/x_86_64 and Windows/x64. You can also build them with the source files. An introduction and usage tutorial may be found at the project's website: http://core-analyzer.sourceforge.net/.
