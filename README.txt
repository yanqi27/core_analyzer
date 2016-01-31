Core analyzer is a power tool to debug memory issues. By parsing the memory image of a process's core dump file or its live address space, core analyzer is able to scan the target's heap data for memory corruption, search the whole address space for data object's references, or analyze memory pattern. It is thorough, labor-free, and insightful. It is proved to be invaluable to debug many tough issues.

The main features include:
Heap Memory
    - Scan heap and report memory corruption and memory usage statistics
    - Display the layout of memory blocks surrounding a given address
    - Display the memory block status containing a given address
    - Show top heap memory blocks with biggest size (potential memory hog)
Object Reference
    - Find an object’s size, type and symbol associated with a given memory address
    - Search and report all references to a given object with any levels of indirection
Others
    - Find all object instances of a given C++ class
    - Display objects shared by selected or all threads
    - Display disassembled instructions annotated with data object  context
    - Data pattern within a range of memory region
    - Detail process map including all segments and their attributes

The tool supports x86_64 architecture including Windows/RedHat/SUSE/MacOSX (32-bit and 64-bit). It integrates with gdb and Windbg debuggers and supports gdb's python extension.

For more information, please see the project's web site http://core-analyzer.sourceforge.net/
