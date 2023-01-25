## Overview
Core analyzer is integrated with gdb and Windbg, the source level debuggers on Linux and Windows. By leveraging the debug symbols, core analyzer is able to reveal memory errors and profiling information in the context of the executed program. Since gdb is open sourced, core analyzer code is compiled and linked into gdb executable directly. On the other hand, Windbg has a comprehensive APIs for extension DLL, of which core analyzer makes use to access the target and its symbols. In both cases, custom debugger commands are added for the core analyzer functions.

To use the features, you will need to recompile gdb from source, install it and run it as usual. While on Windows, you may compile the core analyzer extension DLL (`ref.dll`), load it into Windbg with `.load` command. There are other ways to load it automatically. Please see Windbg document for more information.

## Commands
The following paragraphs list the custom debugger commands and their usage with some examples. The syntax is shown in gdb command while Windows' command is the same except a '!' is prefixed as required by the Windbg's convention of extension command.
Examples are taken from the repo's test program `mallocTest`.

- [help](#help) List supported commands
- [heap](#heap) Scan memory heap
- [reference](#reference) Search variables/objects that reference the input address range
- [object](#object) Search for objects that match the input type
- [decode](#decode) Disassemble current function with detail annotation of object context
- [shared objects](#shared-objects) Find objects that are currently referenced from multiple threads
- [segment](#segment) Display memory segment(s)
- [pattern](#pattern) Guess the data types of the given memory region
- [misc](#miscellaneous) Helpers
- [setting](#settings) Parameters to change the behavior/configuration of the core analyzer

### help
```shell
ca_help
```
This command lists supported core analyzer commands.

### heap
```shell
heap  [/verbose or /v] 

heap  [/leak or /l]

heap  [/block or /b]  <addr_expr>

heap  [/cluster or /c]  <addr_expr>

heap  [/usage or /u]  <var_expr>

heap  [/topblock or /tb]  <count>

heap  [/topuser or /tu]  <count>
```
This command parses the target process's heaps, validates the heap data and detects any possible memory corruption. If there is no error, the command reports a summary of the heaps. The exact output depends on the underlying heap memory allocator.

Option `/verbose` displays more detail while walking each heap, including memory histogram for both in-use and free memory.

Option `/leak` reports a list of memory blocks that are potentially leaked. The algorithm is based on the concept that a heap memory, which is not referenced by any local or global variable directly or indirectly, is not reachable by any code and therefore is leaked. The tool may report false positives if a module’s section is not recognized by the debugger.

Option `/block` queries the memory block that consists of the input address. It shows the memory block's address range, its size, and whether it is free or in use.

Option `/cluster` displays a cluster of memory blocks surrounding the given address, in other words, the memory layout around the interested spot.

Option `/usage` calculates heap memory consumption by a variable. It reports the total heap memory in bytes that are directly and indirectly reachable by the variable. The memory may be allocated and owned by the variable or shared with others.

Option `/topblock` lists biggest heap memory blocks in terms of size.

Option `/topuser` lists local or global variables that consume the most heap memory in terms of aggregated size, or the total heap memory reachable through a variable. This is equivalent to query every local and global variable with `heap /usage`, and find the top list.

**Example:** heap summary
```
(gdb) heap
        Tuning params & stats:
                mmap_threshold=131072
                pagesize=4096
                n_mmaps=17
                n_mmaps_max=65536
                total mmap regions created=17
                mmapped_mem=2932736
                sbrk_base=0x55555555e000
        Main arena (0x7ffff7d9bb80) owns regions:
                [0x55555555e010 - 0x55555557f000] Total 131KB in-use 82(74KB) free 1(57KB)
        Dynamic arena (0x7fffe8000020) owns regions:
                [0x7fffe80008d0 - 0x7fffe821f000] Total 2MB in-use 2071(1MB) free 1316(1MB)
        Dynamic arena (0x7ffff0000020) owns regions:
                [0x7ffff00008d0 - 0x7ffff0213000] Total 2MB in-use 2032(1MB) free 1564(1MB)
        mmap-ed large memory blocks:
                [0x7ffff678d010 - 0x7ffff67b5000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff67b5010 - 0x7ffff67d9000] Total 143KB in-use 1(143KB) free 0(0)
                [0x7ffff67d9010 - 0x7ffff6805000] Total 175KB in-use 1(175KB) free 0(0)
                [0x7ffff6805010 - 0x7ffff682a000] Total 147KB in-use 1(147KB) free 0(0)
                [0x7ffff682a010 - 0x7ffff6858000] Total 183KB in-use 1(183KB) free 0(0)
                [0x7ffff6858010 - 0x7ffff687d000] Total 147KB in-use 1(147KB) free 0(0)
                [0x7ffff687d010 - 0x7ffff68ad000] Total 191KB in-use 1(191KB) free 0(0)
                [0x7ffff68ad010 - 0x7ffff68d7000] Total 167KB in-use 1(167KB) free 0(0)
                [0x7ffff68d7010 - 0x7ffff6901000] Total 167KB in-use 1(167KB) free 0(0)
                [0x7ffff6901010 - 0x7ffff6924000] Total 139KB in-use 1(139KB) free 0(0)
                [0x7ffff6924010 - 0x7ffff6949000] Total 147KB in-use 1(147KB) free 0(0)
                [0x7ffff6949010 - 0x7ffff6976000] Total 179KB in-use 1(179KB) free 0(0)
                [0x7ffff6976010 - 0x7ffff699c000] Total 151KB in-use 1(151KB) free 0(0)
                [0x7ffff699c010 - 0x7ffff69cb000] Total 187KB in-use 1(187KB) free 0(0)
                [0x7ffff69cb010 - 0x7ffff69f9000] Total 183KB in-use 1(183KB) free 0(0)
                [0x7ffff69f9010 - 0x7ffff6a28000] Total 187KB in-use 1(187KB) free 0(0)
                [0x7ffff7a2a010 - 0x7ffff7a5b000] Total 195KB in-use 1(195KB) free 0(0)

        There are 3 arenas and 17 mmap-ed memory blocks Total 7MB
        Total 4202 blocks in-use of 4MB
        Total 2881 blocks free of 2MB
```

**Example:** memory corruption
```
(gdb) heap
        Tuning params & stats:
                mmap_threshold=131072
                pagesize=4096
                n_mmaps=17
                n_mmaps_max=65536
                total mmap regions created=17
                mmapped_mem=2818048
                sbrk_base=0x55555555e000
        Main arena (0x7ffff7d9bb80) owns regions:
                [0x55555555e010 - 0x55555557f000] Total 131KB in-use 82(74KB) free 1(57KB)
        Dynamic arena (0x7fffe8000020) owns regions:
                [0x7fffe80008d0 - 0x7fffe821c000] Total 2MB in-use 2013(1MB) free 1416(1MB)
        Dynamic arena (0x7ffff0000020) owns regions:
                [0x7ffff00008d0 - 0x7ffff0214000] Total 2MB
				Failed to walk arena. The chunk at 0x7ffff0000de0 may be corrupted. Its size tag is 0x0

        mmap-ed large memory blocks:
                [0x7ffff67a9010 - 0x7ffff67cd000] Total 143KB in-use 1(143KB) free 0(0)
                [0x7ffff67cd010 - 0x7ffff67fa000] Total 179KB in-use 1(179KB) free 0(0)
                [0x7ffff67fa010 - 0x7ffff6827000] Total 179KB in-use 1(179KB) free 0(0)
                [0x7ffff6827010 - 0x7ffff6850000] Total 163KB in-use 1(163KB) free 0(0)
                [0x7ffff6850010 - 0x7ffff687c000] Total 175KB in-use 1(175KB) free 0(0)
                [0x7ffff687c010 - 0x7ffff689d000] Total 131KB in-use 1(131KB) free 0(0)
                [0x7ffff689d010 - 0x7ffff68cb000] Total 183KB in-use 1(183KB) free 0(0)
                [0x7ffff68cb010 - 0x7ffff68f3000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff68f3010 - 0x7ffff691b000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff691b010 - 0x7ffff6947000] Total 175KB in-use 1(175KB) free 0(0)
                [0x7ffff6947010 - 0x7ffff696a000] Total 139KB in-use 1(139KB) free 0(0)
                [0x7ffff696a010 - 0x7ffff6998000] Total 183KB in-use 1(183KB) free 0(0)
                [0x7ffff6998010 - 0x7ffff69bd000] Total 147KB in-use 1(147KB) free 0(0)
                [0x7ffff69bd010 - 0x7ffff69de000] Total 131KB in-use 1(131KB) free 0(0)
                [0x7ffff69de010 - 0x7ffff6a07000] Total 163KB in-use 1(163KB) free 0(0)
                [0x7ffff6a07010 - 0x7ffff6a28000] Total 131KB in-use 1(131KB) free 0(0)
                [0x7ffff7a2a010 - 0x7ffff7a5b000] Total 195KB in-use 1(195KB) free 0(0)

1 Errors encountered while walking the heap!
[Error] Failed to walk heap
```

**Example:** scan heap in verbose mode
```
(gdb) heap /v
        Tuning params & stats:
                mmap_threshold=131072
                pagesize=4096
                n_mmaps=17
                n_mmaps_max=65536
                total mmap regions created=17
                mmapped_mem=2863104
                sbrk_base=0x55555555e000
        Main arena (0x7ffff7d9bb80) owns regions:
                [0x55555555e010 - 0x55555557f000] Total 131KB in-use 82(74KB) free 1(57KB)
        Dynamic arena (0x7fffe8000020) owns regions:
                [0x7fffe80008d0 - 0x7fffe820b000] Total 2MB in-use 2004(997KB) free 1381(1MB)
        Dynamic arena (0x7ffff0000020) owns regions:
                [0x7ffff00008d0 - 0x7ffff0211000] Total 2MB in-use 2048(1MB) free 1561(1024KB)
        mmap-ed large memory blocks:
                [0x7ffff679e010 - 0x7ffff67bf000] Total 131KB in-use 1(131KB) free 0(0)
                [0x7ffff67bf010 - 0x7ffff67eb000] Total 175KB in-use 1(175KB) free 0(0)
                [0x7ffff67eb010 - 0x7ffff6813000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff6813010 - 0x7ffff6835000] Total 135KB in-use 1(135KB) free 0(0)
                [0x7ffff6835010 - 0x7ffff685c000] Total 155KB in-use 1(155KB) free 0(0)
                [0x7ffff685c010 - 0x7ffff6889000] Total 179KB in-use 1(179KB) free 0(0)
                [0x7ffff6889010 - 0x7ffff68b6000] Total 179KB in-use 1(179KB) free 0(0)
                [0x7ffff68b6010 - 0x7ffff68e6000] Total 191KB in-use 1(191KB) free 0(0)
                [0x7ffff68e6010 - 0x7ffff690f000] Total 163KB in-use 1(163KB) free 0(0)
                [0x7ffff690f010 - 0x7ffff6936000] Total 155KB in-use 1(155KB) free 0(0)
                [0x7ffff6936010 - 0x7ffff6966000] Total 191KB in-use 1(191KB) free 0(0)
                [0x7ffff6966010 - 0x7ffff6990000] Total 167KB in-use 1(167KB) free 0(0)
                [0x7ffff6990010 - 0x7ffff69b1000] Total 131KB in-use 1(131KB) free 0(0)
                [0x7ffff69b1010 - 0x7ffff69d9000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff69d9010 - 0x7ffff6a00000] Total 155KB in-use 1(155KB) free 0(0)
                [0x7ffff6a00010 - 0x7ffff6a28000] Total 159KB in-use 1(159KB) free 0(0)
                [0x7ffff7a2a010 - 0x7ffff7a5b000] Total 195KB in-use 1(195KB) free 0(0)

        There are 3 arenas and 17 mmap-ed memory blocks Total 6MB
        Total 4151 blocks in-use of 4MB
        Total 2943 blocks free of 2MB

        ========== In-use Memory Histogram ==========
        Size-Range     Count       Total-Bytes
        16 - 32        178(4%)     4KB(0%)
        32 - 64        108(2%)     5KB(0%)
        64 - 128       287(6%)     26KB(0%)
        128 - 256      466(11%)    85KB(1%)
        256 - 512      1074(25%)   405KB(8%)
        512 - 1024     1960(47%)   1MB(29%)
        1024 - 2KB     60(1%)      60KB(1%)
        64KB - 128KB   1(0%)       71KB(1%)
        128KB - 256KB  17(0%)      2MB(56%)
        Total          4151        4MB
        ========== Free Memory Histogram ==========
        Size-Range     Count       Total-Bytes
        16 - 32        101(3%)     2KB(0%)
        32 - 64        133(4%)     6KB(0%)
        64 - 128       238(8%)     21KB(1%)
        128 - 256      267(9%)     50KB(2%)
        256 - 512      526(17%)    199KB(9%)
        512 - 1024     1124(38%)   846KB(39%)
        1024 - 2KB     406(13%)    559KB(26%)
        2KB - 4KB      136(4%)     352KB(16%)
        4KB - 8KB      11(0%)      51KB(2%)
        32KB - 64KB    1(0%)       57KB(2%)
        Total          2943        2MB
```

**Example:** display potential memory leaks
```
(gdb) heap /l
Potentially leaked heap memory blocks:
[1] addr=0x55555555e010 size=648
[2] addr=0x5555555707d0 size=24
[3] addr=0x5555555707f0 size=296
[4] addr=0x7ffff00008d0 size=648
Total 4 (1KB) leak candidates out of 4151 (4MB) in-use memory blocks
```

**Example:** query memory block
```
(gdb) heap /b regions[2].p
        [In-use]
        [Address] 0x7ffff0000e70
        [Size]    760
        [Offset]  0
(gdb) heap /b 0x7ffff0000e80
        [In-use]
        [Address] 0x7ffff0000e70
        [Size]    760
        [Offset]  16
```

**Example:** display memory blocks around given address
```
(gdb) heap /c regions[2].p
        Dynamic arena (0x7ffff0000020): [0x7ffff00008c0 - 0x7ffff0211000]
                        [0x7ffff00008d0 - 0x7ffff0000b58] 648 bytes inuse
                [0x7ffff0000b60 - 0x7ffff0000cc8] 360 bytes free
                [0x7ffff0000cd0 - 0x7ffff0000e68] 408 bytes free
                        [0x7ffff0000e70 - 0x7ffff0001168] 760 bytes inuse
                [0x7ffff0001170 - 0x7ffff00014c8] 856 bytes free
				...
				[0x7ffff02108f0 - 0x7ffff0211000] 1808 bytes free

        Total inuse 2048 blocks 1087088 bytes
        Total free 1561 blocks 1048576 bytes
```

**Example:** heap memory usage (local variable objlist is of type std::list<Base *>)
```
(gdb) print objlist
$4 = std::__cxx11::list = {[0] = 0x55555556ffb0, [1] = 0x55555556fff0, [2] = 0x555555570030, [3] = 0x555555570070, [4] = 0x5555555700b0, [5] = 0x5555555700f0, [6] = 0x555555570130, [7] = 0x555555570170, [8] = 0x5555555701b0, [9] = 0x5555555701f0, [10] = 0x555555570230, [11] = 0x555555570270, [12] = 0x5555555702b0, [13] = 0x5555555702f0, [14] = 0x555555570330, [15] = 0x555555570370, [16] = 0x5555555703b0, [17] = 0x5555555703f0, [18] = 0x555555570430, [19] = 0x555555570470, [20] = 0x5555555704b0, [21] = 0x5555555704f0, [22] = 0x555555570530, [23] = 0x555555570570, [24] = 0x5555555705b0, [25] = 0x5555555705f0, [26] = 0x555555570630, [27] = 0x555555570670, [28] = 0x5555555706b0, [29] = 0x5555555706f0, [30] = 0x555555570730, [31] = 0x555555570770}

(gdb) heap /u objlist
Heap memory consumed by [stack] thread 1 frame 1 objlist @0x7fffffffdf90
All reachable:
    |--> 1KB (64 blocks)
Directly referenced:
    |--> 48 (2 blocks)
```

**Example:** display biggest 4 heap memory blocks
```
(gdb) heap /tb 4
Top 4 biggest in-use heap memory blocks:
        addr=0x7ffff7a2a010  size=200688 (195KB)
        addr=0x7ffff68b6010  size=196592 (191KB)
        addr=0x7ffff6936010  size=196592 (191KB)
        addr=0x7ffff685c010  size=184304 (179KB)
```

**Example:** display top 4 local/global variables or heap memory blocks that reference most heap memory
```
(gdb) heap /tu 4
[1] [heap block] 0x7ffff7a2a010--0x7ffff7a5b000 size=200688
    |--> 4MB (4067 blocks)
[2] [.data/.bss] /workspaces/core_analyzer/test/mallocTest regions @0x55555555d280: 0x7ffff7a2a010
    |--> 195KB (1 blocks)
[3] [stack] thread 3 frame 2 rsp+40 @0x7ffff7227d68: 0x7ffff7a5a178
    |--> 195KB (1 blocks)
[4] [heap block] 0x7ffff68b6010--0x7ffff68e6000 size=196592
    |--> 191KB (1 blocks)
```

### reference
```shell
ref  <addr_expr>

ref  [/thread or /t]  <addr_expr>  <size>  [level]
```
This command searches the target's virtual address space for references to the input address range.

If only one argument is provided, the argument is converted into an address. The command tries to identify the symbol information associated with the input address. It searches the target's virtual space to find a variable with known type, such as a global/local variable or a heap object with RTTI, which references the input address directly or indirectly. If such a variable is found, we could deduce the plausible data type associated with the input address. 

In the second form of the command, both object address and size are given such as an unknown heap memory block. The command searches all references to the data object bounded by the address range.
Option `level` limits the maximum levels of indirect references, which is one by default.
Option `/thread` limits the search to thread contexts only, i.e. threads’ stack memory and registers, which is much faster by skipping heap memory.

**Example:** find the type of an unknown heap memory block
```
(gdb) ref 0x5555555700f0
Search for object type associated with 0x5555555700f0
Address 0x5555555700f0 belongs to heap block [0x5555555700f0, 0x555555570108] size=24
------------------------- 1 -------------------------
[stack] thread 1 frame 1 objlist::"std::__cxx11::_List_base<Base*, std::allocator<Base*> >"._M_impl._M_node::"std::__detail::_List_node_base"._M_next @0x7fffffffdf90: 0x55555556ffd0
    |--> [heap block] 0x55555556ffd0--0x55555556ffe8 size=24 (type="struct std::__detail::_List_node_base")._M_next @+0: 0x555555570010
        |--> [heap block] 0x555555570010--0x555555570028 size=24 (type="struct std::__detail::_List_node_base")._M_next @+0: 0x555555570050
            |--> [heap block] 0x555555570050--0x555555570068 size=24 (type="struct std::__detail::_List_node_base")._M_next @+0: 0x555555570090
                |--> [heap block] 0x555555570090--0x5555555700a8 size=24 (type="struct std::__detail::_List_node_base")._M_next @+0: 0x5555555700d0
                    |--> [heap block] 0x5555555700d0--0x5555555700e8 size=24 (type="struct std::__detail::_List_node_base")._M_next @+0: 0x555555570110
                        |--> [heap block] 0x555555570110--0x555555570128 size=24 @+16: 0x5555555700f0
                            |--> [heap block] 0x5555555700f0--0x555555570108 size=24
```

**Example:** search references to heap block at 0x5555555700f0 with size 24 bytes
```
(gdb) ref 0x5555555700f0 24
Search for references to 0x5555555700f0 size 24 up to 1 levels of indirection
------------------------- Level 1 -------------------------
[heap block] 0x555555570110--0x555555570128 size=24 @+16: 0x5555555700f0
|--> searched target [0x5555555700f0, 0x555555570108)

(gdb) ref 0x5555555700f0 24 4
Search for references to 0x5555555700f0 size 24 up to 4 levels of indirection
------------------------- Level 4 -------------------------
[heap block] 0x555555570050--0x555555570068 size=24 @+0: 0x555555570090
|--> [heap block] 0x555555570090--0x5555555700a8 size=24

[heap block] 0x5555555701d0--0x5555555701e8 size=24 @+8: 0x555555570190
|--> [heap block] 0x555555570190--0x5555555701a8 size=24

------------------------- Level 3 -------------------------
    [heap block] 0x555555570090--0x5555555700a8 size=24 @+0: 0x5555555700d0
    |--> [heap block] 0x5555555700d0--0x5555555700e8 size=24

    [heap block] 0x555555570190--0x5555555701a8 size=24 @+8: 0x555555570150
    |--> [heap block] 0x555555570150--0x555555570168 size=24

------------------------- Level 2 -------------------------
        [heap block] 0x5555555700d0--0x5555555700e8 size=24 @+0: 0x555555570110
        [heap block] 0x555555570150--0x555555570168 size=24 @+8: 0x555555570110
        |--> [heap block] 0x555555570110--0x555555570128 size=24

------------------------- Level 1 -------------------------
            [heap block] 0x555555570110--0x555555570128 size=24 @+16: 0x5555555700f0
            |--> searched target [0x5555555700f0, 0x555555570108)
```

**Example:** search references only in thread contexts
```
(gdb) ref /t 0x7fffffffdfd6 2
Search for thread references to 0x7fffffffdfd6 size 2 up to 1 levels of indirection
------------------------ 1 ------------------------
[stack] thread 3 frame 4 arg @0x7ffff7227da8: 0x7fffffffdfd7

------------------------ 2 ------------------------
[stack] thread 3 frame 4 done @0x7ffff7227db8: 0x7fffffffdfd7

------------------------ 3 ------------------------
[stack] thread 1 frame 1 rsp+40 @0x7fffffffdf88: 0x7fffffffdfd7
```

### object
```script
obj  <type_expr>
```
Given an input type, the command searches for all objects of the specified type. The current implementation supports C++ objects with virtual tables.

**Example:** search object instances of class `Derived`
```
(gdb) obj Derived
Searching objects of type="Derived" size=16 (vtable 0x55555555cbd0--0x55555555cbf8)
    [heap block] 0x55555556ff10--0x55555556ff28 size=24
    [heap block] 0x55555556fef0--0x55555556ff08 size=24
    [heap block] 0x55555556fed0--0x55555556fee8 size=24
    [heap block] 0x55555556feb0--0x55555556fec8 size=24
Total objects found: 4
```

### decode
```
decode [<%reg>=<val>] [from=<addr>] [to=<addr>|end] [frame=f1-f2]
```
This command displays disassembled instructions with annotations of object context. It is intended to help the user to read machine instructions even if they are highly optimized. The annotation tries to reveal the values operated on by the instructions and how they are associated with source-level variables and symbols.
The command uses initial register context and stack memory to show how data objects are muted and referenced as the function is executed. The user should be aware that the command has inherent limitations since it tries to show the progress deduced from the current state.

Option `<%reg>=<val>` allows the user to set the initial value of any register which is changed accordingly as the disassembling progresses. The `%reg` is the register name, e.g. `rdi`.

Options `from=<addr>` and `to=<addr>` allow the user to choose the starting and/or the ending addresses. By default, the command disassembles the currently selected frame starting with the beginning of the function and ends at the instruction currently being executed.

Option `frame=f1-f2` instructs the command to disassemble functions from frame f1 to f2. This may recover certain function arguments that the debugger doesn't display due to optimization, but they may be guessed according to the register rules specified by the x86 ABI.

**Example:** disassemble the main() function with annotation
```
(gdb) decode 

Parameters: argc(edi)=1, argv(rsi)=0x7fffffffe0e8

Dump of assembler code for function main(int, char**):
   0x000055555555692d <+0>:     repz nop %edx                   ## 
   0x0000555555556931 <+4>:     push   %rbp                     ## [%rsp]=0x0
   0x0000555555556932 <+5>:     mov    %rsp,%rbp                ## %rbp=0x7fffffffdff0 [stack] thread 1 frame 1 rsp+144 @0x7fffffffdff0
   0x0000555555556935 <+8>:     push   %r12                     ## [%rsp]=0x555555556360 [.text/.rodata] /workspaces/core_analyzer/test/mallocTest _start (0x555555556360--0x55555555638f)
   0x0000555555556937 <+10>:    push   %rbx                     ## [%rsp]=0x555555558ae0 [.text/.rodata] /workspaces/core_analyzer/test/mallocTest __libc_csu_init (0x555555558ae0--0x555555558b45)
   0x0000555555556938 <+11>:    add    $0xffffffffffffff80,%rsp ## %rsp=0x7fffffffdf60 End of function prologue
   0x000055555555693c <+15>:    mov    %edi,-0x84(%rbp)         ## [%rbp-0x84]=0x1(symbol="argc" type="struct int")
   0x0000555555556942 <+21>:    mov    %rsi,-0x90(%rbp)         ## [%rbp-0x90]=0x7fffffffe0e8(symbol="argv" type="struct char**")
```

### shared objects
```
shrobj [tid0] [tid1] [...]
```
This command displays the objects that are referenced by local variables (including registers and valid stack memory) from at least two selected threads. It is intended to show a full list of candidates that may be subject to threading issues like race conditions or deadlock, etc.

The command accepts an optional list of thread ids (debugger-defined tid). If no thread id is given, all threads are included.

**Example:** search shared objects among threads 2 and 3
```
(gdb) shrobj 2 3
------------------------ 1 ------------------------
shared object: [.data/.bss] /workspaces/core_analyzer/test/mallocTest myLock
    [stack] thread 2 frame 2 rsp+32 @0x7ffff7a28d60: 0x55555555d300
    [stack] thread 2 frame 1 SP @0x7ffff7a28d30: 0x55555555d300
    [stack] thread 2 frame 0 rsp+24 @0x7ffff7a28cd8: 0x55555555d300
    [stack] thread 3 frame 2 rsp+32 @0x7fffef227d60: 0x55555555d300
    [stack] thread 3 frame 1 SP @0x7fffef227d30: 0x55555555d300
    [stack] thread 3 frame 0 rsp+24 @0x7fffef227cd8: 0x55555555d300
------------------------ 2 ------------------------
shared object: [heap block] 0x5555555707b0--0x5555555707c8 size=24
    [stack] thread 2 frame 4 done @0x7ffff7a28db8: 0x5555555707b0
    [stack] thread 2 frame 4 arg @0x7ffff7a28da8: 0x5555555707b0
    [stack] thread 3 frame 4 done @0x7fffef227db8: 0x5555555707b1
    [stack] thread 3 frame 4 arg @0x7fffef227da8: 0x5555555707b1
------------------------ 3 ------------------------
shared object: [.data/.bss] /lib/x86_64-linux-gnu/libc.so.6 pa_next_type
    [register] thread 2 r9=0x7ffff7d9b240
    [register] thread 3 r9=0x7ffff7d9b240
------------------------ 4 ------------------------
shared object: [.data/.bss] /lib/x86_64-linux-gnu/libc.so.6 _nl_global_locale
    [stack] thread 2 frame 12 rsp+206544 @0x7ffff7a5b690: 0x7ffff7d9c4a0
    [stack] thread 2 frame 12 rsp+1680 @0x7ffff7a29650: 0x7ffff7d9c4a0
    [stack] thread 3 frame 12 rsp+1680 @0x7fffef228650: 0x7ffff7d9c4a0
------------------------ 5 ------------------------
shared object: [.data/.bss] /lib/x86_64-linux-gnu/libpthread.so.0 stack_used
    [stack] thread 2 frame 12 rsp+2560 @0x7ffff7a299c0: 0x7ffff7fbc2d0
    [stack] thread 3 frame 12 rsp+2568 @0x7fffef2289c8: 0x7ffff7fbc2d0
```

### segment
```
segment [address]
```
This command displays the target's virtual address segment information.

Option `address` specifies the segment that contains the address. Otherwise, all memory segments are displayed.

**Example:** display the current thread's stack memory segment
```
(gdb) segment $rsp
Address $rsp belongs to segment:
[0x7ffff722a000 - 0x7ffff7a60000]   8408K  rw- [stack] [tid=2] [lwp=53432]
```

### pattern
```
pattern <start> <end>
```
This command guesses the data types of the memory content within the input address range [start, end]. For example, it tries to interpret a group of bytes as a string if they are all printable characters; an object pointer if the aligned bytes forms a pointer value that points to a valid heap memory block, etc.

**Example:** 
```
(gdb) pattern 0x7ffff7a28d60 0x7ffff7a28d80
memory pattern [0x7ffff7a28d60, 0x7ffff7a28d80]:
0x7ffff7a28d60: 0x55555555d300 => [.data/.bss] /workspaces/core_analyzer/test/mallocTest myLock
0x7ffff7a28d68: 0x7ffff7a5a178 => [stack] thread 2 frame 12 rsp+201144 @0x7ffff7a5a178
0x7ffff7a28d70: 0x7ffff7a28d90 => [stack] thread 2 frame 3 rsp+16 @0x7ffff7a28d90
0x7ffff7a28d78: 0x555555556616 => [.text/.rodata] /workspaces/core_analyzer/test/mallocTest mysleep(unsigned long)
```

### miscellaneous
These commands may be handy for the debugging purpose.

**Example:** display type information (Windbg style)
```
(gdb) dt Derived2
type=Derived2  size=16
{
  +0   (base) struct Base  size=16
  {
    +0   <unnamed type>** _vptr.Base  size=8
    +8   struct int data  size=4
  }
  +12  struct float speed  size=4
};
```

**Example:** set/unset a pseudo value at the specified address. This changes the memory content from the core analyzer's point of view but it has no effect on the debugger. The user may play with it to "fix" a memory corruption.
```
# gdb
assign [addr] [value]
unassign <addr>

# Windbg
!set [addr] [value]
!unset <addr>
```

**Example:** display build-ids of all target modules. For example, to match a module's version.
```
(gdb) buildid
/workspaces/core_analyzer/test/mallocTest 1d5d31f85b6bfc71c3d058645ee8c7bdc1b5e79e
/lib64/ld-linux-x86-64.so.2 4587364908de169dec62ffa538170118c1c3a078
system-supplied DSO at 0x7ffff7fcd000 d63643a7045f18103e9c9455b9f8f09a1c60ba65
/lib/x86_64-linux-gnu/libpthread.so.0 7b4536f41cdaa5888408e82d0836e33dcf436466
/lib/x86_64-linux-gnu/libstdc++.so.6 c90e6603c7cdf84713cd445700a575d3ea446d9b
/lib/x86_64-linux-gnu/libgcc_s.so.1 4abd133cc80e01bb388a9c42d9e3cb338836544a
/lib/x86_64-linux-gnu/libc.so.6 1878e6b475720c7c51969e69ab2d276fae6d1dee
/lib/x86_64-linux-gnu/libm.so.6 fe91b4090ea04c1559ff71dd9290062776618891
```

### settings
These commands may change the default configuration of the core analyzer.

**Example:** set/show the underlying heap manager of the target. Heap parsers of various allocators including different versions are compiled into the core analyzer. At the initialization, the proper one is activated based on the target's symbols that are unique to that allocator of a specific version. The user may use this command to view or change the selection.
```
(gdb) switch_heap
Please provide the heap manager name, currently supported heap managers: pt 2.27, (current)pt 2.28-2.31, pt 2.32-2.35, tc.
```

**Example:** set/show the indirection level of search of command `shrobj`
```
(gdb) shrobj_level
Current indirection level of shared-object search is 1

(gdb) shrobj_level 2
Current indirection level of shared-object search is set to 2
```

**Example:** set/show the maximum indirection level of reference search of command `ref`
```
(gdb) max_indirection_level
Current max levels of indirection is 16

(gdb) max_indirection_level 8
Current max levels of indirection is set to 8
```
