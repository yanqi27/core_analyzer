Introduction
=====================================================
This project integrates core analyzer into windbg in the form of a DLL extension. It supports the same functions, such as heap scan, object reference search, memory pattern analysis, etc., with the additional power of debug symbols. The result is clear picture of the memory layout and object relationship of data objects. These added features may shed light on tough issues such as memory corruption, debugging highly optimized code, etc. The current implementation is tested on Window 2003/x64. It won't be difficult to port to other platforms if necessary.


Features
=====================================================
To use the feature, you need to load the DLL into windbg.
0:000> .load c:\ref.dll

The DLL supports the following command. Description of these functions may be found in the project's website: http://core-analyzer.sourceforge.net/

Command: !heap [addr]

Command: !block <addr>

Command: !ref <addr> [size] [level]

Command: !tref <addr> [size] [level]

Command: !obj  <expression>

Command: !shrobj  <thread id> <thread id> ...

Command: !pattern <start> <end>

Command: !segment [addr]

Command: !set  [address]  [value]

Command: !unset  <address>

Command: !max_ref_level  <n>

Command: !shrobj_level  <n>

Command: !include_free / !ignore_free

Command: !help


How to Build
=====================================================
You may use the bundled binary at \Windbg_ext\pta\objchk_wnet_amd64\amd64\ref.dll. If you want to build by yourself, please use the following steps:
(1) Download Windows Driver Kits (WDK)
(2) Open a WDK build window, and change folder to \Windbg_ext
(3) Set windbg SDK path. Please refer to included batch file setenv.bat, you need to set to the path of your installation.
(4) Use "build" command to generate the DLL.

Test
=====================================================
There is a sanity test in the project to compare the the tool's result with the test program. To run the test:
[1] Run mallocTest.exe, it will malloc/free many memory blocks and pause.
[2] Attach Windbg to the process and run the following commands
	0:000> ~0s
	0:000> .frame a
	0:000> .load <path-to-binary>/ref.dll
	0:000> $$>a<$(root)\core_analyzer\Windbg_ext\ref\mallocTest\check.wds <output-file-path>

Troubleshoot
=====================================================
The tool parses heaps based on some assumptions of Windows heap data structures. Since they are undocumented and may change from release to release, the result may be totally wrong on certain Windows versions.
You may also use another windbg extension exts to compare the result. For example,
0:000> !exts.heap -x 00000234c1b1a9e0 
Entry             User              Heap              Segment               Size  PrevSize  Unused    Flags
-------------------------------------------------------------------------------------------------------------
00000234c1b1a9a0  00000234c1b1a9b0  00000234c1450000  00000234c1a5e870       2c0      -            f  LFH;busy 

0:000> !ref.heap /b 00000234c1b1a9e0 
	[In-use]
	[Address] 0x234c1b1a9e0
	[Size]    637
	[Offset]  0


In case of error, try
[1] Set MSFT public symbol server SRV*http://msdl.microsoft.com/download/symbols in Windbg's .sympath
[2] Print out the heap data structures and compare with the project's definition; correct any inconsistency and rebuild the tool.
