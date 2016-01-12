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
