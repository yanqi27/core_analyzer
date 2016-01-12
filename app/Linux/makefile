
PLATFORM = Linux_x86_64
COMPILER = g++
LINKER   = $(COMPILER)

PLATFORM_OBJ = core_elf.o core_elf_linux_x86_64.o heap_ptmalloc.o

COMP_OPT = -g -O -c -m64 -I$(INC)

EXEC_LDFLAGS = -g -O -m64 -Wl,--no-undefined

include ../MakeCommon
