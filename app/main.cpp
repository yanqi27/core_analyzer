/************************************************************************
** FILE NAME..... Main.cpp
**
** (c) COPYRIGHT
**
** FUNCTION......... driver of the core viewer
**
** NOTES............
**
** ASSUMPTIONS......
**
** RESTRICTIONS.....
**
** LIMITATIONS......
**
** DEVIATIONS.......
**
** RETURN VALUES.... 0  - successful
**                   !0 - error
**
** AUTHOR(S)........ Michael Q Yan
**
************************************************************************/
#ifdef WIN32
#include <windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#endif

#include "cmd_impl.h"
#include "util.h"
#include "search.h"
#include "heap.h"
#include "stl_container.h"

// forward declaration
static int AskChoice(const char** options);
static CA_BOOL PrintBlockInfo(address_t addr);

// Global vars
const char* gpInputExecName = NULL;
CA_BOOL gbBatchMode = CA_FALSE;
CA_BOOL gbVerbose   = CA_FALSE;
CA_BOOL g_debug_core = CA_TRUE;

static void PrintBanner()
{
	printf("******************************************************************\n");
	printf("** Core Analyzer version %d.%d                                   **\n", CA_VERSION_MAJOR, CA_VERSION_MINOR);
	printf("** Please report bugs to: Michael Yan (myan@gmail.com)          **\n");
	printf("******************************************************************\n");
}

// The main menu
int main(int argc, char** argv)
{
	CA_BOOL need_exec_file = CA_TRUE;
	// validate input arguments
#if defined(_AIX) || defined(WIN32) || defined(__MACH__)
	need_exec_file = CA_FALSE;
	if (argc < 2)
	{
		printf("Usage: %s [-b] core_file\n", argv[0]);
		return 0;
	}
#else
	if (argc < 3)
	{
		printf("Usage: %s [-b] prog_name core_file\n", argv[0]);
		return 0;
	}
#endif

	int nextarg = 1;
	if (0 == strcmp(argv[nextarg], "-b"))
	{
		gbBatchMode = CA_TRUE;
		nextarg++;
	}

	const char* lpExecName = NULL;
	if (need_exec_file)
		lpExecName = argv[nextarg++];
	const char* lpCoreFile = argv[nextarg++];

	// Open and mmap exec/core files
	MmapFile lExecMmap(lpExecName);
	MmapFile lCoreMmap(lpCoreFile);
	if ((need_exec_file && !lExecMmap.InitSucceed()) || !lCoreMmap.InitSucceed())
	{
		// error message is issued by MmapFile class
		return -1;
	}
	gpInputExecName = lpExecName;

	// sanity check
	// The core file will initialize bit mode
	// exec file must have the same bit mode
	if (!VerifyCoreFile(lCoreMmap.GetStartAddr())
		|| (need_exec_file && !VerifyExecFile(lExecMmap.GetStartAddr())))
		return -1;

	if (!InitCoreAnalyzer(lExecMmap, lCoreMmap)
		|| !alloc_bit_vec()
		|| !init_heap() )
	{
		fprintf(stderr, "Fail to initialize core analyzer\n");
		return -1;
	}

	// Batch mode
	if (gbBatchMode)
	{
		PrintCoreInfo(lCoreMmap);
		heap_walk(0, CA_TRUE);
		return 0;
	}

	PrintBanner();

	// Menu items
	const char* choices[] = {
		/* 0 */ "Print General Core Information",
		/* 1 */ "Find References to an Object (horizontal search)",
		/* 2 */ "What Is This Address and Underlying Object Type (vertical search)",
		/* 3 */ "Objects Shared Between Threads",
		/* 4 */ "Memory Pattern Analysis",
		/* 5 */ "Query Heap Memory Block",
		/* 6 */ "Page Walk (check the integrity of surrounding memory blocks)",
		/* 7 */ "Heap Walk (check the whole heap for corruption and memory usage stats)",
		/* 8 */ "Biggest Heap Memory Blocks",
		/* 9 */ "Biggest Heap Memory Owners(variables)",
		/* 10 */ "Heap Memory Leak Candidates",
		/* 11 */ "Quit",
		/*    */ NULL
	};

	// CLI menu driven services
	while (1)
	{
		address_t start, end;
		address_t lpObjectVirtAddr, lObjectSize;

		int opt = AskChoice(choices);

		// Print general core info
		if (opt == 0)
		{
			if (!PrintCoreInfo(lCoreMmap))
			{
				//break;
			}
		}
		// Horizonal search of all direct first-level references for given object
		else if (opt == 1)
		{
			lpObjectVirtAddr = AskParam("Object start address", NULL, CA_TRUE);
			lObjectSize = AskParam("Object size(RETURN to search the address)", NULL, CA_TRUE);
			if (lObjectSize == 0)
				lObjectSize = 1;
			address_t val =  AskParam("Maximum indirection levels(1-32, RETURN for 1)", NULL, CA_TRUE);
			if (val == 0)
				val = 1;
			unsigned int nLevel = (unsigned int)val;
			printf("Searching all references(up to %d levels of indirection) to ",	nLevel);
			if (lObjectSize > 1)
				printf("object starting at "PRINT_FORMAT_POINTER" size %ld\n", lpObjectVirtAddr, lObjectSize);
			else
				printf("value "PRINT_FORMAT_POINTER"\n", lpObjectVirtAddr);

			if (lpObjectVirtAddr == 0)
			{
				printf("[Error] 0 is an invalid object address\n");
			}
			else if (!find_object_refs(lpObjectVirtAddr, lObjectSize, nLevel) )
			{
				printf("Couldn't find any reference to memory ["PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER")\n",
					lpObjectVirtAddr, lpObjectVirtAddr+lObjectSize);
				//break;
			}
		}
		// Vertical search, find at least one reference chain that leads a known-type variable to the given object
		else if (opt == 2)
		{
			lpObjectVirtAddr = AskParam("Address value", NULL, CA_TRUE);
			if (!find_object_type(lpObjectVirtAddr) )
			{
				printf("No object associated with 0x%lx is found\n", lpObjectVirtAddr);
				//break;
			}
		}
		else if (opt == 3)
		{
			struct CA_LIST* threads = ca_list_new();
			find_shared_objects_by_threads(threads);
			ca_list_delete(threads);
		}
		// Analyze the memory content within a given address range
		else if (opt == 4)
		{
			start = AskParam("Start address", NULL, CA_TRUE);
			end = AskParam("End address", NULL, CA_TRUE);
			if (start >= end)
				printf("Invalid input addresses!\n");
			print_memory_pattern(start, end);
		}
		// Heap memory block
		else if (opt == 5)
		{
			address_t lpBlockAddr = AskParam("Block address", NULL, CA_TRUE);
			if (!PrintBlockInfo(lpBlockAddr))
			{
				//break;
			}
		}
		// Page work
		else if (opt == 6)
		{
			address_t lpPoolAddr = AskParam("Address", NULL, CA_TRUE);
			if (!heap_walk(lpPoolAddr, CA_FALSE))
			{
				//break;
			}
		}
		// Heap walk
		else if (opt == 7)
		{
			if (!heap_walk(0, CA_FALSE))
			{
				//break;
			}
		}
		// Top-sized memory blocks
		else if (opt == 8)
		{
			unsigned int num = AskParam("Number of in-use top-sized heap memory blocks", NULL, CA_TRUE);
			if (!biggest_blocks(num))
			{
				//break;
			}
		}
		// Variables/owners that reference most heap memory
		else if (opt == 9)
		{
			unsigned int num = AskParam("Number of top users(variables) of heap memory", NULL, CA_TRUE);
			if (!biggest_heap_owners_generic(num, CA_FALSE))
			{
				//break;
			}
		}
		else if (opt == 10)
		{
			if (!display_heap_leak_candidates())
			{
				//break;
			}
		}
		else if (opt == 11)
			break;
	}

	// Core file is unmapped and closed here
	return 0;
}

static int AskChoice(const char** options)
{
	int rc, totalChoices = 0;

	printf("\nMain Menu:\n");
	for (totalChoices=0; options[totalChoices]; totalChoices++)
	{
		printf("[%d] %s\n", totalChoices, options[totalChoices]);
	}

	char linebuf[256];
	do
	{
		printf("Select [0-%d]: ", totalChoices-1);
		fgets(linebuf, 256, stdin);
		rc = atoi(linebuf);
	} while (!isdigit(linebuf[0]) || rc<0 || rc>=totalChoices);

	return rc;
}

static CA_BOOL PrintBlockInfo(address_t addr)
{
	struct heap_block block_info;
	if (get_heap_block_info(addr, &block_info))
	{
		printf("\t[Block] ");

		if (block_info.inuse)
			printf("In-use\n");
		else
			printf("Free\n");

		printf("\t[Start Addr] "PRINT_FORMAT_POINTER"\n", block_info.addr);
		printf("\t[Block Size] "PRINT_FORMAT_SIZE"\n", block_info.size);
		printf("\t[Offset] +"PRINT_FORMAT_POINTER"\n", addr - block_info.addr);
	}
	else
	{
		printf("[Error] Failed to query the memory block\n");
	}
	return CA_TRUE;
}
