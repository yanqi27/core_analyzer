/*
 * heap.cpp
 * 		Functions for heap memory
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "defs.h"
#include "heap.h"
#include "segment.h"
#include "search.h"


CoreAnalyzerHeapInterface* gCAHeap;

#define ENSURE_CA_HEAP()							\
	do {											\
		if (!CA_HEAP) {								\
			CA_PRINT("No heap manager is detedted or selected.\n");	\
			return false;							\
		}											\
	} while (0)

std::map<std::string, CoreAnalyzerHeapInterface*> gCoreAnalyzerHeaps;

static std::vector<void(*)()> gHeapRegistrationFuncs = {
	#ifdef WIN32
    register_mscrt_malloc,
	#else
    register_pt_malloc_2_27,
    register_pt_malloc_2_31,
    register_pt_malloc_2_35,
    register_tc_malloc,
    #endif
};

bool init_heap_managers() {
    gCoreAnalyzerHeaps.clear();
    gCAHeap = nullptr;

    for (auto f: gHeapRegistrationFuncs)
        f();

    if (gCAHeap) {
        CA_HEAP->init_heap();
        return true;
    }
	CA_PRINT("failed to parse heap data\n");
    return false;
}

void register_heap_manager(std::string name, CoreAnalyzerHeapInterface* heapIntf, bool detected) {
    gCoreAnalyzerHeaps[name] = heapIntf;
    if (detected) {
        /* TODO we need to resolve the scenario that multi heap managers are present */
        gCAHeap = heapIntf;
    }
}

std::string get_supported_heaps() {
	std::string lSupportedHeaps;
	bool first_entry = true;
	for (const auto &itr : gCoreAnalyzerHeaps) {
		if (!first_entry)
		{
			lSupportedHeaps += ", ";
		}
		if (itr.second == gCAHeap)
			lSupportedHeaps += "(current)";
		lSupportedHeaps += itr.first;
		first_entry = false;
	}
	return lSupportedHeaps;
}

// Used to search for variables that allocate/reach the most heap memory
struct heap_owner
{
	struct object_reference ref;
	size_t aggr_size;
	unsigned long aggr_count;
};

#define LINE_BUF_SZ 1024

// Forward declaration
static bool
mark_blocks_referenced_by_globals_locals(std::vector<struct reachable_block>&, unsigned int*);

static void
display_histogram(const char*, unsigned int,
				const size_t*, const unsigned long*, const size_t*);

static unsigned long
get_next_queued_index(unsigned int*, unsigned long, unsigned long);

static void add_owner(struct heap_owner*, unsigned int, struct heap_owner*);

static size_t
heap_aggregate_size(struct reachable_block*, std::vector<struct reachable_block>&,
    unsigned int*,	unsigned long*);

static bool
build_block_index_map(struct reachable_block*, std::vector<struct reachable_block>&);

// Global Vars
static struct MemHistogram g_mem_hist;

static struct inuse_block *g_inuse_blocks = NULL;
static unsigned long       g_num_inuse_blocks = 0;

char ca_help_msg[] = "Commands of core_analyzer " CA_VERSION_STRING "\n"
	"   ref <addr_exp>\n"
	"           Find a symbol/type associated with the input address directly or indirectly\n"
	"   ref [/thread or /t] <addr_exp> <size> [level]\n"
	"           Search all references to the object starting at input address\n"
	"           parameter [size] specifies the object size\n"
	"           optional parameter [level] limits the levels of indirect reference, which is one by default\n"
	"           option [/thread] limits search to thread contexts only\n"
	"   obj <expr>\n"
	"           Extended function of Windbg \"s -v <Range> <Object>\" command; Search for object and reference to C++ object of the same type as the input expression\n"
	"   obj [/stats or /s]\n"
	"           Display objects stats in turns of count and size\n"
	"   shrobj [tid0] [tid1] [...]\n"
	"           Find objects that currently referenced from multiple threads\n"
	"\n"
	"   heap [/verbose or /v] [/leak or /l]\n"
	"           Heap walk; report memory corruption if any, usage statistics, etc.\n"
	"           option [/v] turns on verbose mode which includes more detail like memory histogram\n"
	"           option [/leak] lists all heap memory blocks that are not reachable from any code; i.e. leak candidates\n"
	"   heap [/block or /b] [/cluster or /c] <addr_exp>\n"
	"           option [/block] displays information about the memory block containing the given address\n"
	"           option [/cluster] displays a cluster of memory blocks surrounding the given address\n"
	"   heap [/usage or /u] <var_exp>\n"
	"           option [/usage] calculates heap memory consumption by input variable or memory object\n"
	"   heap [/topblock or /tb] [/topuser or /tu] <num>\n"
	"           option [/topblock] lists biggest <num> heap memory blocks\n"
	"           option [/topuser] lists the top <num> local/global variables that consume the most heap memory\n"
	"   heap [/m]\n"
	"           Display heap manager information\n"
	//"   heap [/fragmentation or /f]\n"
	"\n"
	"   segment [addr_exp]\n"
	"           Print process' virtual address space in segments\n"
	"           optional parameter [addr] specifies the segment to display\n"
	"   pattern <start> <end>\n"
	"           Reveal the data pattern within the given range\n"
	"   decode /v [reg=<val>] [from=<addr>] [to=<addr>|end]\n"
	"           Disassemble current function with detail annotation of object context\n"
	"           option [/v] turns on verbose mode\n"
	"           option [reg=<val>] specifies initial register values at the first instruction to disassemble\n"
	"           option [from=<addr>] and [to=<addr>] specifies the instruction addresses to disassemble\n"
	"\n"
	"   dt <type|variable>\n"
	"           Display type (windbg style) that matches the input expression\n"
	"   dt [/size or /s] <size> [<size-max>]\n"
	"           List types that matches the size or a range of size\n"
	"   shrobj_level [n]   - Set/Show the indirection level of shared-object search\n"
	"   max_indirection_level [n] - Set/Show the maximum levels of indirection\n"
	"   set/assign <addr> <val>   - Set a pseudo value at address\n"
	"   unset/unassign <addr>     - Undo the pseudo value at address\n";

// Binary search if addr belongs to one of the blocks
static int
inuse_block_cmp(const void *key, const void *elmt)
{
	const struct inuse_block *a = (struct inuse_block *)key;
	const struct inuse_block *b = (struct inuse_block *)elmt;
	if (a->addr < b->addr) {
		return -1;
	} else if (a->addr >= b->addr + b->size) {
		return 1;
	} else {
		return 0;
	}
}

struct inuse_block *
find_inuse_block(address_t addr, struct inuse_block *blocks, unsigned long total_blocks)
{
	struct inuse_block key = {addr, 1};
	return (struct inuse_block *) bsearch(&key, blocks, total_blocks,
	    sizeof(*blocks), inuse_block_cmp);
}

static struct reachable_block *
find_reachable_block(address_t addr, std::vector<struct reachable_block>& blocks)
{
	struct reachable_block key(addr, 1);
	return (struct reachable_block *) bsearch(&key, &blocks[0], blocks.size(),
	    sizeof(blocks[0]), inuse_block_cmp);
}

/*
 * Parse user options and invoke corresponding heap-related functions
 */
bool
heap_command_impl(char* args)
{
	ENSURE_CA_HEAP();

	bool rc = true;

	address_t addr = 0;
	bool verbose = false;
	bool check_leak = false;
	bool calc_usage = false;
	bool block_info = false;
	bool cluster_blocks = false;
	bool top_block = false;
	bool top_user = false;
	bool exlusive_opt = false;
	bool all_reachable_blocks = false;	// experimental option
	char* expr = NULL;

#define check_exclusive_option()	\
	if (exlusive_opt) {				\
		CA_PRINT("Option [%s] conflicts with one of the previous options\n", option);	\
		return false;				\
	} else {						\
		exlusive_opt = true;		\
	}

	// Parse user input options
	// argument is either an address or /v or /leak
	if (args) {
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		int i;

		for (i = 0; i < num_options; i++) {
			char* option = options[i];
			if (*option == '/')	{
				if (strcmp(option, "/m") == 0) {
					check_exclusive_option();
					CA_PRINT("Target allocator: %s\n", CA_HEAP->heap_version());
					return true;
				} else if (strcmp(option, "/leak") == 0 || strcmp(option, "/l") == 0) {
					check_leak = true;
					check_exclusive_option();
				} else if (strcmp(option, "/verbose") == 0 || strcmp(option, "/v") == 0) {
					verbose = true;
				} else if (strcmp(option, "/block") == 0 || strcmp(option, "/b") == 0) {
					block_info = true;
					check_exclusive_option();
				} else if (strcmp(option, "/cluster") == 0 || strcmp(option, "/c") == 0) {
					cluster_blocks = true;
					check_exclusive_option();
				} else if (strcmp(option, "/usage") == 0 || strcmp(option, "/u") == 0) {
					calc_usage = true;
					check_exclusive_option();
				} else if (strcmp(option, "/topblock") == 0 || strcmp(option, "/tb") == 0) {
					top_block = true;
					check_exclusive_option();
				} else if (strcmp(option, "/topuser") == 0 || strcmp(option, "/tu") == 0) {
					top_user = true;
					check_exclusive_option();
				} else if (strcmp(option, "/all") == 0 || strcmp(option, "/a") == 0) {
					all_reachable_blocks = true;
				} else {
					CA_PRINT("Invalid option: [%s]\n", option);
					return false;
				}
			} else if (calc_usage) {
				expr = option;
				break;
			} else if (addr == 0) {
				addr = ca_eval_address (option);
			} else {
				CA_PRINT("Invalid option: [%s]\n", option);
				return false;
			}
		}
	}

	if (check_leak) {
		if (addr)
			CA_PRINT("Unexpected address expression\n");
		else
			display_heap_leak_candidates();
	} else if (block_info) {
		if (!addr)
			CA_PRINT("Heap block address is expected\n");
		else {
			struct heap_block heap_block;
			if (CA_HEAP->get_heap_block_info(addr, &heap_block)) {
				if (heap_block.inuse)
					CA_PRINT("\t[In-use]\n");
				else
					CA_PRINT("\t[Free]\n");
				CA_PRINT("\t[Address] " PRINT_FORMAT_POINTER "\n", heap_block.addr);
				CA_PRINT("\t[Size]    " PRINT_FORMAT_SIZE "\n", heap_block.size);
				CA_PRINT("\t[Offset]  " PRINT_FORMAT_SIZE "\n", addr - heap_block.addr);
			} else {
				CA_PRINT("[Error] Failed to query the memory block\n");
			}
		}
	}
	else if (cluster_blocks) {
		if (addr) {
			if (!CA_HEAP->heap_walk(addr, verbose))
				CA_PRINT("[Error] Failed to walk heap\n");
		} else {
			CA_PRINT("Heap block address is expected\n");
		}
	} else if (calc_usage) {
		if (expr)
			calc_heap_usage(expr);
		else
			CA_PRINT("An expression of heap memory owner is expected\n");
	} else if (top_block || top_user) {
		unsigned int n = (unsigned int)addr;
		if (n == 0)
			CA_PRINT("A number is expected\n");
		else if (top_user)
			biggest_heap_owners_generic(n, all_reachable_blocks);
		else
			biggest_blocks(n);
	} else {
		if (addr)
			CA_PRINT("Unexpected address expression\n");
		else if (!CA_HEAP->heap_walk(addr, verbose))
			CA_PRINT("[Error] Failed to walk heap\n");
	}
	if (expr)
		free(expr);
	return rc;
}

/*
 * Parse user options and invoke corresponding search functions
 */
bool ref_command_impl(char* args)
{
	ENSURE_CA_HEAP();

	int rc;
	bool threadref = false;
	address_t addr = 0;
	size_t size  = 0;
	size_t level = 0;

	// Parse user input options
	// argument is in the form of <addr> [size] [level]
	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		int i;
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];
			if (strcmp(option, "/thread") == 0 || strcmp(option, "/t") == 0)
				threadref = true;
			else if (addr == 0)
			{
				addr = ca_eval_address (option);
				if (addr == 0)
				{
					CA_PRINT("Invalid address [%s] argument\n", option);
					return false;
				}
			}
			else if (size == 0)
			{
				size = ca_eval_address (option);
				if (size == 0)
				{
					CA_PRINT("Invalid size [%s] argument\n", option);
					return false;
				}
			}
			else if (level == 0)
			{
				level = ca_eval_address (option);
				if (level == 0)
				{
					CA_PRINT("Invalid level [%s] argument\n", option);
					return false;
				}
			}
			else
			{
				CA_PRINT("Too many arguments: %s\n", option);
				return false;
			}
		}
	}

	if (addr == 0)
	{
		CA_PRINT("Missing object address.");
		return false;
	}

	if (threadref)
	{
		if (size == 0)
			size = 1;
		if (level == 0)
			level = 1;
		CA_PRINT("Search for thread references to " PRINT_FORMAT_POINTER " size " PRINT_FORMAT_SIZE " up to " PRINT_FORMAT_SIZE " levels of indirection\n",
					addr, size, level);
		rc = find_object_refs_on_threads(addr, size, level);
	}
	else
	{
		if (size == 0)
		{
			CA_PRINT("Search for object type associated with " PRINT_FORMAT_POINTER "\n", addr);
			rc = find_object_type(addr);
		}
		else
		{
			if (level == 0)
				level = 1;
			CA_PRINT("Search for references to " PRINT_FORMAT_POINTER " size " PRINT_FORMAT_SIZE " up to " PRINT_FORMAT_SIZE " levels of indirection\n",
						addr, size, level);
			rc = find_object_refs(addr, size, level);
		}
	}
	if (!rc)
		CA_PRINT("No result found\n");

	return true;
}

/*
 * Parse user options and invoke corresponding segment functions
 */
static void
print_segment(struct ca_segment* segment)
{
	CA_PRINT("[" PRINT_FORMAT_POINTER " - " PRINT_FORMAT_POINTER "] %6ldK  %c%c%c ",
		segment->m_vaddr, segment->m_vaddr+segment->m_vsize,
		segment->m_vsize/1024,
		segment->m_read?'r':'-', segment->m_write?'w':'-', segment->m_exec?'x':'-');

	//if (g_debug_core && segment->m_fsize != segment->m_vsize)
	//	CA_PRINT(" (fsize=%ldK)", segment->m_fsize/1024);

	if (segment->m_type == ENUM_MODULE_TEXT)
		CA_PRINT("[.text/.rodata] [%s]", segment->m_module_name);
	else if (segment->m_type == ENUM_MODULE_DATA)
		CA_PRINT("[.data/.bss] [%s]", segment->m_module_name);
	else if (segment->m_type == ENUM_STACK)
	{
		CA_PRINT("[stack] [tid=%d]", segment->m_thread.tid);
		if (segment->m_thread.lwp)
			CA_PRINT(" [lwp=%ld]", segment->m_thread.lwp);
	}
	else if (segment->m_type == ENUM_HEAP)
		CA_PRINT("[heap]");
	CA_PRINT("\n");
}

bool segment_command_impl(char* args)
{
	struct ca_segment* segment;

	if (args)
	{
		address_t addr = ca_eval_address (args);
		segment = get_segment(addr, 0);
		if (segment)
		{
			CA_PRINT("Address %s belongs to segment:\n", args);
			print_segment(segment);
		}
		else
			CA_PRINT("Address %s doesn't belong to any segment\n", args);
	}
	else
	{
		unsigned int i;
		CA_PRINT("vaddr                         size      perm     name\n");
		CA_PRINT("=====================================================\n");
		for (i=0; i<g_segment_count; i++)
		{
			CA_PRINT("[%4d] ", i);
			print_segment(&g_segments[i]);
		}
		// Find out why SIZE is much bigger than RSS, it might be modules, thread stack or heap, or all
		/*if (!g_debug_core)
		{
			size_t heap_gap = 0, stack_gap = 0, module_gap = 0;	// account for gap between RSS and SIZE
			int pid = ptid_get_pid (inferior_ptid);
			char fname[128];
			FILE* fp;

			snprintf(fname, 128, "/proc/%d/smaps", pid);
			if ((fp = fopen (fname, "r")) != NULL)
			{
				int ret;
				// Now iterate until end-of-file.
				do
				{
					int k;
					address_t addr, endaddr, offset, inode;
					char permissions[8], device[8], filename[128];
					size_t vsize, rss, dumb;

					ret = fscanf (fp, "%lx-%lx %s %lx %s %lx",
							    &addr, &endaddr, permissions, &offset, device, &inode);
					if (ret <= 0 || ret == EOF)
						break;
					filename[0] = '\0';
					if (ret > 0 && ret != EOF)
						ret += fscanf (fp, "%[^\n]\n", filename);
					ret = fscanf (fp, "Size: %ld kB\n", &vsize);
					ret = fscanf (fp, "Rss: %ld kB\n", &rss);
					for (k = 0; k < 11; k++)
						fgets(filename, 128, fp);	// Pss, etc.
					//CA_PRINT("Segment: 0x%lx SIZE=%ld RSS=%ld\n", addr, vsize, rss);
					if (vsize > rss)
					{
						struct ca_segment* segment = get_segment(addr, 1);
						size_t gap = (vsize - rss) * 1024;
						if (segment)
						{
							if (segment->m_type == ENUM_STACK)
								stack_gap += gap;
							else if (segment->m_type == ENUM_MODULE_TEXT || segment->m_type == ENUM_MODULE_DATA)
								module_gap += gap;
							else if (segment->m_type == ENUM_HEAP)
								heap_gap += gap;
						}
					}
				} while(1);
				fclose(fp);

				CA_PRINT("Gap between SIZE and RSS:\n");
				CA_PRINT("\tmodules: ");
				print_size(module_gap);
				CA_PRINT("\n");
				CA_PRINT("\tthreads: ");
				print_size(stack_gap);
				CA_PRINT("\n");
				CA_PRINT("\theap: ");
				print_size(heap_gap);
				CA_PRINT("\n");
			}
		}*/
	}
	return true;
}

/*
 * Parse user options and invoke corresponding pattern function
 */
bool pattern_command_impl(char* args)
{
	ENSURE_CA_HEAP();

	address_t lo = 0, hi = 0;
	// Parse user input options
	// argument is in the form of <start> <end>
	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		if (num_options != 2)
		{
			CA_PRINT("Expect arguments: <start> <end>\n");
			return false;
		}
		lo = ca_eval_address (options[0]);
		hi = ca_eval_address (options[1]);
		if (hi <= lo)
		{
			CA_PRINT("Invalid memory address range (start >= end)\n");
			return false;
		}
	}
	else
	{
		CA_PRINT("Missing object address.");
		return false;
	}

	print_memory_pattern(lo, hi);

	return true;
}

/*
 * Return an array of struct inuse_block, of all in-use blocks
 * 	the array is cached for repeated usage unless a live process has changed
 */
struct inuse_block *
build_inuse_heap_blocks(unsigned long* opCount)
{
	struct inuse_block* blocks = NULL;
	unsigned long total_inuse = 0;

	if (g_inuse_blocks && g_num_inuse_blocks)
	{
		if (g_debug_core)
		{
			*opCount = g_num_inuse_blocks;
			return g_inuse_blocks;
		}
		else
		{
			// FIXME
			// Even for a live process, return here if it hasn't change since last time
			free(g_inuse_blocks);
			g_inuse_blocks = NULL;
			g_num_inuse_blocks = 0;
		}
	}

	*opCount = 0;
	// 1st walk counts the number of in-use blocks
	if (CA_HEAP->walk_inuse_blocks(NULL, &total_inuse) && total_inuse)
	{
		// allocate memory for inuse_block array
		blocks = (struct inuse_block*) calloc(total_inuse, sizeof(struct inuse_block));
		if (!blocks)
		{
			CA_PRINT("Failed: Out of Memory\n");
			return NULL;
		}
		// 2nd walk populate the array for in-use block info
		if (!CA_HEAP->walk_inuse_blocks(blocks, opCount) || *opCount != total_inuse)
		{
			CA_PRINT("Unexpected error while walking in-use blocks\n");
			*opCount = 0;
			free (blocks);
			return NULL;
		}
		// sanity check whether the array is sorted by address, as required.
		if (total_inuse >= 2)
		{
			unsigned long count;
			struct inuse_block* cursor;
			for (count = 0, cursor = blocks; count < total_inuse - 1; count++, cursor++)
			{
				if (cursor->addr + cursor->size > (cursor+1)->addr)
				{
					CA_PRINT("Internal error: in-use array is not properly sorted at %ld\n", count);
					CA_PRINT("\t[%ld] " PRINT_FORMAT_POINTER " size=%ld\n", count, cursor->addr, cursor->size);
					CA_PRINT("\t[%ld] " PRINT_FORMAT_POINTER "\n", count+1, (cursor+1)->addr);
					free (blocks);
					*opCount = 0;
					return NULL;
				}
			}
		}
	}
	// cache the data
	g_inuse_blocks = blocks;
	g_num_inuse_blocks = total_inuse;

	return blocks;
}

static bool
build_reachable_blocks(std::vector<struct reachable_block>& orBlocks)
{
	struct inuse_block *inuse_blocks;
	unsigned long index;
	unsigned long count;

	inuse_blocks = build_inuse_heap_blocks(&count);
	if (!inuse_blocks || count == 0) {
		CA_PRINT("Failed: no in-use heap block is found\n");
		return false;
	}

	orBlocks.reserve(count);
	for (index = 0; index < count; index++)
		orBlocks.push_back(inuse_blocks[index]);

	return true;
}

/*
 * Bitmap for in-use blocks is used
 *   Each block uses two bits(queued/visited)
 * 	 one "int" may contain bits for 16 blocks
 */
#define QUEUED   0x01u
#define VISITED  0x02u

/*static inline void set_visited(unsigned int* bitmap, unsigned long index)
{
	unsigned long bit = (index & 0xf) << 1;
	bitmap[index >> 4] |= (VISITED << bit);
}

static inline unsigned int is_queued_or_visited(unsigned int* bitmap, unsigned long index)
{
	unsigned long bit = (index & 0xf) << 1;
	return (bitmap[index >> 4] & ((QUEUED | VISITED) << bit));
}

static inline void reset_queued(unsigned int* bitmap, unsigned long index)
{
	unsigned long bit = (index & 0xf) << 1;
	bitmap[index >> 4] &= ~(QUEUED << bit);
}

static inline void set_queued(unsigned int* bitmap, unsigned long index)
{
	unsigned long bit = (index & 0xf) << 1;
	bitmap[index >> 4] |= (QUEUED << bit);
}

static inline unsigned int is_queued(unsigned int* bitmap, unsigned long index)
{
	unsigned long bit = (index & 0xf) << 1;
	return (bitmap[index >> 4] & (QUEUED << bit));
}*/
#define set_visited(bitmap,index)  bitmap[(index) >> 4] |= (VISITED << (((index) & 0xf) << 1))
#define is_queued_or_visited(bitmap,index)   (bitmap[(index) >> 4] & ((QUEUED | VISITED) << (((index) & 0xf) << 1)))
#define reset_queued(bitmap,index) bitmap[(index) >> 4] &= ~(QUEUED << (((index) & 0xf) << 1))
#define set_queued(bitmap,index)   bitmap[(index) >> 4] |= (QUEUED << (((index) & 0xf) << 1))
#define is_queued(bitmap,index)    (bitmap[(index) >> 4] & (QUEUED << (((index) & 0xf) << 1)))
#define is_visited(bitmap,index)   (bitmap[(index) >> 4] & (VISITED << (((index) & 0xf) << 1)))
#define set_queued_and_visited(bitmap,index)   bitmap[(index) >> 4] |= ((QUEUED | VISITED) << (((index) & 0xf) << 1))

static const size_t GB = 1024*1024*1024;
static const size_t MB = 1024*1024;
static const size_t KB = 1024;

// A utility function
void print_size(size_t sz)
{
	if (sz > GB)
		CA_PRINT("%.1fGB", (double)sz/(double)GB);
	else if (sz > MB)
		CA_PRINT(PRINT_FORMAT_SIZE"MB", sz/MB);
	else if (sz > KB)
		CA_PRINT(PRINT_FORMAT_SIZE"KB", sz/KB);
	else
		CA_PRINT(PRINT_FORMAT_SIZE, sz);
}

static void fprint_size(char* buf, size_t sz)
{
	if (sz > GB)
		sprintf(buf, "%.1fGB", (double)sz/(double)GB);
	else if (sz > MB)
		sprintf(buf, PRINT_FORMAT_SIZE"MB", sz/MB);
	else if (sz > KB)
		sprintf(buf, PRINT_FORMAT_SIZE"KB", sz/KB);
	else
		sprintf(buf, PRINT_FORMAT_SIZE, sz);
}

// Find the top n memory blocks in term of size
bool biggest_blocks(unsigned int num)
{
	bool rc = true;
	struct heap_block* blocks;

	if (num == 0)
		return true;
	else if (num > 1024 * 1024)
	{
		CA_PRINT("The number %d is too big, I am not sure I can do it\n", num);
		return false;
	}

	blocks = (struct heap_block*) calloc (num, sizeof(struct heap_block));
	if (!blocks)
		return false;

	if (CA_HEAP->get_biggest_blocks (blocks, num))
	{
		unsigned int i;
		// display big blocks
		CA_PRINT("Top %d biggest in-use heap memory blocks:\n", num);
		for (i=0; i<num; i++)
		{
			CA_PRINT("\taddr=" PRINT_FORMAT_POINTER "  size=" PRINT_FORMAT_SIZE " (",
					blocks[i].addr, blocks[i].size);
			print_size (blocks[i].size);
			CA_PRINT(")\n");
		}
	}
	else
		rc = false;

	// cleanup
	free (blocks);

	return rc;
}

/*
 * Find/display global/local variables which own the most heap memory in bytes
 */
bool biggest_heap_owners_generic(unsigned int num, bool all_reachable_blocks)
{
	bool rc = false;
	unsigned int i;
	int nregs = 0;
	struct reg_value *regs_buf = NULL;
	size_t ptr_sz = g_ptr_bit >> 3;
	struct heap_owner *owners;
	struct heap_owner *smallest;

	struct ca_segment *segment;
	size_t total_bytes = 0;
	size_t processed_bytes = 0;

	std::vector<struct reachable_block> blocks;
	unsigned long num_blocks;
	unsigned long inuse_index;

	struct reachable_block *blk;
	struct object_reference ref;
	size_t aggr_size;
	unsigned long aggr_count;
	address_t start, end, cursor;

	// Allocate an array for the biggest num of owners
	if (num == 0)
		return false;
	owners = (struct heap_owner *) calloc(num, sizeof(struct heap_owner));
	if (!owners)
		goto clean_out;
	smallest = &owners[num - 1];

	// First, create and populate an array of all in-use blocks
	if (!build_reachable_blocks(blocks)) {
		CA_PRINT("Failed: no in-use heap block is found\n");
		goto clean_out;
	}
	num_blocks = blocks.size();

	// estimate the work to enable progress bar
	for (i=0; i<g_segment_count; i++)
	{
		segment = &g_segments[i];
		if (segment->m_type == ENUM_STACK || segment->m_type == ENUM_MODULE_DATA)
			total_bytes += segment->m_fsize;
	}
	init_progress_bar(total_bytes);

	// Walk through all segments of threads' registers/stacks or globals
	for (i=0; i<g_segment_count; i++)
	{
		// bail out if user is impatient for the long searching
		if (user_request_break())
		{
			CA_PRINT("Abort searching biggest heap memory owners\n");
			goto clean_out;
		}

		// Only thread stack and global .data sections are considered
		segment = &g_segments[i];
		if (segment->m_type == ENUM_STACK || segment->m_type == ENUM_MODULE_DATA)
		{
			int tid = 0;
			// check registers if it is a thread's stack segment
			if (segment->m_type == ENUM_STACK)
			{
				tid = get_thread_id (segment);
				// allocate register value buffer for once
				if (!nregs && !regs_buf)
				{
					nregs = read_registers (NULL, NULL, 0);
					if (nregs)
						regs_buf = (struct reg_value*) malloc(nregs * sizeof(struct reg_value));
				}
				// check each register for heap reference
				if (nregs && regs_buf)
				{
					int k;
					int nread = read_registers (segment, regs_buf, nregs);
					for (k = 0; k < nread; k++)
					{
						if (regs_buf[k].reg_width == ptr_sz)
						{
							blk = find_reachable_block(regs_buf[k].value, blocks);
							if (blk)
							{
								ref.storage_type = ENUM_REGISTER;
								ref.vaddr = 0;
								ref.value = blk->addr;
								ref.where.reg.tid = tid;
								ref.where.reg.reg_num = k;
								ref.where.reg.name = NULL;
								calc_aggregate_size(&ref, ptr_sz, all_reachable_blocks, blocks, &aggr_size, &aggr_count);
								if (aggr_size > smallest->aggr_size)
								{
									struct heap_owner newowner;
									newowner.ref = ref;
									newowner.aggr_size = aggr_size;
									newowner.aggr_count = aggr_count;
									add_owner(owners, num, &newowner);
								}
							}
						}
					}
				}
			}

			// Calculate the memory region to search
			if (segment->m_type == ENUM_STACK)
			{
				start = get_rsp(segment);
				if (start < segment->m_vaddr || start >= segment->m_vaddr + segment->m_vsize)
					start = segment->m_vaddr;
				if (start - segment->m_vaddr >= segment->m_fsize)
					end = start;
				else
					end = segment->m_vaddr + segment->m_fsize;
			}
			else if (segment->m_type == ENUM_MODULE_DATA)
			{
				start = segment->m_vaddr;
				end = segment->m_vaddr + segment->m_fsize;
			}
			else
				continue;

			// Evaluate each variable or raw pointer in the target memory region
			cursor = ALIGN(start, ptr_sz);
			while (cursor < end)
			{
				size_t val_len = ptr_sz;
				address_t sym_addr;
				size_t    sym_sz;
				bool known_sym = false;

				// If the address belongs to a known variable, include all its subfields
				// FIXME
				// consider subfields that are of pointer-like types, however, it will miss
				// references in an unstructured buffer
				ref.storage_type = segment->m_type;
				ref.vaddr = cursor;
				if (segment->m_type == ENUM_STACK)
				{
					ref.where.stack.tid = tid;
					ref.where.stack.frame = get_frame_number(segment, cursor, &ref.where.stack.offset);
					if (known_stack_sym(&ref, &sym_addr, &sym_sz) && sym_sz)
						known_sym = true;
				}
				else if (segment->m_type == ENUM_MODULE_DATA)
				{
					ref.where.module.base = segment->m_vaddr;
					ref.where.module.size = segment->m_vsize;
					ref.where.module.name = segment->m_module_name;
					if (known_global_sym(&ref, &sym_addr, &sym_sz) && sym_sz)
						known_sym = true;
				}
				if (known_sym)
				{
					if (cursor != sym_addr)
						ref.vaddr = cursor = sym_addr;	// we should never come to here!
					val_len = sym_sz;
				}

				// Query heap for aggregated memory size/count originated from the candidate variable
				if (val_len >= ptr_sz)
				{
					calc_aggregate_size(&ref, val_len, all_reachable_blocks, blocks, &aggr_size, &aggr_count);
					// update the top list if applies
					if (aggr_size >= smallest->aggr_size)
					{
						struct heap_owner newowner;
						if (val_len == ptr_sz)
							read_memory_wrapper(NULL, ref.vaddr, (void*)&ref.value, ptr_sz);
						else
							ref.value = 0;
						newowner.ref = ref;
						newowner.aggr_size = aggr_size;
						newowner.aggr_count = aggr_count;
						add_owner(owners, num, &newowner);
					}
				}
				cursor = ALIGN(cursor + val_len, ptr_sz);
			}
			processed_bytes += segment->m_fsize;
			set_current_progress(processed_bytes);
		}
	}
	end_progress_bar();

	if (!all_reachable_blocks)
	{
		// Big memory blocks may be referenced indirectly by local/global variables
		// check all in-use blocks
		for (inuse_index = 0; inuse_index < num_blocks; inuse_index++)
		{
			blk = &blocks[inuse_index];
			ref.storage_type = ENUM_HEAP;
			ref.vaddr = blk->addr;
			ref.where.heap.addr = blk->addr;
			ref.where.heap.size = blk->size;
			ref.where.heap.inuse = 1;
			calc_aggregate_size(&ref, ptr_sz, false, blocks, &aggr_size, &aggr_count);
			// update the top list if applies
			if (aggr_size >= smallest->aggr_size)
			{
				struct heap_owner newowner;
				ref.value = 0;
				newowner.ref = ref;
				newowner.aggr_size = aggr_size;
				newowner.aggr_count = aggr_count;
				add_owner(owners, num, &newowner);
			}
		}
	}

	// Print the result
	for (i = 0; i < num; i++)
	{
		struct heap_owner *owner = &owners[i];
		if (owner->aggr_size)
		{
			CA_PRINT("[%d] ", i+1);
			print_ref(&owner->ref, 0, false, false);
			CA_PRINT("    |--> ");
			print_size(owner->aggr_size);
			CA_PRINT(" (%ld blocks)\n", owner->aggr_count);
		}
	}
	rc = true;

clean_out:
	// clean up
	if (regs_buf)
		free (regs_buf);
	if (owners)
		free (owners);

	return rc;
}

/*
 * Given a reference, a variable or a pointer to a heap block, with known size,
 * 	Return its aggregated reachable in-use blocks
 */
bool
calc_aggregate_size(const struct object_reference *ref,
					size_t var_len,
					bool all_reachable_blocks,
					std::vector<struct reachable_block>& inuse_blocks,
					size_t *total_size,
					unsigned long *total_count)
{
	address_t addr, cursor, end;
	size_t ptr_sz = g_ptr_bit >> 3;
	size_t aggr_size = 0;
	unsigned long aggr_count = 0;
	struct reachable_block *blk;
	size_t bitmap_sz = ((inuse_blocks.size() + 15) * 2 / 32) * sizeof(unsigned int);

	static unsigned int* qv_bitmap = NULL;	// Bit flags of whether a block is queued/visited
	static unsigned long bitmap_capacity = 0;	// in terms of number of blocks handled

	// ground return values
	*total_size = 0;
	*total_count = 0;

	// Prepare bitmap with the clean state
	if (bitmap_capacity < inuse_blocks.size())
	{
		if (qv_bitmap)
			free (qv_bitmap);
		// Each block uses two bits(queued/visited)
		qv_bitmap = (unsigned int*) malloc(bitmap_sz);
		if (!qv_bitmap)
		{
			bitmap_capacity = 0;
			CA_PRINT("Out of Memory\n");
			return false;
		}
		bitmap_capacity = inuse_blocks.size();
	}
	memset(qv_bitmap, 0, bitmap_sz);

	// Input is a pointer to an in-use memory block
	if (ref->storage_type == ENUM_REGISTER || ref->storage_type == ENUM_HEAP)
	{
		if (var_len != ptr_sz)
			return false;
		blk = find_reachable_block(ref->vaddr, inuse_blocks);
		if (blk)
		{
			// cached result is available, return now
			if (all_reachable_blocks && blk->reachable.aggr_size)
			{
				*total_size  = blk->reachable.aggr_size;
				*total_count = blk->reachable.aggr_count;
				return true;
			}
			else
			{
				// search starts with the memory block
				cursor = blk->addr;
				end  = cursor + blk->size;
				aggr_size  = blk->size;
				aggr_count = 1;
				set_visited(qv_bitmap, blk - &inuse_blocks[0]);
			}
		}
		else
			return false;
	}
	// input reference is an object with given size, e.g. a local/global variable
	else
	{
		if (all_reachable_blocks && var_len == ptr_sz)
		{
			// input is of pointer size, which is candidate for cache value
			if(read_memory_wrapper(NULL, ref->vaddr, (void*)&addr, ptr_sz))
			{
				blk = find_reachable_block(addr, inuse_blocks);
				if (blk)
				{
					if (blk->reachable.aggr_size)
					{
						*total_size  = blk->reachable.aggr_size;
						*total_count = blk->reachable.aggr_count;
						return true;
					}
				}
				else
					return false;
			}
			else
				return false;
		}
		cursor = ref->vaddr;
		end  = cursor + var_len;
	}

	// We now have a range of memory to search
	cursor = ALIGN(cursor, ptr_sz);
	while (cursor < end)
	{
		if(!read_memory_wrapper(NULL, cursor, (void*)&addr, ptr_sz))
			break;
		blk = find_reachable_block(addr, inuse_blocks);
		if (blk && !is_queued_or_visited(qv_bitmap, blk - &inuse_blocks[0]))
		{
			if (all_reachable_blocks)
			{
				unsigned long sub_count = 0;
				aggr_size += heap_aggregate_size(blk, inuse_blocks, qv_bitmap, &sub_count);
				aggr_count += sub_count;
			}
			else
			{
				aggr_size += blk->size;
				aggr_count++;
				set_visited(qv_bitmap, blk - &inuse_blocks[0]);
			}
		}
		cursor += ptr_sz;
	}

	// can we cache the result?
	if (all_reachable_blocks && aggr_size)
	{
		if (ref->storage_type == ENUM_REGISTER || ref->storage_type == ENUM_HEAP)
		{
			blk = find_reachable_block(ref->vaddr, inuse_blocks);
			blk->reachable.aggr_size = aggr_size;
			blk->reachable.aggr_count = aggr_count;
		}
		else if (var_len == ptr_sz)
		{
			if (read_memory_wrapper(NULL, ref->vaddr, (void*)&addr, ptr_sz))
			{
				blk = find_reachable_block(addr, inuse_blocks);
				if (blk)
				{
					blk->reachable.aggr_size = aggr_size;
					blk->reachable.aggr_count = aggr_count;
				}
			}
		}
	}

	// return happily
	*total_size  = aggr_size;
	*total_count = aggr_count;
	return true;
}

// A not-so-fast leak checking based on the concept what a heap block without any
// reference directly or indirectly from a global or local variable is a lost one
bool display_heap_leak_candidates(void)
{
	bool rc = true;
	unsigned long total_blocks = 0;
	std::vector<struct reachable_block> blocks;
	struct reachable_block* blk;
	unsigned int* qv_bitmap = NULL;	// Bit flags of whether a block is queued/visited
	unsigned long cur_index;
	size_t total_leak_bytes;
	size_t total_bytes;
	unsigned long leak_count;

	// create and populate an array of all in-use blocks
	if (!build_reachable_blocks(blocks)) {
		CA_PRINT("Failed: no in-use heap block is found\n");
		return false;
	}
	total_blocks = blocks.size();

	// Prepare bitmap with the clean state
	// Each block uses two bits(queued/visited)
	qv_bitmap = (unsigned int*) calloc((total_blocks+15)*2/32, sizeof(unsigned int));
	if (!qv_bitmap)
	{
		CA_PRINT("Out of Memory\n");
		rc = false;
		goto leak_check_out;
	}

	// search global/local(module's .text/.data/.bss and thread stack) memory
	// for all references to these in-use blocks, mark them queued and visited
	if (!mark_blocks_referenced_by_globals_locals(blocks, qv_bitmap))
	{
		rc = false;
		goto leak_check_out;
	}

	// Within in-use blocks,
	// repeatedly use queued blocks to find unvisited ones through reference
	// mark newly found blocks queued and visited
	// until no queued blocks any more to work with
	cur_index = 0;
	do
	{
		cur_index = get_next_queued_index(qv_bitmap, total_blocks, cur_index);
		if (cur_index < total_blocks)
		{
			unsigned int* indexp;
			blk = &blocks[cur_index];
			if (!blk->reachable.index_map)
			{
				if (!build_block_index_map(blk, blocks))
				{
					rc = false;
					goto leak_check_out;
				}
			}
			// We have index map to work with by now
			indexp = blk->reachable.index_map;
			while (*indexp != UINT_MAX)
			{
				unsigned int index = *indexp;
				if (!is_queued_or_visited(qv_bitmap, index))
				{
					set_queued_and_visited(qv_bitmap, index);
				}
				indexp++;
			}
			// done with this block
			reset_queued(qv_bitmap, cur_index);
		}
		else
			break;
	} while (1);

	// Display blocks that found no references to them directly or indirectly from global/local areas
	CA_PRINT("Potentially leaked heap memory blocks:\n");
	total_leak_bytes = 0;
	total_bytes = 0;
	leak_count = 0;
	for (cur_index = 0, blk = &blocks[0]; cur_index < total_blocks; cur_index++, blk++)
	{
		total_bytes += blk->size;
		if (!is_visited(qv_bitmap, cur_index))
		{
			leak_count++;
			CA_PRINT("[%ld] addr=" PRINT_FORMAT_POINTER " size=" PRINT_FORMAT_SIZE "\n",
					leak_count, blk->addr, blk->size);
			total_leak_bytes += blk->size;
		}
	}
	if (leak_count)
	{
		CA_PRINT("Total %ld (", leak_count);
		print_size(total_leak_bytes);
		CA_PRINT(") leak candidates out of %ld (", total_blocks);
		print_size(total_bytes);
		CA_PRINT(") in-use memory blocks\n");
	}
	else
		CA_PRINT("All %ld heap blocks are referenced, no leak candidate\n", total_blocks);

leak_check_out:
	if (qv_bitmap)
		free (qv_bitmap);
	return rc;
}

/*
 * Histogram functions
 */
void display_mem_histogram(const char* prefix)
{
	if (!g_mem_hist.num_buckets || !g_mem_hist.bucket_sizes
		|| !g_mem_hist.inuse_cnt || !g_mem_hist.inuse_bytes
		|| !g_mem_hist.free_cnt || !g_mem_hist.free_bytes)
		return;

	CA_PRINT("%s========== In-use Memory Histogram ==========\n", prefix);
	display_histogram(prefix, g_mem_hist.num_buckets, g_mem_hist.bucket_sizes, g_mem_hist.inuse_cnt, g_mem_hist.inuse_bytes);

	CA_PRINT("%s========== Free Memory Histogram ==========\n", prefix);
	display_histogram(prefix, g_mem_hist.num_buckets, g_mem_hist.bucket_sizes, g_mem_hist.free_cnt, g_mem_hist.free_bytes);
}

void release_mem_histogram(void)
{
	if (g_mem_hist.bucket_sizes)
		free(g_mem_hist.bucket_sizes);
	if (g_mem_hist.inuse_cnt)
		free(g_mem_hist.inuse_cnt);
	if (g_mem_hist.inuse_bytes)
		free(g_mem_hist.inuse_bytes);
	if (g_mem_hist.free_cnt)
		free(g_mem_hist.free_cnt);
	if (g_mem_hist.free_bytes)
		free(g_mem_hist.free_bytes);
	memset(&g_mem_hist, 0, sizeof(g_mem_hist));
}

void init_mem_histogram(unsigned int nbuckets)
{
	unsigned int i;

	release_mem_histogram();

	g_mem_hist.num_buckets = nbuckets;
	g_mem_hist.bucket_sizes = (size_t*)malloc(nbuckets * sizeof(size_t));
	for (i = 0; i < nbuckets; i++)
		g_mem_hist.bucket_sizes[i] = 16 << i;
	g_mem_hist.inuse_cnt = (unsigned long*)malloc((nbuckets+1) * sizeof(unsigned long));
	g_mem_hist.inuse_bytes = (size_t*)malloc((nbuckets+1) * sizeof(size_t));
	g_mem_hist.free_cnt = (unsigned long*)malloc((nbuckets+1) * sizeof(unsigned long));
	g_mem_hist.free_bytes = (size_t*)malloc((nbuckets+1) * sizeof(size_t));
	for (i = 0; i < nbuckets + 1; i++)
	{
		g_mem_hist.inuse_cnt[i] = 0;
		g_mem_hist.inuse_bytes[i] = 0;
		g_mem_hist.free_cnt[i] = 0;
		g_mem_hist.free_bytes[i] = 0;
	}
}

void add_block_mem_histogram(size_t size, bool inuse, unsigned int num_block)
{
	unsigned int n;

	if (!g_mem_hist.num_buckets || !g_mem_hist.bucket_sizes
		|| !g_mem_hist.inuse_cnt || !g_mem_hist.inuse_bytes
		|| !g_mem_hist.free_cnt || !g_mem_hist.free_bytes)
		return;

	for (n = 0; n < g_mem_hist.num_buckets; n++)
	{
		if (size <= g_mem_hist.bucket_sizes[n])
			break;
	}
	if (inuse)
	{
		g_mem_hist.inuse_cnt[n] += num_block;
		g_mem_hist.inuse_bytes[n] += size * num_block;
	}
	else
	{
		g_mem_hist.free_cnt[n] += num_block;
		g_mem_hist.free_bytes[n] += size * num_block;
	}
}

static void fill_space_til_pos(char* buf, size_t to_pos)
{
	size_t len = strlen(buf);
	if (len < to_pos - 1)
	{
		while (len < to_pos - 1)
			buf[len++] = ' ';
		buf[len] = '\0';
	}
	else
	{
		buf[len] = ' ';
		buf[len+1] = '\0';
	}
}

/*
 * Helper functions
 */
static void display_histogram(const char* prefix,
			unsigned int   nbuckets,
			const size_t*        bucket_sizes,
			const unsigned long* block_cnt,
			const size_t*        block_bytes)
{
	unsigned int n;
	unsigned long total_cnt, total_cnt2;
	size_t total_bytes;
	char linebuf[LINE_BUF_SZ];
	int pos = 0;
	const int second_col_pos = 16;
	const int third_col_pos = 28;

	// title
	sprintf(linebuf, "%sSize-Range", prefix);
	fill_space_til_pos(linebuf, strlen(prefix)+second_col_pos);
	pos = strlen(linebuf);
	sprintf(linebuf + pos, "Count");
	fill_space_til_pos(linebuf, strlen(prefix)+third_col_pos);
	pos = strlen(linebuf);
	sprintf(linebuf + pos, "Total-Bytes");
	CA_PRINT("%s\n", linebuf);

	total_cnt = 0;
	total_bytes = 0;
	for (n = 0; n <= nbuckets; n++)
	{
		total_cnt += block_cnt[n];
		total_bytes += block_bytes[n];
	}

	total_cnt2 = 0;
	for (n = 0; n <= nbuckets && total_cnt2 < total_cnt; n++)
	{
		if (block_cnt[n] > 0)
		{
			sprintf(linebuf, "%s", prefix);
			pos = strlen(linebuf);

			// bucket size range
			if (n == 0)
			{
				strcat(linebuf, "0 - ");
				pos = strlen(linebuf);
				fprint_size(linebuf + pos, bucket_sizes[n]);
				pos = strlen(linebuf);
			}
			else if (n == nbuckets)
			{
				fprint_size(linebuf + pos, bucket_sizes[n-1]);
				pos = strlen(linebuf);
				strcat(linebuf, " -    ");
				pos = strlen(linebuf);
			}
			else
			{
				fprint_size(linebuf + pos, bucket_sizes[n-1]);
				pos = strlen(linebuf);
				strcat(linebuf, " - ");
				pos = strlen(linebuf);
				fprint_size(linebuf + pos, bucket_sizes[n]);
				pos = strlen(linebuf);
			}
			fill_space_til_pos(linebuf, strlen(prefix)+second_col_pos);
			pos = strlen(linebuf);

			// count
			sprintf(linebuf + pos, "%ld(%ld%%)",
					block_cnt[n], block_cnt[n] * 100 / total_cnt);
			fill_space_til_pos(linebuf, strlen(prefix)+third_col_pos);
			pos = strlen(linebuf);

			// total bytes
			fprint_size(linebuf + pos, block_bytes[n]);
			pos = strlen(linebuf);
			sprintf(linebuf + pos, "(%ld%%)", block_bytes[n] * 100 / total_bytes);

			// output
			CA_PRINT("%s\n", linebuf);

			total_cnt2 += block_cnt[n];
		}
	}
	sprintf(linebuf, "%sTotal", prefix);
	fill_space_til_pos(linebuf, strlen(prefix)+second_col_pos);
	pos = strlen(linebuf);
	sprintf(linebuf + pos, "%ld", total_cnt);
	fill_space_til_pos(linebuf, strlen(prefix)+third_col_pos);
	pos = strlen(linebuf);
	fprint_size(linebuf + pos, total_bytes);
	CA_PRINT("%s\n", linebuf);
}

static bool
mark_blocks_referenced_by_globals_locals(std::vector<struct reachable_block>& blocks,
						unsigned int* qv_bitmap)
{
	unsigned int seg_index;
	size_t ptr_sz = g_ptr_bit >> 3;

	for (seg_index = 0; seg_index < g_segment_count; seg_index++)
	{
		struct ca_segment* segment = &g_segments[seg_index];

		// This search may take long, bail out if user is impatient
		if (user_request_break())
		{
			CA_PRINT("Abort searching\n");
			break;
		}

		if (segment->m_fsize == 0)
			continue;

		// Only local/global variables are checked
		if (segment->m_type == ENUM_STACK
			|| segment->m_type == ENUM_MODULE_DATA
			|| segment->m_type == ENUM_MODULE_TEXT)
		{
			address_t start, next, end;

			start = segment->m_vaddr;
			end   = start + segment->m_fsize;
			// ignore stack memory below stack pointer
			if (segment->m_type == ENUM_STACK)
			{
				address_t rsp = get_rsp(segment);
				if (rsp >= segment->m_vaddr && rsp < segment->m_vaddr + segment->m_vsize)
					start = rsp;
			}

			next = ALIGN(start, ptr_sz);
			while (next + ptr_sz <= end)
			{
				address_t ptr;
				struct reachable_block* blk;

				if (!read_memory_wrapper(segment, next, &ptr, ptr_sz))
					break;

				blk = find_reachable_block(ptr, blocks);
				if (blk)
				{
					unsigned long index = blk - &blocks[0];
					set_queued_and_visited(qv_bitmap, index);
				}
				next += ptr_sz;
			}
		}
	}

	return true;
}

static unsigned long get_next_queued_index(unsigned int* bitmap, unsigned long max_index, unsigned long cur_index)
{
	unsigned long next_index;
	unsigned int indexes;

	next_index = cur_index + 1;
	while (next_index < max_index)
	{
		indexes = bitmap[next_index >> 4];
		if (indexes & 0x55555555) // check 16 queue bits at once
		{
			unsigned long bit = (next_index & 0xf) << 1;
			if (indexes & (QUEUED << bit))
				return next_index;
			next_index++;
		}
		else
		{
			// skip all bits within this "int"
			next_index = (next_index & (~0x0Ful)) + 16;
		}
	}
	next_index = 0;
	while (next_index < cur_index)
	{
		indexes = bitmap[next_index >> 4];
		if (indexes & 0x55555555) // check 16 queue bits at once
		{
			unsigned long bit = (next_index & 0xf) << 1;
			if (indexes & (QUEUED << bit))
				return next_index;
			next_index++;
		}
		else
		{
			// skip all bits within this "int"
			next_index = (next_index & (~0x0Ful)) + 16;
		}
	}
	return UINT_MAX;
}

static unsigned int* get_index_map_buffer(unsigned int len)
{
	static unsigned int* g_index_map_buffer = NULL;
	static unsigned int  g_index_map_buffer_size = 0;
	if (g_index_map_buffer_size < len)
	{
		// beware of overflow
		if (len == UINT_MAX)
			g_index_map_buffer_size = UINT_MAX;
		else
			g_index_map_buffer_size = len + 1;
		// free previous, smaller buffer
		if (g_index_map_buffer)
			free (g_index_map_buffer);
		// allocate a buffer big enough for current request
		g_index_map_buffer = (unsigned int*) malloc(g_index_map_buffer_size * sizeof(unsigned int));
		if (!g_index_map_buffer)
		{
			CA_PRINT("Out-of-memory\n");
			return NULL;
		}
	}
	return g_index_map_buffer;
}

/*
 * block's index map is an array of indexes of sub blocks
 */
static bool build_block_index_map(struct reachable_block* blk,
						std::vector<struct reachable_block>& blocks)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	// Prepare this
	if (!blk->reachable.index_map)
	{
		address_t start, end, cursor;
		unsigned int max_sub_blocks, total_sub_blocks;
		unsigned int* index_buf = NULL;
		unsigned int i, index;

		// Queue possible pointers to heap memory contained by this block
		start = ALIGN(blk->addr, ptr_sz);
		end   = start + blk->size;
		cursor = start;

		max_sub_blocks = (end - start) / ptr_sz;
		total_sub_blocks = 0;
		index_buf = get_index_map_buffer(max_sub_blocks + 1);	// one for terminator
		while (cursor < end)
		{
			address_t ptr;
			struct reachable_block *sub_blk;
			if (read_memory_wrapper(NULL, cursor, (void*)&ptr, ptr_sz) && ptr)
			{
				sub_blk = find_reachable_block(ptr, blocks);
				if (sub_blk)
				{
					bool found_dup = false;
					// avoid duplicate, which is not uncommon
					// FIXME, consider non-linear search
					index = sub_blk - &blocks[0];
					for (i = 0; i < total_sub_blocks; i++)
					{
						if (index_buf[i] == index)
						{
							found_dup = true;
							break;
						}
					}
					if (!found_dup)
					{
						index_buf[total_sub_blocks++] = index;
						if (total_sub_blocks == UINT_MAX)
						{
							CA_PRINT("Internal fatal error: number of sub blocks exceeds 4 billion\n");
							return false;
						}
					}
				}
			}
			cursor += ptr_sz;
		}
		// allocate cache to hold the indexes of this block
		index_buf[total_sub_blocks++] = UINT_MAX;	// this value serves as terminator
		blk->reachable.index_map = (unsigned int*) malloc(total_sub_blocks * sizeof(unsigned int));
		if (!blk->reachable.index_map)
		{
			CA_PRINT("Out-of-memory\n");
			return false;
		}
		memcpy(blk->reachable.index_map, index_buf, total_sub_blocks * sizeof(unsigned int));
	}
	return true;
}

/*
 * Input is a heap memory address
 * Return the sum of sizes of all memory blocks (and their count) reachable by the block
 * 		i.e. referenced directly or indirectly by it (avoid duplicates)
 */
static size_t
heap_aggregate_size(struct reachable_block *blk,
					std::vector<struct reachable_block>& inuse_blocks,
					unsigned int* qv_bitmap,
					unsigned long *aggr_count)
{
	size_t sum = 0;

	// Get the inuse_block struct of the input address
	*aggr_count = 0;
	if (is_queued_or_visited(qv_bitmap, blk - &inuse_blocks[0]))
		return 0;

	// Big loop until all reachable have been visited
	while (blk)
	{
		struct reachable_block *nextblk = NULL;
		unsigned int* indexp;
		unsigned long blk_index = blk - &inuse_blocks[0];

		// mark this block is reachable and accounted for
		sum += blk->size;
		(*aggr_count)++;
		reset_queued(qv_bitmap, blk_index);
		set_visited(qv_bitmap, blk_index);

		// Prepare this block's index map, which is an array of indexes of sub blocks
		if (!blk->reachable.index_map)
		{
			if (!build_block_index_map(blk, inuse_blocks))
				return 0;
		}

		// We have index map to work with by now
		indexp = blk->reachable.index_map;
		while (*indexp != UINT_MAX)
		{
			unsigned int index = *indexp;
			//if (index >= num_inuse_blocks)
			//{
			//	CA_PRINT("Internal fatal error: sub block index out of bound\n");
			//	return 0;
			//}
			if (!is_queued_or_visited(qv_bitmap, index))
			{
				set_queued(qv_bitmap, index);
				if (!nextblk)
					nextblk = &inuse_blocks[index];
			}
			indexp++;
		}

		// Get the next block that is queued
		if (!nextblk)
		{
			// block processed doesn't have any subfield that points to an unvisited in-use block
			// starts from the current block and wrap around
			unsigned long next_index = get_next_queued_index(qv_bitmap, inuse_blocks.size(), blk_index);
			if (next_index < inuse_blocks.size())
				nextblk = &inuse_blocks[next_index];
		}
		blk = nextblk;
	}
	return sum;
}

// find the insertion point so that the array is sorted properly
static void add_owner(struct heap_owner *owners, unsigned int num, struct heap_owner *newowner)
{
	unsigned int i;

	// If the new owner is just an alias of an existing owner, don't add it
	// but replace the existing one if the new one has more symbolic information
	if (newowner->ref.value)	// non-zero ref.value indicates reference is of a pointer type
	{
		for (i = 0; i < num; i++)
		{
			if (newowner->ref.value == owners[i].ref.value)
			{
				if ((owners[i].ref.storage_type == ENUM_STACK && newowner->ref.storage_type == ENUM_MODULE_DATA)
					|| (owners[i].ref.storage_type == ENUM_REGISTER && newowner->ref.storage_type != ENUM_REGISTER))
				{
					owners[i] = *newowner;
				}
				return;
			}
		}
	}

	// the first owner (index i) that is smaller than the new one
	for (i = 0; i < num; i++)
	{
		if (newowner->aggr_size > owners[i].aggr_size)
			break;
	}
	// insert new owner before owners[i] unless the new one is too small
	if (i <= num - 1)
	{
		// if necessary, move owners[i, .., num-2] to owners[i+1, .., num-1]
		if (num >= 2 && i < num - 1)
		{
			unsigned int j;
			for (j = num - 2; ; j--)
			{
				owners[j + 1] = owners[j];
				if (j == i)
					break;
			}
		}
		// insert new owner at index i
		owners[i] = *newowner;
	}
}
