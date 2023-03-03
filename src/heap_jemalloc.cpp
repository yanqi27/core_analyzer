/*
 * heap_jemalloc.cpp
 *
 *  Created on: March 1, 2023
 *      Author: myan
 *
 * This Implementation uses gdb specific types. Hence not portable to non-Linux
 * platforms
 */
#include "segment.h"
#include "heap_jemalloc.h"

/*
 * Global variables
 */
static jemalloc g_jemalloc;

/*
 * Forward declaration
 */
static bool gdb_symbol_probe(void);

/******************************************************************************
 * Exposed functions
 *****************************************************************************/
static const char *
heap_version(void)
{
	return "jemalloc";
}

static bool
init_heap(void)
{
    struct symbol *sym;
    struct type *type;
    struct value *val;
    size_t data;
    // retrieve configuration parameters
    // 1.  narenas_total
    //     struct {
    //         unsigned int repr;
    //     }
    sym = lookup_symbol("narenas_total", 0, VAR_DOMAIN, 0).symbol;
    if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"narenas_total\"\n");
		return false;
	}
    val = value_of_variable(sym, 0);
    if(!ca_get_field_value(val, "repr", &data, false)) {
		CA_PRINT("Failed to retrieve value of \"narenas_total\"\n");
		return false;
	}
    g_jemalloc.narenas_total = data;
    // 2.  je_arenas
    //     type = struct {
    //         void *repr;
    //     } [4095]
    sym = lookup_symbol("je_arenas", 0, VAR_DOMAIN, 0).symbol;
    if (sym == nullptr) {
        CA_PRINT("Failed to lookup gv \"je_arenas\"\n");
        return false;
    }
    type = ca_type(sym);
    if(ca_code(type) != TYPE_CODE_ARRAY) {
        CA_PRINT("Failed to validate the type of \"je_arenas\"\n");
        return false;
    }
    LONGEST low_bound, high_bound;
    if (!get_array_bounds(type, &low_bound, &high_bound)) {
        CA_PRINT("Failed to query array \"je_arenas\"\n");
        return false;
    }
    size_t alen = high_bound - low_bound + 1;
    g_jemalloc.je_arenas = new struct je_arena[alen];

    val = value_of_variable(sym, 0);
    for (int i = 0; i < alen; i++) {
        struct value *v = value_subscript(val, i);
        
    }


    return false;
}

static bool
get_heap_block_info(address_t addr, struct heap_block* blk)
{
    return false;
}

static bool
get_next_heap_block(address_t addr, struct heap_block* blk)
{
    return false;
}

/* Return true if the block belongs to a heap */
static bool
is_heap_block(address_t addr)
{
    return false;
}

/*
 * Traverse all spans unless a non-zero address is given, in which case the
 * specific span is walked
 */
static bool
heap_walk(address_t heapaddr, bool verbose)
{
    return false;
}

static bool
get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
    return false;
}

static bool
walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
    return false;
}

CoreAnalyzerHeapInterface sJeMallHeapManager = {
   heap_version,
   init_heap,
   heap_walk,
   is_heap_block,
   get_heap_block_info,
   get_next_heap_block,
   get_biggest_blocks,
   walk_inuse_blocks,
};

void register_je_malloc() {
	bool my_heap = gdb_symbol_probe();
    return register_heap_manager("je", &sJeMallHeapManager, my_heap);
}


/******************************************************************************
 * Helper Functions
 *****************************************************************************/
// Return true if the target has jemalloc symbols
bool
gdb_symbol_probe(void)
{
    struct symbol *arenas;
    arenas = lookup_symbol("je_arenas", 0, VAR_DOMAIN, 0).symbol;
    if (arenas)
        return true;
    return false;
}
