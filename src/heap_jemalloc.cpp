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
static jemalloc *g_jemalloc = nullptr;

/*
 * Forward declaration
 */
static bool gdb_symbol_probe(void);
static bool parse_edata(je_bin_info_t *bininfo, je_edata_t *slab, struct value *edata_v);

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
	LONGEST low_bound, high_bound;

	if (g_jemalloc)
		delete g_jemalloc;
	g_jemalloc = new jemalloc;

	/*
	** retrieve configuration parameters
	*/

	// narenas_total
	// type = struct {
	//     unsigned int repr;
	// }
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
	g_jemalloc->narenas_total = data;

	// nbins_total
	// type = unsigned int
	sym = lookup_symbol("nbins_total", 0, VAR_DOMAIN, 0).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"nbins_total\"\n");
		return false;
	}
	val = value_of_variable(sym, 0);
	g_jemalloc->nbins_total = value_as_long(val);

	// je_bin_infos
	// type = bin_info_t [36]
	sym = lookup_symbol("je_bin_infos", 0, VAR_DOMAIN, 0).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"je_bin_infos\"\n");
		return false;
	}
	type = ca_type(sym);
	if(ca_code(type) != TYPE_CODE_ARRAY) {
		CA_PRINT("Failed to validate the type of \"je_bin_infos\"\n");
		return false;
	}
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array \"je_bin_infos\"\n");
		return false;
	}
	size_t bin_infos_len = high_bound - low_bound + 1;
	val = value_of_variable(sym, 0);
	for (int i = 0; i < bin_infos_len; i++) {
		// je_bin_infos[i]
		struct value *v = value_subscript(val, i);
		if (!v) {
			CA_PRINT("Failed to parse je_bin_infos[%d]\n", i);
			return false;
		}
		je_bin_info_t binfo;
		bool success = true;
		success &= ca_get_field_value(v, "n_shards", &data, false);
		binfo.n_shards = data;
		success &= ca_get_field_value(v, "nregs", &data, false);
		binfo.nregs = data;
		success &= ca_get_field_value(v, "reg_size", &data, false);
		binfo.reg_size = data;
		success &= ca_get_field_value(v, "slab_size", &data, false);
		binfo.slab_size = data;
		if (!success) {
			CA_PRINT("Failed to extract memebers of \"je_bin_infos[%d]\"\n", i);
			return false;
		}
		struct value *bitmap_info_v = ca_get_field_gdb_value(v, "bitmap_info");
		if (!bitmap_info_v
			|| !ca_get_field_value(bitmap_info_v, "nbits", &binfo.bitmap_info.nbits, false)
			|| !ca_get_field_value(bitmap_info_v, "ngroups", &binfo.bitmap_info.ngroups, false)) {
			CA_PRINT("Failed to extract bitmap_info of \"je_bin_infos[%d]\"\n", i);
			return false;
		}
		g_jemalloc->bin_infos.push_back(binfo);
	}
	if (g_jemalloc->bin_infos.size() != g_jemalloc->nbins_total) {
		CA_PRINT("je_bin_infos length(%ld) != nbins_total(%d)\n",
			g_jemalloc->bin_infos.size(), g_jemalloc->nbins_total);
		return false;
	}

	// je_arenas
	// type = struct {
	//     void *repr;
	// } [4095]
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
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array \"je_arenas\"\n");
		return false;
	}
	val = value_of_variable(sym, 0);

	size_t alen = high_bound - low_bound + 1;
	struct type *arena_type = lookup_transparent_type("arena_s");
	if (arena_type == nullptr) {
		CA_PRINT("Failed to lookup type \"arena_s\"\n");
		return false;
	}
	arena_type = lookup_pointer_type(arena_type);

	for (int i = 0; i < alen; i++) {
		// je_arenas[i]
		struct value *v = value_subscript(val, i);
		v = ca_get_field_gdb_value(v, "repr");
		if (value_as_address(v) == 0)
			continue;   // should we break the loop at the first empty arena?
		struct value *arena_pv = value_cast(arena_type, v);
		struct value *arena_v = value_ind(arena_pv);
		if (!arena_v) {
			CA_PRINT("Failed to parse je_arenas[%d]\n", i);
			return false;
		}
		je_arena *arena = new je_arena;
		arena->bins = new je_bin_t[g_jemalloc->nbins_total];
		struct value *stats_v = ca_get_field_gdb_value(arena_v, "stats");
		if (!stats_v) {
			CA_PRINT("Failed to parse je_arenas[%d]'s data memeber \"stats\"\n", i);
			return false;
		}
		ca_get_field_value(stats_v, "base", &arena->stats.base, false);
		ca_get_field_value(stats_v, "resident", &arena->stats.resident, false);
		// je_arenas[i].bins
		struct value *bins_v = ca_get_field_gdb_value(arena_v, "bins");
		if (!bins_v) {
			CA_PRINT("Failed to parse je_arenas[%d]'s data memeber \"bins\"\n", i);
			return false;
		}
		for (int j = 0; j < g_jemalloc->nbins_total; j++) {
			// je_arenas[i].bins[j]
			struct value *bin_v = value_subscript(bins_v, j);
			stats_v = ca_get_field_gdb_value(bin_v, "stats");
			ca_get_field_value(stats_v, "curslabs", &arena->bins[j].stats.curslabs, false);
			ca_get_field_value(stats_v, "nonfull_slabs", &arena->bins[j].stats.nonfull_slabs, false);
			struct value *slabcur_v = ca_get_field_gdb_value(bin_v, "slabcur");
			if (value_as_address(slabcur_v) == 0)
				continue;
			slabcur_v = value_ind(slabcur_v);
			if (!parse_edata(&g_jemalloc->bin_infos[j], &arena->bins[j].slabcur, slabcur_v)) {
				CA_PRINT("Failed to parse je_arenas[%d].bins[%d] data memeber \"slabcur\"\n", i, j);
				return false;
			}
		}
		g_jemalloc->je_arenas.push_back(arena);
	}
 
	// je_tcache_bin_info
	// type = cache_bin_info_t *
	/*sym = lookup_symbol("je_tcache_bin_info", 0, VAR_DOMAIN, 0).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"je_tcache_bin_info\"\n");
		return false;
	}*/

	return true;
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
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap parser is not initialized\n");
		return false;
	}

	int i = 0;
	for (auto arena : g_jemalloc->je_arenas) {
		CA_PRINT("arena[%d]: base=%ld resident=%ld\n",
			i++, arena->stats.base, arena->stats.resident);
		for (int bi = 0; bi < g_jemalloc->nbins_total; bi++) {
			je_bin_t *bin = &arena->bins[bi];
			if (bin->stats.curslabs == 0 && bin->stats.nonfull_slabs == 0)
				continue;
			CA_PRINT("\tbin[%d]: curslabs=%ld nonfull_slabs=%ld\n",
				bi, bin->stats.curslabs, bin->stats.nonfull_slabs);
			CA_PRINT("\t\tslabcur: reg_size=%ld inuse=%d free=%d\n",
				g_jemalloc->bin_infos[bi].reg_size, bin->slabcur.inuse_cnt, bin->slabcur.free_cnt);
		}
	}
	return true;
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

bool
parse_edata(je_bin_info_t *bininfo, je_edata_t *slab, struct value *edata_v)
{
	if (!edata_v)
		return false;

	if (!ca_get_field_value(edata_v, "e_bits", &slab->e_bits, false)
		|| !ca_get_field_value(edata_v, "e_addr", (size_t*)&slab->e_addr, false))
		return false;

	if (edata_slab_get(slab->e_bits)) {
		// small fix-sized blocks
		unsigned int nfree = edata_nfree_get(slab->e_bits);
		struct value *slab_data_v = ca_get_field_gdb_value(edata_v, "e_slab_data");
		if (!slab_data_v)
			return false;
		struct value *bitmap_v = ca_get_field_gdb_value(slab_data_v, "bitmap");
		if (!bitmap_v)
			return false;

		slab->free_cnt = 0;
		slab->inuse_cnt = 0;
		uint32_t reg_index = 0;
		size_t blksz = bininfo->reg_size;
		address_t addr = (address_t) slab->e_addr;
		for (size_t i = 0; i < bininfo->bitmap_info.ngroups && reg_index < bininfo->nregs; i++) {
			struct value *v = value_subscript(bitmap_v, i);
			if (!v)
				return false;
			je_bitmap_t bitmap = value_as_long(v);
			size_t bit = 1;
			for (int j = 0; j < 64 && reg_index < bininfo->nregs; j++,reg_index++) {
				if (bit & bitmap) {
					// set bit means free region (block)
					slab->free_cnt++;
				} else {
					slab->inuse_cnt++;
				}
				bit <<= 1;
				addr += blksz;
				// cache the block
			}
		}
		// verify
		if (nfree != slab->free_cnt) {
			CA_PRINT("slab inconsistent free count: nfree=%d bitmap_free=%d bitmap_inuse=%d bin_info::nregs=%d\n",
				nfree, slab->free_cnt, slab->inuse_cnt, bininfo->nregs);
		}
	}
	return true;
}
