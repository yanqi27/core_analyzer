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
static je_edata_t *parse_edata(struct value *edata_v, je_rtree_contents_t *contents);
//static bool parse_edata_heap(je_bin_info_t *bininfo, je_edata_set& slab_set, struct value *heap_v, struct type *edata_p_type);
//static bool parse_edata_list(je_bin_info_t *bininfo, je_edata_set& slab_set, struct value *list_v, struct type *edata_p_type);
//static je_edata_t *get_edata(address_t addr);
static heap_block *get_heap_block(address_t addr);
static bool build_tcache(void);

/******************************************************************************
 * Exposed functions
 *****************************************************************************/
static const char *
heap_version(void)
{
	return "jemalloc";
}

#define CHECK_VALUE(v,name) 	\
	if (!v) {					\
		CA_PRINT("Failed to get gdb value of " name "\n");	\
		return false;			\
	}

#define CHECK_SYM(s,name)	\
	if (!s) {				\
		CA_PRINT("Failed to lookup gv " name "\n");	\
		return false;		\
	}

static bool
init_heap(void)
{
	struct symbol *sym = nullptr;
	struct type *type = nullptr;
	struct value *val = nullptr;
	size_t data = 0;
	LONGEST low_bound=0, high_bound=0;

	//CA_PRINT("init heap ...\n");

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
	CHECK_SYM(sym, "narenas_total");

	val = value_of_variable(sym, 0);
	if(!ca_get_field_value(val, "repr", &data, false)) {
		CA_PRINT("Failed to retrieve value of \"narenas_total\"\n");
		return false;
	}
	g_jemalloc->narenas_total = data;

	// nbins_total
	// type = unsigned int
	sym = lookup_symbol("nbins_total", 0, VAR_DOMAIN, 0).symbol;
	CHECK_SYM(sym, "nbins_total");

	val = value_of_variable(sym, 0);
	g_jemalloc->nbins_total = value_as_long(val);

	// je_bin_infos
	// type = bin_info_t [36]
	sym = lookup_symbol("je_bin_infos", 0, VAR_DOMAIN, 0).symbol;
	CHECK_SYM(sym, "je_bin_infos");
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

	// size_t sz_index2size_tab[SC_NSIZES];
	sym = lookup_symbol("je_sz_index2size_tab", 0, VAR_DOMAIN, 0).symbol;
	CHECK_SYM(sym, "je_sz_index2size_tab");
	type = ca_type(sym);
	if(ca_code(type) != TYPE_CODE_ARRAY) {
		CA_PRINT("Failed to validate the type of \"je_sz_index2size_tab\"\n");
		return false;
	}
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array \"je_sz_index2size_tab\"\n");
		return false;
	}
	size_t sz_tab_len = high_bound - low_bound + 1;
	val = value_of_variable(sym, 0);
	for (int i = 0; i < sz_tab_len; i++) {
		// sz_index2size_tab[i]
		struct value *v = value_subscript(val, i);
		if (!v) {
			CA_PRINT("Failed to parse sz_index2size_tab[%d]\n", i);
			return false;
		}
		g_jemalloc->sz_table.push_back(value_as_long(v));
	}

	// slabs from the global radix tree, which is 2-level on x64 arch
	// rtree_levels
	// type = const struct rtree_level_s {
	//     unsigned int bits;
	//     unsigned int cumbits;
	// } [2]
	sym = lookup_symbol("rtree_levels", 0, VAR_DOMAIN, 0).symbol;
	CHECK_SYM(sym, "rtree_levels");
	type = ca_type(sym);
	if(ca_code(type) != TYPE_CODE_ARRAY) {
		CA_PRINT("Failed to validate the type of \"rtree_levels\"\n");
		return false;
	}
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array \"rtree_levels\"\n");
		return false;
	}
	size_t total_level = high_bound - low_bound + 1;
	if (total_level != 2) {
		CA_PRINT("Expect \"rtree_levels\" is an array of length 2, but got %ld\n", total_level);
		return false;
	}
	val = value_of_variable(sym, 0);
	for (auto i = 0; i < 2; i++) {
		struct value *v = value_subscript(val, i);
		CHECK_VALUE(v, "rtree_levels[i]");
		if (!ca_get_field_value(v, "bits", &data, false)) {
			CA_PRINT("Failed to extract members of rtree_levels[i].bits\n");
			return false;
		}
		g_jemalloc->rtree_level[i].bits = (unsigned int) data;
		if (!ca_get_field_value(v, "cumbits", &data, false)) {
			CA_PRINT("Failed to extract members of rtree_levels[i].cumbits\n");
			return false;
		}
		g_jemalloc->rtree_level[i].cumbits = (unsigned int) data;
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
			/*
			// je_arenas[i].bins[j].slabcur
			auto binfo = &g_jemalloc->bin_infos[j];
			je_edata_t *slab = nullptr;
			struct value *slabcur_v = ca_get_field_gdb_value(bin_v, "slabcur");
			struct type	*edata_p_type = value_type(slabcur_v);
			if (value_as_address(slabcur_v) != 0) {
				slabcur_v = value_ind(slabcur_v);
				slab = parse_edata(binfo, slabcur_v);
				if (!slab) {
					CA_PRINT("Failed to parse je_arenas[%d].bins[%d] data memeber \"slabcur\"\n", i, j);
					return false;
				}
				slab->slab_owner = ENUM_SLAB_CUR;
				arena->bins[j].slabs.insert(slab);
			}
			// je_arenas[i].bins[j].slabs_nonfull
			// type = edata_heap_t
			struct value *slabs_nonfull_v = ca_get_field_gdb_value(bin_v, "slabs_nonfull");
			if (!parse_edata_heap(binfo, arena->bins[j].slabs, slabs_nonfull_v, edata_p_type)) {
				CA_PRINT("Failed to parse je_arenas[%d].bins[%d] data memeber \"slabs_nonfull\"\n", i, j);
				return false;
			}
			// je_arenas[i].bins[j].slabs_full
			// type = struct edata_list_active_t
			struct value *slabs_full_v = ca_get_field_gdb_value(bin_v, "slabs_full");
			if (!parse_edata_list(binfo, arena->bins[j].slabs, slabs_full_v, edata_p_type)) {
				CA_PRINT("Failed to parse je_arenas[%d].bins[%d] data memeber \"slabs_full\"\n", i, j);
				return false;
			}
			*/
		}
		g_jemalloc->je_arenas.push_back(arena);
	}

	// je_arena_emap_global
	// type = struct emap_s {
	//     rtree_t rtree;
	// }
	// type = struct rtree_s {
	//     base_t *base;
	//     malloc_mutex_t init_lock;
	//     rtree_node_elm_t root[262144];
	// }
	// type = struct rtree_node_elm_s {
	//     atomic_p_t child;
	// }
	// type = struct atomic_p_t {
	//     void *repr;
	// }
	sym = lookup_symbol("je_arena_emap_global", 0, VAR_DOMAIN, 0).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"je_arena_emap_global\"\n");
		return false;
	}
	val = value_of_variable(sym, 0);
	CHECK_VALUE(val, "je_arena_emap_global");

	struct value *rtree_v = ca_get_field_gdb_value(val, "rtree");
	CHECK_VALUE(rtree_v, "je_arena_emap_global::rtree");

	struct value *root_v = ca_get_field_gdb_value(rtree_v, "root");
	CHECK_VALUE(root_v, "je_arena_emap_global::rtree::root");

	type = value_type(root_v);
	if(ca_code(type) != TYPE_CODE_ARRAY) {
		CA_PRINT("Failed to validate the type of \"je_arena_emap_global::rtree::root\"\n");
		return false;
	}
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array \"je_arena_emap_global::rtree::root\"\n");
		return false;
	}
	size_t total_nodes = high_bound - low_bound + 1;

	struct type *leaf_type = lookup_transparent_type("rtree_leaf_elm_s");
	if (leaf_type == nullptr) {
		CA_PRINT("Failed to lookup type \"rtree_leaf_elm_s\"\n");
		return false;
	}
	leaf_type = lookup_pointer_type(leaf_type);

	struct type *edata_type = lookup_transparent_type("edata_s");
	if (!edata_type) {
		CA_PRINT("Failed to lookup type \"edata_s\"\n");
		return false;
	}
	std::set<uintptr_t> edata_addr_set;

	for (auto i = 0; i < total_nodes; i++) {
		// level 0
		// rtree_node_elm_t root[262144]
		struct value *v = value_subscript(root_v, i);
		CHECK_VALUE(v, "je_arena_emap_global::rtree::root[i]");
		struct value *child_v = ca_get_field_gdb_value(v, "child");
		CHECK_VALUE(child_v, "rtree_node_elm_s::child");
		struct value *repr_v = ca_get_field_gdb_value(child_v, "repr");
		CHECK_VALUE(repr_v, "rtree_node_elm_s::child::repr");
		if (value_as_address(repr_v) == 0)
			continue;
		// level 1
		// rtree_leaf_elm_t[262144] (2^rtree_level[1].bits)
		// type = struct rtree_leaf_elm_s {
		//     atomic_p_t le_bits;
		// }
		struct value *leaf_v = value_cast(leaf_type, repr_v);
		size_t total_leaf = (size_t)1 << g_jemalloc->rtree_level[1].bits;
		for (auto j = 0; j < total_leaf; j++) {
			struct value *leaf_elm = value_subscript(leaf_v, j);
			struct value *bits_v = ca_get_field_gdb_value(leaf_elm, "le_bits");
			struct value *leaf_repr_v = ca_get_field_gdb_value(bits_v, "repr");
			uintptr_t bits = value_as_address(leaf_repr_v);
			if (bits == 0)
				continue;
			// decode the bits to edata
			je_rtree_contents_t contents;
			contents.metadata.szind = bits >> LG_VADDR;
			contents.metadata.slab = (bool)(bits & 1);
			contents.metadata.is_head = (bool)(bits & (1 << 1));

			uintptr_t state_bits = (bits & RTREE_LEAF_STATE_MASK) >> RTREE_LEAF_STATE_SHIFT;
			contents.metadata.state = ( unsigned int)state_bits;

			uintptr_t low_bit_mask = ~((uintptr_t)EDATA_ALIGNMENT - 1);
			contents.edata = ((uintptr_t)((intptr_t)(bits << RTREE_NHIB) >> RTREE_NHIB) & low_bit_mask);

			// deduplicate
			if (edata_addr_set.find(contents.edata) != edata_addr_set.end()) {
				//CA_PRINT("Duplicated rtree leafs 0x%lx and 0x%lx; both have e_addr=0x%lx\n",
				//	contents.edata, edata_addr_map[edata->e_addr], edata->e_addr);
				continue;
			} else
				edata_addr_set.insert(contents.edata);

			struct value *edata_v = value_at(edata_type, contents.edata);
			CHECK_VALUE(edata_v, "rtree leaf");
			je_edata_t *edata = parse_edata(edata_v, &contents);
			if (!edata) {
				CA_PRINT("Failed to parse rtree leaf\n");
				return false;
			}
			g_jemalloc->edata_sorted.push_back(edata);
		}
	}

	// sort global edata vector
	std::sort(g_jemalloc->edata_sorted.begin(), g_jemalloc->edata_sorted.end(), je_edata_cmp_func);
	if (g_jemalloc->edata_sorted.size() > 1) {
		// verify there is no overlapping
		for (int i = 0; i < g_jemalloc->edata_sorted.size()-1; i++) {
			je_edata_t *edata = g_jemalloc->edata_sorted[i];
			je_edata_t *next = g_jemalloc->edata_sorted[i+1];
			if (edata->base + edata->e_size > next->base) {
				CA_PRINT("edata are not sorted correctly at index %d-%d\n", i, i+1);
				//break;
			}
		}
	}

	// sort global blocks
	std::sort(g_jemalloc->blocks.begin(), g_jemalloc->blocks.end(), heap_block_cmp_func);
	if (g_jemalloc->blocks.size() > 1) {
		for (int i = 0; i < g_jemalloc->blocks.size()-1; i++) {
			heap_block *blk1 = &g_jemalloc->blocks[i];
			heap_block *blk2 = &g_jemalloc->blocks[i+1];
			if (blk1->addr + blk1->size > blk2->addr) {
				CA_PRINT("heap blocks are not sorted correctly at index %d-%d\n", i, i+1);
				break;
			}
		}
	}

	// Extract memory blocks in thread cache and adjust their inuse status from emap
	if (!build_tcache())
		return false;
	//CA_PRINT("There are %ld memory blocks in tcache\n", g_jemalloc->cached_addr.size());
	for (auto addr : g_jemalloc->cached_addr) {
		heap_block *found = get_heap_block(addr);
		if (found)
			found->inuse = false;
		else {
			CA_PRINT("tcache address 0x%lx is not found in emap\n", addr);
		}
	}

	return true;
}


static bool
get_heap_block_info(address_t addr, struct heap_block* blk)
{
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap was not initialized successfully\n");
		return false;
	}

	heap_block *found = get_heap_block(addr);
	if (!found)
		return false;

	blk->addr = found->addr;
	blk->inuse = found->inuse;
	blk->size = found->size;

	return true;
}

static bool
get_next_heap_block(address_t addr, struct heap_block* blk)
{
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap was not initialized successfully\n");
		return false;
	}

	heap_block *next = nullptr;
	size_t len = g_jemalloc->blocks.size();
	if (addr == 0) {
		if (len > 0)
			next = &g_jemalloc->blocks[0];
	} else {
		heap_block *found = get_heap_block(addr);
		if (found && found < &g_jemalloc->blocks[len-1])
			next = found + 1;
	}

	if (next) {
		blk->addr = next->addr;
		blk->inuse = next->inuse;
		blk->size = next->size;
		return true;
	}

	return false;
}

/* Return true if the block belongs to a heap */
static bool
is_heap_block(address_t addr)
{
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap was not initialized successfully\n");
		return false;
	}

	heap_block *found = get_heap_block(addr);
	if (found)
		return true;

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
	// arenas
	for (auto arena : g_jemalloc->je_arenas) {
		CA_PRINT("arena[%d]: base=%ld resident=%ld\n",
			i++, arena->stats.base, arena->stats.resident);
		// bins
		for (int bi = 0; bi < g_jemalloc->nbins_total; bi++) {
			je_bin_t *bin = &arena->bins[bi];
			// slabs
			if (bin->stats.curslabs == 0 && bin->stats.nonfull_slabs == 0)
				continue;
			CA_PRINT("\tbin[%d]: curslabs=%ld nonfull_slabs=%ld\n",
				bi, bin->stats.curslabs, bin->stats.nonfull_slabs);
			/*
			size_t nonfull_cnt = 0;
			size_t full_cnt = 0;
			for (auto slab: bin->slabs) {
				if (slab->slab_owner == ENUM_SLAB_FULL)
					full_cnt++;
				else if (slab->slab_owner == ENUM_SLAB_NONFULL)
					nonfull_cnt++;
			}
			if (nonfull_cnt != bin->stats.nonfull_slabs) {
				CA_PRINT("\tbin[%d]: nonfull_slabs are inconsistent: stats.nonfull_slabs=%ld nonfull_slabs::heap_link=%ld\n",
					bi, bin->stats.nonfull_slabs, nonfull_cnt);
			}
			if (verbose && bin->slabs.size()) {
				for (auto slab : bin->slabs) {
					CA_PRINT("\t\t0x%lx %s reg_size=%ld inuse=%d free=%d\n",
						slab->e_addr, slab_owner_name(slab),
						g_jemalloc->bin_infos[bi].reg_size, slab->inuse_cnt, slab->free_cnt);
				}
			}
			*/
		}
	}
	return true;
}

static bool
get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap was not initialized successfully\n");
		return false;
	}

	// Ensure the output buffer is clean
	if (num == 0)
		return true;
	for (auto i = 0; i < num; i++) {
		blks[i].addr = 0;
		blks[i].inuse = false;
		blks[i].size = 0;
	}

	struct heap_block* smallest = &blks[num - 1];
	for (auto blk : g_jemalloc->blocks) {
		if (blk.size > smallest->size)
		{
			for (unsigned int j = 0; j < num; j++)
			{
				if (blk.size > blks[j].size)
				{
					// Insert blk->blks[i]
					// Move blks[i]->blks[i+1], .., blks[num-2]->blks[num-1]
					for (int k = ((int)num) - 2; k >= (int)j; k--)
						blks[k+1] = blks[k];
					blks[j] = blk;
					break;
				}
			}
		}
	}

	return true;
}

// there are two use cases
// [1] just get the total in-use blocks (opBlocks is null)
// [2] populate opBlocks with all in-use blocks
static bool
walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	if (!g_jemalloc) {
		CA_PRINT("jemalloc heap was not initialized successfully\n");
		return false;
	}

	*opCount = 0;
	struct inuse_block* pBlockinfo = opBlocks;
	for (auto blk : g_jemalloc->blocks) {
		if (blk.inuse) {
			(*opCount)++;
			if (pBlockinfo)
			{
				pBlockinfo->addr = blk.addr;
				pBlockinfo->size = blk.size;
				pBlockinfo++;
			}
		}
	}

	return true;
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

je_edata_t *
parse_edata(struct value *edata_v, je_rtree_contents_t *contents)
{
	if (!edata_v)
		return nullptr;

	std::unique_ptr<je_edata_t> edata = std::make_unique<je_edata_t>();
	if (!ca_get_field_value(edata_v, "e_bits", &edata->e_bits, false)
		|| !ca_get_field_value(edata_v, "e_addr", (size_t*)&edata->e_addr, false))
		return nullptr;
	struct value *size_v = ca_get_field_gdb_value(edata_v, "e_size_esn");
	if (!size_v)
		return nullptr;
	edata->e_size = value_as_long(size_v) & EDATA_SIZE_MASK;

	struct ca_segment *segment = get_segment(edata->e_addr, edata->e_size);
	if (segment != nullptr && segment->m_type == ENUM_UNKNOWN)
		segment->m_type = ENUM_HEAP;

	je_extent_state_t state = edata_state_get(edata->e_bits);
	if (state == extent_state_dirty || state == extent_state_muzzy) {
		edata->slab = false;
		edata->base = PAGE_ADDR2BASE(edata->e_addr);
		edata->free_cnt = 1;
		edata->inuse_cnt = 0;
		// cache the block
		g_jemalloc->blocks.push_back({edata->base, edata->e_size, false});
	} else if (edata_slab_get(edata->e_bits)) {
		edata->slab = true;
		edata->base = edata->e_addr;
		// small fix-sized blocks
		struct value *slab_data_v = ca_get_field_gdb_value(edata_v, "e_slab_data");
		if (!slab_data_v)
			return nullptr;
		struct value *bitmap_v = ca_get_field_gdb_value(slab_data_v, "bitmap");
		if (!bitmap_v)
			return nullptr;

		unsigned int nfree = edata_nfree_get(edata->e_bits);
		unsigned int szind = edata_szind_get(edata->e_bits);
		if (szind >= g_jemalloc->bin_infos.size()) {
			CA_PRINT("edata szind is out of range\n");
			return nullptr;
		}
		je_bin_info_t *bininfo = &g_jemalloc->bin_infos[szind];
		edata->free_cnt = 0;
		edata->inuse_cnt = 0;
		uint32_t reg_index = 0;
		size_t blksz = bininfo->reg_size;
		address_t addr = (address_t) edata->e_addr;
		for (size_t i = 0; i < bininfo->bitmap_info.ngroups && reg_index < bininfo->nregs; i++) {
			struct value *v = value_subscript(bitmap_v, i);
			if (!v)
				return nullptr;
			je_bitmap_t bitmap = value_as_long(v);
			size_t bit = 1;
			for (int j = 0; j < 64 && reg_index < bininfo->nregs; j++,reg_index++) {
				bool inuse;
				if (bit & bitmap) {
					// set bit means free region (block)
					edata->free_cnt++;
					inuse = false;
				} else {
					edata->inuse_cnt++;
					inuse = true;
				}
				// cache the block
				g_jemalloc->blocks.push_back({addr, blksz, inuse});
				// next block
				bit <<= 1;
				addr += blksz;
			}
		}
		// verify
		if (nfree != edata->free_cnt) {
			CA_PRINT("slab inconsistent free count: nfree=%d bitmap_free=%d bitmap_inuse=%d bin_info::nregs=%d\n",
				nfree, edata->free_cnt, edata->inuse_cnt, bininfo->nregs);
		}
	} else {
		// large memory block
		edata->slab = false;
		edata->base = PAGE_ADDR2BASE(edata->e_addr);
		edata->free_cnt = 0;
		edata->inuse_cnt = 1;
		size_t blksz = edata->e_size - (edata->e_addr - edata->base);
		if (contents->metadata.szind < g_jemalloc->sz_table.size())
			blksz = g_jemalloc->sz_table[contents->metadata.szind];
		// cache the block
		g_jemalloc->blocks.push_back({edata->e_addr, blksz, true});
	}

	/*
	// store the new slab
	auto itr = slab_set.insert(slab.get());
	if (itr.second == false) {
		CA_PRINT("Failed to add a new slab(je_edata_t) to the set\n");
		return false;
	}
	slab.release();
	*/

	return edata.release();
}

/*
// Parameters:
//     node: type = void* (real type = struct edata_t)
static bool
parse_edata_heap_node(struct value *node_v, je_bin_info_t *bininfo, je_edata_set& slab_set, struct type *edata_p_type)
{
	if (value_as_address(node_v) == 0)
		return true;

	// parse this node
	struct value *edata_p_v = value_cast(edata_p_type, node_v);
	struct value *edata_v = value_ind(edata_p_v);
	je_edata_t *slab = parse_edata(bininfo, edata_v);
	if (!slab)
		return false;
	slab->slab_owner = ENUM_SLAB_NONFULL;
	slab_set.insert(slab);

	// parse the pairing heap tree under the node
	struct value *heap_link_v = ca_get_field_gdb_value(edata_v, "heap_link");
	if (!heap_link_v) {
		CA_PRINT("Failed to extract member \"heap_link\" of \"edata_t\" object\n");
		return false;
	}
	// struct edata_heap_link_t {
    //     phn_link_t link;
	// }
	struct value *link_v = ca_get_field_gdb_value(heap_link_v, "link");
	if (!link_v) {
		CA_PRINT("Failed to extract member \"link\" of \"edata_heap_link_t\" object\n");
		return false;
	}
	// struct phn_link_s {
	//    void *prev;
	//    void *next;
	//    void *lchild;
	// }
	// chase "next" and "lchild", ignore "prev" which should be visited already
	struct value *next_v = ca_get_field_gdb_value(link_v, "next");
	struct value *lchild_v = ca_get_field_gdb_value(link_v, "lchild");
	if (!next_v || !lchild_v) {
		CA_PRINT("Failed to extract member \"next\"/\"lchild\" of \"phn_link_s\" object\n");
		return false;
	}
	bool success = true;
	// parse next node
	if (value_as_address(next_v)) {
		success = parse_edata_heap_node(next_v, bininfo, slab_set, edata_p_type) && success;
	}
	// parse child node
	if (value_as_address(lchild_v)) {
		success = parse_edata_heap_node(lchild_v, bininfo, slab_set, edata_p_type) && success;
	}
	return success;
}

// Parameters:
//     heap_v: type = struct edata_heap_t {
//                     ph_t ph;
//                    };
bool
parse_edata_heap(je_bin_info_t *bininfo, je_edata_set& slab_set, struct value *heap_v, struct type *edata_p_type)
{
	if (!heap_v)
		return false;

	// type = struct ph_s {
	//     void *root;
	//     size_t auxcount;
	// }
	heap_v = ca_get_field_gdb_value(heap_v, "ph");
	if (!heap_v)
		return false;
	struct value *root_v = ca_get_field_gdb_value(heap_v, "root");

	// parse the pairing heap
	return parse_edata_heap_node(root_v, bininfo, slab_set, edata_p_type);
}

// Parameters:
//     list_v: type = struct edata_list_active_t {
//                        struct {
//                            edata_t *qlh_first;
//                        } head;
//                    }
bool
parse_edata_list(je_bin_info_t *bininfo, je_edata_set& slab_set, struct value *list_v, struct type *edata_p_type)
{
	if (!list_v)
		return false;

	struct value *head_v = ca_get_field_gdb_value(list_v, "head");
	if (!head_v) {
		CA_PRINT("Failed to extract member \"head\" of \"edata_list_active_t\" object\n");
		return false;
	}
	struct value *qlh_first_v = ca_get_field_gdb_value(head_v, "qlh_first");
	if (!qlh_first_v) {
		CA_PRINT("Failed to extract member \"qlh_first\" of \"head\" object\n");
		return false;
	}

	CORE_ADDR head_addr = value_as_address(qlh_first_v);
	if (head_addr == 0)
		return true;

	// traverse the doubly-link list
	struct value *node = value_ind(qlh_first_v);
	do {
		je_edata_t *slab = parse_edata(bininfo, node);
		if (!slab)
			return false;
		slab->slab_owner = ENUM_SLAB_FULL;
		slab_set.insert(slab);
		// ql_link_active
		// type = struct { edata_t *qre_next; edata_t *qre_prev; }
		struct value *linkage_v = ca_get_field_gdb_value(node, "ql_link_active");
		if (!linkage_v) {
			CA_PRINT("Failed to extract member \"ql_link_active\" of \"edata_t\" object\n");
			return false;
		}
		// next, which can't never be null because it is a doubly-linked list.
		struct value *next_v = ca_get_field_gdb_value(linkage_v, "qre_next");
		if (!next_v) {
			CA_PRINT("Failed to extract member \"qre_next\" of \"ql_link_active\"\n");
			return false;
		}
		node = value_ind(next_v);
	} while (value_as_address(node) != head_addr);

	return true;
}

je_edata_t *
get_edata(address_t addr)
{
	je_edata_t key;
	key.e_addr = addr;
	key.e_size = 0;

	auto lower = std::lower_bound(g_jemalloc->edata_sorted.begin(), g_jemalloc->edata_sorted.end(),
		&key, je_edata_cmp_func);
	if (lower != g_jemalloc->edata_sorted.end()) {
		if (addr >= (*lower)->e_addr && addr < (*lower)->e_addr + (*lower)->e_size)
			return *lower;
	}

	return nullptr;
}
*/

heap_block *
get_heap_block(address_t addr)
{
	heap_block blk = {addr, 0, false};

	auto lower = std::lower_bound(g_jemalloc->blocks.begin(), g_jemalloc->blocks.end(),
		blk, heap_block_cmp_func);
	if (lower != g_jemalloc->blocks.end()) {
		if (addr >= (*lower).addr && addr < (*lower).addr + (*lower).size)
			return &(*lower);
	}
	return nullptr;
}

// Always return 0 so that all threads are visited
static int
thread_tcache (struct thread_info *info, void *data)
{
	struct symbol *sym;
	struct value *val;
	struct type *type;

	switch_to_thread (info);

	// je_tsd_tls
	// type = __thread tsd_t je_tsd_tls
	sym = lookup_symbol("je_tsd_tls", 0, VAR_DOMAIN, 0).symbol;
	if (!sym) {
		CA_PRINT("Failed to lookup thread-local variable \"je_tsd_tls\" of thread [%d]\n", info->ptid.pid());
		return 0;
	}
	val = value_of_variable(sym, 0);
	if (!val) {
		CA_PRINT("Failed to get the value of \"je_tsd_tls\" of thread [%d]\n", info->ptid.pid());
		return 0;
	}
	struct value *tcache_v = ca_get_field_gdb_value(val, "cant_access_tsd_items_directly_use_a_getter_or_setter_tcache");
	if (!tcache_v) {
		CA_PRINT("Failed to extract member \"cant_access_tsd_items_directly_use_a_getter_or_setter_tcache\" of \"je_tsd_tls\" of thread [%d]\n", info->ptid.pid());
		return 0;
	}

	// je_tsd_tls.cant_access_tsd_items_directly_use_a_getter_or_setter_tcache
	// type = struct tcache_s {
	//     tcache_slow_t *tcache_slow;
	//     cache_bin_t bins[73];
	// }
	struct value *bins_v = ca_get_field_gdb_value(tcache_v, "bins");
	if (!bins_v) {
		CA_PRINT("Failed to extract member \"bins\" of \"tcache_t\" of thread [%d]\n", info->ptid.pid());
		return 0;
	}
	type = value_type(bins_v);
	if(ca_code(type) != TYPE_CODE_ARRAY) {
		CA_PRINT("Failed to validate the array type of \"tcache_t::bins\"\n");
		return 0;
	}
	LONGEST low_bound=0, high_bound=0;
	if (!get_array_bounds(type, &low_bound, &high_bound)) {
		CA_PRINT("Failed to query array bounds of \"tcache_t::bins\"\n");
		return false;
	}
	size_t bins_len = high_bound - low_bound + 1;
	for (int i = 0; i < bins_len; i++) {
		// tcache_t::bins[i]
		// type = struct cache_bin_s {
		//      void **stack_head;
		//      cache_bin_stats_t tstats;
		//      uint16_t low_bits_low_water;
		//      uint16_t low_bits_full;
		//      uint16_t low_bits_empty;
		// }
		struct value *cache_bin_v = value_subscript(bins_v, i);
		if (!cache_bin_v) {
			CA_PRINT("Failed to index array of \"tcache_t::bins\" at [%d]\n", i);
			return 0;
		}
		struct value *head_v = ca_get_field_gdb_value(cache_bin_v, "stack_head");
		if (!head_v) {
			CA_PRINT("Failed to extract member \"stack_head\" of \"cache_bin_t\"\n");
			return 0;
		}
		uintptr_t head = value_as_address(head_v);
		size_t mdata;
		if (!ca_get_field_value(cache_bin_v, "low_bits_empty", &mdata, false)) {
			CA_PRINT("Failed to extract member \"low_bits_empty\" of \"cache_bin_t\"\n");
			return 0;
		}
		uint16_t low_bits_empty = (uint16_t)mdata;
		uint16_t low_bits = (uint16_t)head;
		if (low_bits > low_bits_empty)	// corruption?
			continue;
		uint16_t offset = low_bits_empty - low_bits;
		if (offset & ((uint16_t)sizeof(void*)-1)) {
			// offset should be multiple of ptr size
			continue;
		}
		uint16_t cache_cnt = offset / (uint16_t)sizeof(void*);
		for (uint16_t j = 0; j < cache_cnt; j++) {
			struct value *ptr_v = value_subscript(head_v, j);
			if (!ptr_v) {
				CA_PRINT("Failed to index array of \"cache_bin_t::stack_head\" at [%d]\n", j);
				return 0;
			}
			uintptr_t ptr = value_as_address(ptr_v);
			if (ptr)
				g_jemalloc->cached_addr.insert(ptr);
		}
	}

	return 0;
}

// Traverse all threads for thread-local variables
bool
build_tcache(void)
{
	// je_tcache_bin_info
	// type = cache_bin_info_t *
	/*sym = lookup_symbol("je_tcache_bin_info", 0, VAR_DOMAIN, 0).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"je_tcache_bin_info\"\n");
		return false;
	}*/

	/* remember current thread */
	struct thread_info* old = inferior_thread();
	/* switch to all threads */
	iterate_over_threads(thread_tcache, NULL);
	/* resume the old thread */
	switch_to_thread (old);

	return true;
}