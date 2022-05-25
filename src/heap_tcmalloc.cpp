/*
 * heap_tcmalloc.c
 *
 *  Created on: August 27, 2016
 *      Author: myan
 *
 * This Implementation uses gdb specific types. Hence not portable to non-Linux
 * platforms
 */

#include "heap_tcmalloc.h"
#include "segment.h"


#define CA_DEBUG 0
#if CA_DEBUG
#define CA_PRINT_DBG CA_PRINT
#else
#define CA_PRINT_DBG(format,args...)
#endif


/*
 * Internal data structures
 */
struct span_stats {
	int sizeclass;
	size_t span_count;
	size_t inuse_count;
	size_t free_count;
	size_t inuse_bytes;
	size_t free_bytes;
};

/*
 * Globals
 */
static int tc_version_major = 2;
static int tc_version_minor = 0;
static int tc_version_patch = 0;

static bool g_initialized = false;

static struct ca_config g_config;

static struct ca_span *g_spans;
static unsigned long g_spans_capacity;
static unsigned long g_spans_count;
static unsigned long skip_npage;

static address_t *g_cached_blocks;
static unsigned long g_cached_blocks_capacity;
static unsigned long g_cached_blocks_count;

/*
 * Forward declaration
 */
static void gdb_symbol_prelude(void);
static int type_field_name2no(struct type *, const char *);
static struct value *get_field_value(struct value *, const char *);
static bool parse_config(void);
static bool parse_pagemap(void);
static bool parse_thread_cache(void);
static bool parse_central_cache(void);
static bool parse_leaf(struct value *, struct type *);
static bool parse_span(struct value *);
static bool parse_thread_cache_lists(struct value *);
static bool parse_central_freelist(struct value *);
static bool parse_central_freelist_tcentry(struct value *, bool *);

static bool cached_block_add(address_t);
static int cached_block_compare(const void *, const void *);
static int cached_block_search_compare(const void *, const void *);
static bool verify_sorted_cached_blocks(void);
static bool is_block_cached(address_t);

static struct ca_span *span_get(address_t);
static int span_search_compare(const void *, const void *);
static bool verify_sorted_spans(void);
static bool span_block_free(struct ca_span*, address_t);
static bool span_populate_free_bitmap(struct ca_span*);
static void span_get_stat(struct ca_span *, struct span_stats *);
static void span_walk(struct ca_span *);

static void add_one_big_block(struct heap_block *, unsigned int,
    struct heap_block *);
/******************************************************************************
 * Exposed functions
 *****************************************************************************/
static const char *
heap_version(void)
{
	return "TCmalloc";
}

static bool
init_heap(void)
{
	unsigned long i;

	/*
	 * Start with a clean slate
	 */
	g_initialized = false;
	if (g_config.sizemap.class_to_pages != NULL)
		free(g_config.sizemap.class_to_pages);
	if (g_config.sizemap.class_to_size != NULL)
		free(g_config.sizemap.class_to_size);
	if (g_config.sizemap.num_objects_to_move != NULL)
		free(g_config.sizemap.num_objects_to_move);
	memset(&g_config, 0, sizeof(g_config));
	for (i = 0; i < g_spans_count; i++) {
		struct ca_span *span = &g_spans[i];
		if (span->bitmap != NULL)
			free(span->bitmap);
		memset(span, 0, sizeof *span);
	}
	g_spans_count = 0;
	skip_npage = 0;
	g_cached_blocks_count = 0;

	/* Trigger gdb symbol resolution */
	gdb_symbol_prelude();

	if (parse_config() == false ||
	    parse_pagemap() == false ||
	    parse_thread_cache() == false ||
	    parse_central_cache() == false) {
		return false;
	}

	qsort(g_cached_blocks, g_cached_blocks_count, sizeof(*g_cached_blocks),
	    cached_block_compare);
	if (verify_sorted_cached_blocks() == false ||
	    verify_sorted_spans() == false) {
		return false;
	}

	/*
	 * Show result
	 */
	CA_PRINT_DBG("%ld Spans are found\n", g_spans_count);
	for (i = 0; i < g_spans_count; i++) {
		struct ca_span *span = &g_spans[i];

		CA_PRINT_DBG("[%ld] {\n"
		    "\tstart %ld\n"
		    "\tlength %ld\n"
		    "\tnext %#lx\n"
		    "\tprev %#lx\n"
		    "\tobjects %#lx\n"
		    "\trefcount %d\n"
		    "\tsizeclass %d\n"
		    "\tlocation %d\n"
		    "\tsample %d\n"
		    "}\n",
		    i, span->start, span->length, span->next, span->prev,
		    span->objects, span->refcount, span->sizeclass,
		    span->location, span->sample);
	}
	CA_PRINT_DBG("thread/central cached blocks %ld\n", g_cached_blocks_count);

	CA_PRINT_DBG("tcmalloc heap is initialized successfully\n");
	g_initialized = true;
	return true;
}

static bool
get_heap_block_info(address_t addr, struct heap_block* blk)
{
	struct ca_span *span;
	address_t base;

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	/*
	 * No span means the address is not managed by tcmalloc
	 */
	span = span_get(addr);
	if (span == NULL)
		return false;

	/*
	 * The whole span is free
	 */
	if (span->location != SPAN_IN_USE) {
		blk->inuse = false;
		blk->addr = span->start << g_config.kPageShift;
		blk->size = span->length << g_config.kPageShift;
		return true;
	}

	/*
	 * Block size by class
	 */
	if (span->sizeclass != 0)
		blk->size = g_config.sizemap.class_to_size[span->sizeclass];
	else
		blk->size = span->length << g_config.kPageShift;

	/*
	 * Block address is on fixed-size boundary
	 */
	base = span->start << g_config.kPageShift;
	blk->addr = addr - ((addr - base) % blk->size);

	/*
	 * Block status needs to consult span's object list and all cache lists
	 */
	span_populate_free_bitmap(span);
	if (span_block_free(span, blk->addr) == true)
		blk->inuse = false;
	else
		blk->inuse = true;

	return true;
}

static bool
get_next_heap_block(address_t addr, struct heap_block* blk)
{
	struct ca_span *span, *last_span, *next;
	unsigned long pageid;

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	if (addr == 0) {
		if (g_spans_count == 0) {
			CA_PRINT("There is not heap block\n");
			return false;
		}
		/*
		* Return the first block with lowest address
		*/
		span = &g_spans[0];
	} else {
		span = span_get(addr);
		if (span == NULL) {
			CA_PRINT("The input address %#lx doesn't belong to "
			    "the heap\n", addr);
			return false;
		}

		if (span->location == SPAN_IN_USE && span->sizeclass != 0) {
			size_t blk_sz = g_config.sizemap.class_to_size[span->sizeclass];
			address_t base = span->start << g_config.kPageShift;
			unsigned int index = (addr - base) / blk_sz;
			unsigned n, bit;
			if (index < span->count -1 ) {
				index++;
				blk->addr = base + index * blk_sz;
				blk->size = blk_sz;
				n = index / UINT_BITS;
				bit = index - n * UINT_BITS;
				blk->inuse = !(span->bitmap[n] & (1 << bit));
				return true;
			}
		}

		/*
		* The next block is in the next span
		*/
		last_span = &g_spans[g_spans_count - 1];
		next = NULL;
		for (pageid = span->start + span->length;
		    pageid <= last_span->start;
		    pageid++) {
			next = span_get(pageid << g_config.kPageShift);
			if (next != NULL)
				break;
		}
		if (next == NULL)
			return false;
		span = next;
	}

	span_populate_free_bitmap(span);
	blk->addr = span->start << g_config.kPageShift;
	if (span->location != SPAN_IN_USE) {
		blk->size = span->length << g_config.kPageShift;
		blk->inuse = false;
	} else if (span->sizeclass == 0) {
		blk->size = span->length << g_config.kPageShift;
		blk->inuse = true;
	} else {
		blk->size = g_config.sizemap.class_to_size[span->sizeclass];
		blk->inuse = !(span->bitmap[0] & 1);
	}

	return true;
}

/* Return true if the block belongs to a heap */
static bool
is_heap_block(address_t addr)
{

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	return span_get(addr) != NULL;
}

/*
 * Traverse all spans unless a non-zero address is given, in which case the
 * specific span is walked
 */
static bool
heap_walk(address_t heapaddr, bool verbose)
{
	unsigned int i;
	struct span_stats *stats;
	struct span_stats total;
	size_t blk_sz;
	struct ca_span *span;

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	/*
	 * Display all blocks belonging to the span of the given address
	 */
	if (heapaddr) {
		span = span_get(heapaddr);
		if (span == NULL) {
			CA_PRINT("Address %#lx doesn't belong to tcmalloc "
			    "heap\n", heapaddr);
			return false;
		}
		span_walk(span);
		return true;
	}

	/*
	 * Full heap walk
	 */
	stats = (struct span_stats *)calloc(g_config.kNumClasses + 1, sizeof *stats);
	if (stats == NULL) {
		CA_PRINT("Out of memory\n");
		return false;
	}
	for (i = 0; i < g_config.kNumClasses; i++) {
		stats[i].sizeclass = i;
	}
	stats[g_config.kNumClasses].sizeclass = -1;

	/*
	 * Collect statistics of all spans
	 */
	for (i = 0; i < g_spans_count; i++) {
		span = &g_spans[i];

		if (span->location == SPAN_IN_USE) {
			span_get_stat(span, &stats[span->sizeclass]);
		} else {
			span_get_stat(span, &stats[g_config.kNumClasses]);
		}
	}
	memset(&total, 0, sizeof(total));

	/*
	 * Display statistics
	 */
	CA_PRINT("  size_class   num_spans  block_size  inuse_blks inuse_bytes   free_blks  free_bytes\n");
	for (i = 0; i < g_config.kNumClasses + 1; i++) {
		if (i == 0) {
			CA_PRINT("    (large)0%12zu         n/a", stats[i].span_count);
		}
		else if (i == g_config.kNumClasses)
			CA_PRINT("      (free)%12zu         n/a", stats[i].span_count);
		else {
			blk_sz = g_config.sizemap.class_to_size[i];
			CA_PRINT("%12d%12zu%12zu", i, stats[i].span_count, blk_sz);
		}

		if (stats[i].span_count != 0) {
			CA_PRINT("%12zu%12zu%12zu%12zu\n",
			    stats[i].inuse_count, stats[i].inuse_bytes,
			    stats[i].free_count, stats[i].free_bytes);
		}
		else {
			CA_PRINT("\n");
		}
		total.span_count += stats[i].span_count;
		total.inuse_count += stats[i].inuse_count;
		total.inuse_bytes += stats[i].inuse_bytes;
		total.free_count += stats[i].free_count;
		total.free_bytes += stats[i].free_bytes;
	}
	CA_PRINT("------------------------------------------------------------------------------------\n");
	CA_PRINT("       Total");
	CA_PRINT("%12zu            %12zu%12zu%12zu%12zu\n",
	    total.span_count, total.inuse_count,  total.inuse_bytes,
	    total.free_count, total.free_bytes);

	free(stats);

	return true;
}

static bool
get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	unsigned long i;
	struct ca_span *span;
	struct heap_block* smallest = &blks[num - 1];
	struct heap_block blk;

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	if (num == 0)
		return true;
	memset(blks, 0, num * sizeof *blks);

	/*
	 * Traverse big blocks (size class 0) first and populate the returned
	 * array
	 */
	for (i = 0; i < g_spans_count; i++) {
		span = &g_spans[i];

		if (span->location != SPAN_IN_USE)
			continue;

		if (span->sizeclass == 0) {
			blk.size = span->length << g_config.kPageShift;
			if (blk.size > smallest->size)
			{
				blk.addr = span->start << g_config.kPageShift;
				blk.inuse = true;
				add_one_big_block(blks, num, &blk);
			}
		}
	}
	if (smallest->size > 0)
		return true;

	/*
	 * If the queried number of largest blocks exceeds number of big blocks,
	 * continue to traverse normal blocks (size class != 0)
	 */
	for (i = 0; i < g_spans_count; i++) {
		span = &g_spans[i];

		if (span->location != SPAN_IN_USE)
			continue;

		if (span->sizeclass != 0) {
			address_t base = span->start << g_config.kPageShift;
			unsigned int index;

			blk.size = g_config.sizemap.class_to_size[span->sizeclass];
			if (blk.size <= smallest->size)
				continue;

			span_populate_free_bitmap(span);
			for (index = 0; index < span->count; index++) {
				unsigned int n, bit;

				n = index / UINT_BITS;
				bit = index - n * UINT_BITS;
				if (!(span->bitmap[n] & (1 << bit)) &&
				    blk.size > smallest->size) {
					blk.addr = base + index * blk.size;
					blk.inuse = true;
					add_one_big_block(blks, num, &blk);
				}
			}
		}
	}

	return true;
}

static bool
walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	unsigned long i;
	struct ca_span *span;

	if (g_initialized == false) {
		CA_PRINT("tcmalloc heap was not initialized successfully\n");
		return false;
	}

	*opCount = 0;
	for (i = 0; i < g_spans_count; i++) {
		span = &g_spans[i];
		span_populate_free_bitmap(span);

		if (span->location != SPAN_IN_USE)
			continue;

		if (span->sizeclass == 0) {
			(*opCount)++;
			if (opBlocks != NULL) {
				opBlocks->addr = span->start << g_config.kPageShift;
				opBlocks->size = span->length << g_config.kPageShift;
				opBlocks++;
			}
		} else {
			address_t base = span->start << g_config.kPageShift;
			unsigned int index;
			size_t blk_sz = g_config.sizemap.class_to_size[span->sizeclass];

			for (index = 0; index < span->count; index++) {
				unsigned int n, bit;

				n = index / UINT_BITS;
				bit = index - n * UINT_BITS;
				if (!(span->bitmap[n] & (1 << bit))) {
					(*opCount)++;
					if (opBlocks != NULL) {
						opBlocks->addr = base + index * blk_sz;
						opBlocks->size = blk_sz;
						opBlocks++;
					}
				}
			}
		}
	}

	return true;
}


CoreAnalyzerHeapInterface sTcMallHeapManager = {
   heap_version,
   init_heap,
   heap_walk,
   is_heap_block,
   get_heap_block_info,
   get_next_heap_block,
   get_biggest_blocks,
   walk_inuse_blocks,
};

void _init_tc_malloc() {
    return register_heap_manager("tc", &sTcMallHeapManager, false);
}
/******************************************************************************
 * Helper Functions
 *****************************************************************************/
static void
add_one_big_block(struct heap_block *blks, unsigned int num,
    struct heap_block *blk)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (blk->size > blks[i].size) {
			int k;
			// Insert blk->blks[i]
			// Move blks[i]->blks[i+1], .., blks[num-2]->blks[num-1]
			for (k = ((int)num) - 2; k >= (int)i; k--)
				blks[k+1] = blks[k];
			blks[i] = *blk;
			break;
		}
	}
}

void
gdb_symbol_prelude(void)
{
	struct symbol *pagemap3;

	/*
	 * template <int BITS>
	 *     class TCMalloc_PageMap3
	 */
	pagemap3 = lookup_symbol("TCMalloc_PageMap3<35>", 0, VAR_DOMAIN, 0).symbol;
	if (pagemap3 == NULL) {
		CA_PRINT_DBG("Failed to lookup type \"TCMalloc_PageMap3<35>\""
		    "\n");
	}

	return;
}

struct ca_span *
span_get(address_t addr)
{
	struct ca_span *span;
	unsigned long pageid;

	pageid = addr >> g_config.kPageShift;
	span = (struct ca_span *)bsearch(&pageid, (void *)g_spans, g_spans_count,
	    sizeof(struct ca_span), span_search_compare);

	return span;
}

bool
parse_config(void)
{
	struct symbol *pageshift_;
	struct symbol *sizemap_;
	struct value *sizemap;
	struct value *class_to_size;
	int fieldno;
	LONGEST low_bound, high_bound, index;

	/*
	 * Global var
	 * static const size_t kPageShift;
	 */
	pageshift_ = lookup_symbol("kPageShift", 0, VAR_DOMAIN, 0).symbol;
	if (pageshift_ == NULL) {
		CA_PRINT("Failed to lookup gv \"kPageShift\"\n");
		return false;
	}
	g_config.kPageShift = value_as_long(value_of_variable(pageshift_, 0));

	/*
	 * Global var
	 * tcmalloc::Static::sizemap_
	 */
	sizemap_ = lookup_global_symbol("tcmalloc::Static::sizemap_", 0,
	    VAR_DOMAIN).symbol;
	if (sizemap_ == NULL) {
		CA_PRINT("Failed to lookup gv "
		    "\"tcmalloc::Static::sizemap_\"\n");
		return false;
	}
	sizemap = value_of_variable(sizemap_, 0);

	/*
	 * tcmalloc::Static::sizemap_.class_to_size_
	 */
	class_to_size = get_field_value(sizemap, "class_to_size_");
	if (!class_to_size)
		return false;
	if (TYPE_CODE (value_type(class_to_size)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected \"class_to_size\" is not an array\n");
		return false;
	}
	if (get_array_bounds (value_type(class_to_size), &low_bound,
	    &high_bound) == 0) {
		CA_PRINT("Could not determine \"class_to_size\" bounds\n");
		return false;
	}

	g_config.kNumClasses = high_bound - low_bound + 1;
	g_config.sizemap.class_to_size = (size_t *)calloc(g_config.kNumClasses,
	    sizeof(size_t));
	g_config.sizemap.class_to_pages = (size_t *)calloc(g_config.kNumClasses,
	    sizeof(size_t));
	g_config.sizemap.num_objects_to_move = (int *)calloc(g_config.kNumClasses,
	    sizeof(int));
	if (g_config.sizemap.class_to_size == NULL ||
	    g_config.sizemap.class_to_pages == NULL ||
	    g_config.sizemap.num_objects_to_move == NULL) {
		CA_PRINT("Out of memory\n");
		return false;
	}

	/*
	 * tcmalloc::Static::sizemap_.class_to_size_[index]
	 */
	for (index = low_bound; index <= high_bound; index++) {
		struct value *v;

		v = value_subscript(class_to_size, index);
		g_config.sizemap.class_to_size[index] = value_as_long(v);
	}

	return true;
}

static bool
parse_pagemap_2_5(struct symbol *pageheap_, struct type *leaf_type,
    struct type *span_type)
{
	struct value *pageheap_p, *pageheap;
	struct value *pagemap;
	struct value *root_p, *root;
	struct value *ptrs;
	LONGEST low_bound, high_bound, index;

	/* struct symbol to struct value */
	pageheap_p = value_of_variable(pageheap_, 0);
	/* deref pointer value */ 
	pageheap = value_ind(pageheap_p);
	/*
	 * tcmalloc::Static::pageheap_->pagemap_
	 */
	pagemap = get_field_value(pageheap, "pagemap_");

	/*
	 * tcmalloc::Static::pageheap_->pagemap_.root_
	 */
	root_p = get_field_value(pagemap, "root_");
	root = value_ind(root_p);

	/*
	 * tcmalloc::Static::pageheap_->pagemap_.root_->ptrs
	 */
	ptrs = get_field_value(root, "ptrs");
	if (TYPE_CODE (value_type(ptrs)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected \"ptrs\" is not an array\n");
		return false;
	}
	if (get_array_bounds (value_type(ptrs), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"ptrs\" bounds\n");
		return false;
	}
	CA_PRINT_DBG("tcmalloc::Static::pageheap_->pagemap_.root_->ptrs[%ld-%ld] "
	    "array length %ld\n", low_bound, high_bound,
	    high_bound - low_bound + 1);

	/*
	 * tcmalloc::Static::pageheap_->pagemap_.root_->ptrs[index]
	 */
	for (index = low_bound; index <= high_bound; index++) {
		struct value *ptr, *node;
		struct value *ptrs2;
		LONGEST low_bound2, high_bound2, index2;

		ptr = value_subscript(ptrs, index);
		if (value_as_address(ptr) == 0)
			continue;
		node = value_ind(ptr);
		/*
		 * tcmalloc::Static::pageheap_->pagemap_.root_->ptrs[index]->ptrs
		 */
		ptrs2 = get_field_value(node, "ptrs");
		get_array_bounds (value_type(ptrs2), &low_bound2, &high_bound2);
		CA_PRINT_DBG("tcmalloc::Static::pageheap_->pagemap_.root_->ptrs[%ld]->ptrs[%ld-%ld] "
		    "array length %ld\n", index, low_bound2, high_bound2,
		    high_bound2 - low_bound2 + 1);

		/*
		 * tcmalloc::Static::pageheap_->pagemap_.root_->ptrs[index]->ptrs[index2]
		 */
		for (index2 = low_bound2; index2 <= high_bound2; index2++) {
			struct value *node2;
			struct value *leaf_p, *leaf;

			node2 = value_subscript(ptrs2, index2);
			if (value_as_address(node2) == 0)
				continue;
			leaf_p = value_cast(leaf_type, node2);
			leaf = value_ind(leaf_p);
			if (parse_leaf(leaf, span_type) == false)
				return false;
		}
	}
	return true;
}

static bool
parse_pagemap_2_7(struct symbol *pageheap_, struct type *leaf_type,
    struct type *span_type)
{
	struct value *pageheap, *storage;
	struct value *pagemap;
	struct type *pageheap_type;
	struct value *root_p, *root;
	LONGEST low_bound, high_bound, index;
	const char *type_name;

	/* tcmalloc::PageHeap needs more than the default 64KB for gdb value buffer */
	execute_command("set max-value-size 2097152", 0);

	/* struct symbol to struct value */
	storage = value_of_variable(pageheap_, 0);

	/* cast reinterpret_cast<PageHeap *>(&pageheap_.memory); */
	pageheap_type = lookup_transparent_type("tcmalloc::PageHeap");
	if (pageheap_type == NULL) {
		CA_PRINT("Failed to lookup type \"tcmalloc::PageHeap\"\n");
		return false;
	}
	pageheap = value_cast(pageheap_type, storage);

	/*
	 * tcmalloc::Static::pageheap_.memory.pagemap_
	 * type = class TCMalloc_PageMap2<35> {
	 *   private:
	 *     TCMalloc_PageMap2<35>::Leaf *root_[131072];
	 *     void *(*allocator_)(Number);
	 * }
	 */
	pagemap = get_field_value(pageheap, "pagemap_");
	type_name = TYPE_NAME(check_typedef(value_type(pagemap)));
	if (strcmp(type_name, "TCMalloc_PageMap2<35>") != 0) {
		CA_PRINT("Internal error: pageheap_.pagemap_ has unexpected type\n");
		return false;
	}
	root = get_field_value(pagemap, "root_");

	if (get_array_bounds (value_type(root), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"root_\" bounds\n");
		return false;
	}
	CA_PRINT_DBG("tcmalloc::Static::pageheap_.pagemap_.root_[%ld-%ld] "
	    "array length %ld\n", low_bound, high_bound,
	    high_bound - low_bound + 1);

	/*
	 * tcmalloc::Static::pageheap_.memory.pagemap_.root_[index]
	 */
	for (index = low_bound; index <= high_bound; index++) {
		struct value *leaf_p, *leaf;
		LONGEST low_bound2, high_bound2, index2;

		leaf_p = value_subscript(root, index);
		if (value_as_address(leaf_p) == 0)
			continue;
		leaf = value_ind(leaf_p);
		if (parse_leaf(leaf, span_type) == false)
			return false;
	}

	return true;
}

bool
parse_pagemap(void)
{
	struct symbol *pageheap_;
	struct type *ph_type;
	struct type *leaf_type, *span_type;
	const char *type_name;
	struct value *val;
	bool span_has_objects = false;

	/*
	 * We need to cast a void* to this type later
	 */
	type_name = "tcmalloc::Span";
	span_type = lookup_transparent_type(type_name);
	if (span_type == NULL) {
		CA_PRINT("Failed to lookup type \"%s\"\n", type_name);
		CA_PRINT("Do you forget to download debug symbols of libtcmalloc.so?\n");
		return false;
	}
	if (type_field_name2no(span_type, "objects") >= 0)
		span_has_objects = true;
	span_type = lookup_pointer_type(span_type);

	/*
	 * Version detection through global var:
	 *   tcmalloc::PageHeap *tcmalloc::Static::pageheap_;
	 */
	pageheap_ = lookup_global_symbol("tcmalloc::Static::pageheap_", 0,
	    VAR_DOMAIN).symbol;
	if (pageheap_ == NULL) {
		CA_PRINT("Failed to lookup gv "
		    "\"tcmalloc::Static::pageheap_\"\n");
		return false;
	}
	ph_type = SYMBOL_TYPE(pageheap_);
	if (TYPE_NAME(ph_type) &&
	    strcmp(TYPE_NAME(ph_type), "tcmalloc::Static::PageHeapStorage") == 0) {
		if (span_has_objects)
			tc_version_minor = 6;
		else
			tc_version_minor = 7;
	} else {
		tc_version_minor = 5;
	}

	if (tc_version_minor <= 5) {
		/* Version 2.5 uses three-leveled page map */
		type_name = "TCMalloc_PageMap3<35>::Leaf";
		leaf_type = lookup_transparent_type(type_name);
		if (leaf_type == NULL) {
			CA_PRINT("Failed to lookup type \"%s\"\n", type_name);
			return false;
		}
		leaf_type = lookup_pointer_type(leaf_type);
		if (!parse_pagemap_2_5(pageheap_, leaf_type, span_type))
			return false;
	} else if (tc_version_minor <= 7) {
		/* Version 2.6+ uses two-leveled page map */
		type_name = "TCMalloc_PageMap2<35>::Leaf";
		leaf_type = lookup_transparent_type(type_name);
		if (leaf_type == NULL) {
			CA_PRINT("Failed to lookup type \"%s\"\n", type_name);
			return false;
		}
		leaf_type = lookup_pointer_type(leaf_type);
		if (!parse_pagemap_2_7(pageheap_, leaf_type, span_type))
			return false;
	} else {
		CA_PRINT("Unsupported tcmalloc version\n");
		return false;
	}

	return true;
}

bool
parse_central_cache(void)
{
	struct symbol *central_cache_;
	struct value *central_cache;
	LONGEST low_bound, high_bound, index;

	/*
	 * Global var
	 * tcmalloc::CentralFreeListPadded tcmalloc::Static::central_cache_[88]
	 */
	central_cache_ = lookup_global_symbol("tcmalloc::Static::central_cache_",
	    0, VAR_DOMAIN).symbol;
	if (central_cache_ == NULL) {
		CA_PRINT("Failed to lookup gv "
		    "\"tcmalloc::Static::central_cache_\"\n");
		return false;
	}
	central_cache = value_of_variable(central_cache_, 0);
	if (TYPE_CODE (value_type(central_cache)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected \"central_cache_\" is not an array\n");
		return false;
	}
	if (get_array_bounds (value_type(central_cache), &low_bound,
	    &high_bound) == 0) {
		CA_PRINT("Could not determine \"central_cache_\" bounds\n");
		return false;
	}
	if (g_config.kNumClasses == 0)
		g_config.kNumClasses = high_bound - low_bound + 1;
	else if (g_config.kNumClasses != high_bound - low_bound + 1) {
		CA_PRINT("Inconsistent kNumClasses in central_cache\n");
		return false;
	}

	/*
	 * tcmalloc::Static::central_cache_[index]
	 */
	for (index = low_bound; index <= high_bound; index++) {
		struct value *v;
		struct value *cfl;	/* CentralFreeListPadded */
		struct type *cfl_type;

		v = value_subscript(central_cache, index);
		/*
		 * We need to work with tcmalloc::CentralFreeList,
		 * which is base class of tcmalloc::CentralFreeListPaddedTo<16>,
		 * which is base class of tcmalloc::CentralFreeListPadded
		 */
		cfl_type = TYPE_BASECLASS(value_type(v), 0);
		cfl_type = TYPE_BASECLASS(cfl_type, 0);
		cfl = value_cast(cfl_type, v);

		if (parse_central_freelist(cfl) == false)
			return false;
	}

	return true;
}

bool
parse_central_freelist(struct value *cfl)
{
	int used_slots, count;
	struct value *tc_slots, *val;
	LONGEST low_bound, high_bound, index;

	/*
	 * tcmalloc::CentralFreeList::used_slots_
	 */
	val = get_field_value(cfl, "used_slots_");
	used_slots = value_as_long(val);

	/*
	 * tcmalloc::CentralFreeList::used_slots_
	 */
	tc_slots = get_field_value(cfl, "tc_slots_");
	if (TYPE_CODE (value_type(tc_slots)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected \"tc_slots\" is not an array\n");
		return false;
	}
	if (get_array_bounds (value_type(tc_slots), &low_bound,
	    &high_bound) == 0) {
		CA_PRINT("Could not determine \"tc_slots\" bounds\n");
		return false;
	}

	/*
	 * tcmalloc::CentralFreeList::used_slots_[index]
	 */
	count = 0;
	for (index = 0; index < used_slots; index++) {
		struct value *tcentry;	/* tcmalloc::CentralFreeList::TCEntry */
		bool empty_slot;

		tcentry = value_subscript(tc_slots, index);
		if (parse_central_freelist_tcentry(tcentry, &empty_slot) ==
		    false) {
			return false;
		}

		if (empty_slot == false)
			count++;
	}
	if (count != used_slots) {
		/* FIXME */
		CA_PRINT("Heap corruption: CentralFreeList records %d slots "
		    "are used while tc_slots_ shows %d\n", used_slots, count);
	}

	return true;
}

bool
parse_central_freelist_tcentry(struct value *tcentry, bool *empty_slot)
{
	struct value *head, *tail;
	int count;
	struct type *void_p, *void_pp;

	/*
	 * tcmalloc::CentralFreeList::TCEntry::head
	 */
	head = get_field_value(tcentry, "head");
	void_p = value_type(head);
	void_pp = lookup_pointer_type(void_p);

	/*
	 * tcmalloc::CentralFreeList::TCEntry::tail
	 */
	tail = get_field_value(tcentry, "tail");

	count = 0;
	while (value_as_address(head) != 0) {
		struct value *v;

		count++;
		/* FIXME validate the address */
		if (cached_block_add(value_as_address(head)) == false)
			return false;

		/* FIXME count < sizemap_.num_objects_to_move[cl] */
		if (count > 1024) {
			CA_PRINT("tcentry's list is too long > 1024\n");
			return false;
		}

		if (value_as_address(head) == value_as_address(tail))
			break;

		v = value_cast(void_pp, head);
		head = value_ind(v);
	}
	if (count > 0)
		*empty_slot = false;
	else
		*empty_slot = true;

	return true;
}

void
span_walk(struct ca_span *span)
{
	unsigned int index, n, bit;
	size_t blk_sz;
	unsigned long addr;

	if (span->corrupt == true)
		return;

	addr = span->start << g_config.kPageShift;
	if (span->location != SPAN_IN_USE) {
		blk_sz = span->length << g_config.kPageShift;
		CA_PRINT("Free span %#lx - %#lx size %ld KiB\n",
		    addr, addr + blk_sz, blk_sz);
	} else if (span->sizeclass == 0) {
		blk_sz = span->length << g_config.kPageShift;
		CA_PRINT("Large block %#lx - %#lx size %ld KiB\n",
		    addr, addr + blk_sz, blk_sz);
	} else {
		size_t inuse_count = 0;
		size_t free_count = 0;

		span_populate_free_bitmap(span);
		blk_sz = g_config.sizemap.class_to_size[span->sizeclass];
		for (index = 0; index < span->count; index++) {
			n = index / UINT_BITS;
			bit = index - n * UINT_BITS;
			if (span->bitmap[n] & (1 << bit)) {
				free_count++;
				CA_PRINT("\t[%#lx - %#lx] %ld bytes free\n",
				    addr + index * blk_sz, addr + (index + 1) * blk_sz,
				    blk_sz);
			} else {
				inuse_count++;
				CA_PRINT("\t[%#lx - %#lx] %ld bytes inuse\n",
				    addr + index * blk_sz, addr + (index + 1) * blk_sz,
				    blk_sz);
			}
		}
		CA_PRINT("\tTotal inuse %ld blocks %ld bytes\n", inuse_count,
		    inuse_count * blk_sz);
		CA_PRINT("\tTotal free %ld blocks %ld bytes\n", free_count,
		    free_count * blk_sz);
	}

	return;
}

void
span_get_stat(struct ca_span *span, struct span_stats *stats)
{
	unsigned int index, n, bit;
	size_t blk_sz;

	if (span->corrupt == true)
		return;

	stats->span_count++;
	if (span->location != SPAN_IN_USE) {
		stats->free_count++;
		stats->free_bytes += span->length << g_config.kPageShift;
	} else if (span->sizeclass == 0) {
		stats->inuse_count++;
		stats->inuse_bytes += span->length << g_config.kPageShift;
	} else {
		span_populate_free_bitmap(span);
		blk_sz = g_config.sizemap.class_to_size[span->sizeclass];
		for (index = 0; index < span->count; index++) {
			n = index / UINT_BITS;
			bit = index - n * UINT_BITS;
			if (span->bitmap[n] & (1 << bit)) {
				stats->free_count++;
				stats->free_bytes += blk_sz;
			} else {
				stats->inuse_count++;
				stats->inuse_bytes += blk_sz;
			}
		}
	}

	return;
}

bool
span_populate_free_bitmap(struct ca_span *span)
{
	size_t blk_sz, n_uint;
	address_t base, end, cursor, next;
	unsigned long i;
	unsigned int index, n, bit;

	if (span->bitmap != NULL ||
	    span->sizeclass == 0 ||
	    span->location != SPAN_IN_USE) {
		return true;
	}

	/*
	 * Allocate space for the bitmap
	 */
	blk_sz = g_config.sizemap.class_to_size[span->sizeclass];
	span->count = (span->length << g_config.kPageShift) / blk_sz;
	n_uint = (span->count + UINT_BITS - 1) / UINT_BITS;
	span->bitmap = (unsigned int *)calloc(n_uint, sizeof(unsigned int));
	if (span->bitmap == NULL) {
		CA_PRINT("%s: out out memory\n", __FUNCTION__);
		return false;
	}

	/*
	 * Walk objects list for free blocks
	 */
	base = span->start << g_config.kPageShift;
	end = base + span->count * blk_sz;
	cursor = span->objects;
	while (cursor != 0) {
		/*
		 * Address check
		 */
		if (cursor < base || cursor >= end) {
			/* FIXME */
			CA_PRINT("Heap corruption: objects list node %#lx is "
			    "out of span's range\n", cursor);
			break;
		}
		index = (cursor - base) / blk_sz;
		if (base + index * blk_sz != cursor) {
			/* FIXME */
			CA_PRINT("Heap corruption: invalid free %#lx\n",
			    cursor);
			break;
		}

		/*
		 * Set bitmap
		 */
		n = index / UINT_BITS;
		bit = index - n * UINT_BITS;
		span->bitmap[n] |= 1 << bit;

		/*
		 * Move to the next link node
		 */
		if (read_memory_wrapper(NULL, cursor, &next, sizeof(void*)) ==
		    false) {
			break;
		}
		cursor = next;
	}
	/*
	 * Cached blocks are free blocks as well
	 * g_cached_blocks has been sorted by now
	 */
	for (i = 0; i < g_cached_blocks_count; i++) {
		address_t addr = g_cached_blocks[i];

		if (addr < base)
			continue;
		else if (addr >= end)
			break;

		index = (addr - base) / blk_sz;
		n = index / UINT_BITS;
		bit = index - n * UINT_BITS;
		span->bitmap[n] |= 1 << bit;
	}

	return true;
}

bool
span_block_free(struct ca_span *span, address_t addr)
{
	address_t base;
	unsigned int index, n, bit;
	size_t blk_sz;

	if (span->location != SPAN_IN_USE)
		return true;
	else if (span->sizeclass == 0)
		return false;

	base = span->start << g_config.kPageShift;
	blk_sz = g_config.sizemap.class_to_size[span->sizeclass];
	index = (addr - base) / blk_sz;
	n = index / UINT_BITS;
	bit = index - n * UINT_BITS;

	return span->bitmap[n] & (1 << bit);
}

int
type_field_name2no(struct type *type, const char *field_name)
{
	int n;

	if (type == NULL)
		return -1;

	type = check_typedef (type);

	for (n = 0; n < TYPE_NFIELDS (type); n++) {
		if (strcmp (field_name, TYPE_FIELD_NAME (type, n)) == 0)
			return n;
	}
	return -1;
}

struct value *
get_field_value(struct value *val, const char *field_name)
{
	int fieldno;

	fieldno = type_field_name2no(value_type(val), field_name);
	if (fieldno < 0) {
		CA_PRINT("failed to find member \"%s\"\n", field_name);
		return NULL;
	}
	return value_field(val, fieldno);
}

bool
parse_leaf(struct value *leaf, struct type *span_type)
{
	struct value *values;
	LONGEST low_bound, high_bound, index;

	/*
	 * leaf->values
	 */
	values = get_field_value(leaf, "values");
	if (TYPE_CODE (value_type(values)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected: \"values\" is not an array\n");
		return false;
	}
	if (get_array_bounds (value_type(values), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"values\" bounds\n");
		return false;
	}
	CA_PRINT_DBG("TCMalloc_PageMap3<35>::Leaf::values[%ld-%ld] array "
	    "length %ld\n", low_bound, high_bound, high_bound - low_bound + 1);

	/*
	 * leaf->values[index]
	 */
	for (index = low_bound; index <= high_bound; index++) {
		struct value *v, *span_p, *span;

		if (skip_npage > 0) {
			skip_npage--;
			continue;
		}

		v = value_subscript(values, index);
		if (value_as_address(v) == 0)
			continue;
		/*
		 * (tcmalloc::Span*)leaf->values[index]
		 */
		span_p = value_cast(span_type, v);
		span = value_ind(span_p);
		if (parse_span(span) == false)
			return false;
	}
	return true;
}

bool
parse_span(struct value *span)
{
	struct ca_span *my_span;
	struct value *m;
	struct ca_segment *segment;

	if (g_spans_count >= g_spans_capacity) {
		unsigned long goal;

		if (g_spans_capacity == 0)
			goal = 1024;
		else
			goal = g_spans_capacity * 2;
		g_spans = (struct ca_span *)realloc(g_spans, goal * sizeof(struct ca_span));
		if (g_spans == NULL)
			return false;
		g_spans_capacity = goal;
	}
	my_span = &g_spans[g_spans_count++];
	memset(my_span, 0, sizeof *my_span);

	m = get_field_value(span, "start");
	my_span->start = value_as_long(m);

	m = get_field_value(span, "length");
	my_span->length = value_as_long(m);

	m = get_field_value(span, "next");
	my_span->next = value_as_address(m);

	m = get_field_value(span, "prev");
	my_span->prev = value_as_address(m);

	if (tc_version_minor <= 6) {
		m = get_field_value(span, "objects");
		my_span->objects = value_as_address(m);
	} else {
		int n;
		struct type *span_type = value_type(span);
		/*
		 * struct tcmalloc::Span {
		 *     union {
		 *         void *objects;
		 *         char span_iter_space[8];
		 *     };
		 *     ...
		 * }
		 */
		m = get_field_value(span, "has_span_iter");
		for (n = 0; n < TYPE_NFIELDS (span_type); n++) {
			if (TYPE_CODE(TYPE_FIELD_TYPE(span_type, n)) == TYPE_CODE_UNION) {
				struct value *v = value_field(span, n);
				m = get_field_value(v, "objects");
				my_span->objects = value_as_address(m);
				break;
			}
		}
	}

	m = get_field_value(span, "refcount");
	my_span->refcount = value_as_long(m);

	m = get_field_value(span, "sizeclass");
	my_span->sizeclass = value_as_long(m);

	m = get_field_value(span, "location");
	my_span->location = value_as_long(m);

	m = get_field_value(span, "sample");
	my_span->sample = value_as_long(m);

	skip_npage = my_span->length - 1;

	segment = get_segment(my_span->start << g_config.kPageShift,
	    my_span->length << g_config.kPageShift);
	if (segment != NULL)
		segment->m_type = ENUM_HEAP;

	return true;
}

bool
parse_thread_cache(void)
{
	struct symbol *thread_heaps_;
	struct value *thread_heaps_p, *thread_heaps;

	/*
	 * Global var
	 * tcmalloc::ThreadCache *tcmalloc::ThreadCache::thread_heaps_
	 */
	thread_heaps_ = lookup_global_symbol("tcmalloc::ThreadCache::thread_heaps_",
	    0, VAR_DOMAIN).symbol;
	if (thread_heaps_ == NULL) {
		CA_PRINT("Failed to lookup gv "
		    "\"tcmalloc::ThreadCache::thread_heaps_\"\n");
		return false;
	}
	thread_heaps_p = value_of_variable(thread_heaps_, 0);
	/*
	 * thread_heaps_ is a link list of ThreadCache objects
	 */
	while (value_as_address(thread_heaps_p) != 0) {
		struct value *lists;
		LONGEST low_bound, high_bound;

		thread_heaps = value_ind(thread_heaps_p);
		lists = get_field_value(thread_heaps, "list_");
		if (TYPE_CODE (value_type(lists)) != TYPE_CODE_ARRAY) {
			CA_PRINT("Unexpected \"list_\" is not an array\n");
			return false;
		}
		if (get_array_bounds (value_type(lists), &low_bound,
		    &high_bound) == 0) {
			CA_PRINT("Could not determine \"list_\" bounds\n");
			return false;
		}
		CA_PRINT_DBG("thread_heaps_->list_[%ld-%ld] array length %ld\n",
		    low_bound, high_bound, high_bound - low_bound + 1);

		if (g_config.kNumClasses == 0)
			g_config.kNumClasses = high_bound - low_bound + 1;
		else if (g_config.kNumClasses != high_bound - low_bound + 1) {
			CA_PRINT("Inconsistent kNumClasses\n");
			return false;
		}

		if (parse_thread_cache_lists(lists) == false)
			return false;

		/* next ThreadCache on link list */
		thread_heaps_p = get_field_value(thread_heaps, "next_");
	}

	return true;
}

bool
parse_thread_cache_lists(struct value *lists)
{
	unsigned int index;

	for (index = 0; index < g_config.kNumClasses; index++) {
		struct value *freelist, *list;
		unsigned int len, count;
		struct type *void_p, *void_pp;

		freelist = value_subscript(lists, index);

		len = value_as_address(get_field_value(freelist, "length_"));

		list = get_field_value(freelist, "list_");
		void_p = value_type(list);
		void_pp = lookup_pointer_type(void_p);
		count = 0;
		while (value_as_address(list) != 0) {
			struct value *v;

			count++;
			/* FIXME validate the address */
			if (cached_block_add(value_as_address(list)) == false)
				return false;
			CA_PRINT_DBG("->%#lx", value_as_address(list));

			if (count > len)
				break;

			v = value_cast(void_pp, list);
			list = value_ind(v);
		}
		if (count > 0) {
			CA_PRINT_DBG("\n");
		}
		if (len != count) {
			CA_PRINT("Heap corruption: ThreadCache::FreeList::length_ %d "
			    "while ThreadCache::FreeList::list_ %d\n", len, count);
		}
	}

	return true;
}

bool
cached_block_add(address_t addr)
{

	if (g_cached_blocks_count >= g_cached_blocks_capacity) {
		unsigned long goal;

		if (g_cached_blocks_capacity == 0)
			goal = 1024;
		else
			goal = g_cached_blocks_capacity * 2;
		g_cached_blocks = (address_t *)realloc(g_cached_blocks, goal * sizeof(address_t));
		if (g_cached_blocks == NULL)
			return false;
		g_cached_blocks_capacity = goal;
	}
	g_cached_blocks[g_cached_blocks_count++] = addr;
	return true;
}

int
cached_block_compare(const void *l, const void *r)
{
	const address_t la = *(const address_t *)l;
	const address_t ra = *(const address_t *)r;

	return (la > ra) - (ra > la);
}

int
cached_block_search_compare(const void *k, const void *m)
{
	const address_t a = *(const address_t *)k;
	const address_t c = *(const address_t *)m;

	return (a > c) - (c > a);
}

int
span_search_compare(const void *k, const void *m)
{
	const unsigned long *pageid = (const unsigned long *)k;
	const struct ca_span *span = (const struct ca_span *)m;

	return (*pageid >= span->start) - (*pageid < span->start +
	    span->length);
}

bool
is_block_cached(address_t addr)
{
	address_t *a;

	a = (address_t *)bsearch(&addr, g_cached_blocks, g_cached_blocks_count,
	    sizeof(address_t), cached_block_search_compare);
	return a != NULL;
}

bool
verify_sorted_cached_blocks(void)
{
	unsigned long i;

	if (g_cached_blocks_count < 2)
		return true;

	for (i = 0; i < g_cached_blocks_count - 1; i++) {
		if (g_cached_blocks[i] > g_cached_blocks[i + 1]) {
			CA_PRINT("cached blocks are not sorted properly at "
			    "%ld\n", i);
			return false;
		} else if (g_cached_blocks[i] == g_cached_blocks[i + 1]) {
			CA_PRINT("found duplicate cached blocks at %ld\n", i);
		}
	}

	for (i = 0; i < g_cached_blocks_count; i++) {
		address_t addr = g_cached_blocks[i];

		if (is_block_cached(addr) == false) {
			CA_PRINT("failed to query cached block %#lx at %ld\n",
			    addr, i);
			return false;
		} else if (is_block_cached(addr + 1) == true) {
			CA_PRINT("false positive to query cached block %#lx",
			    addr + 1);
			return false;
		}
	}

	return true;
}

bool
verify_sorted_spans(void)
{
	unsigned long i, l;

	/*
	 * Mark a span corrupted if there is Inconsistency
	 */
	for (i = 0; i < g_spans_count; i++) {
		struct ca_span *span = &g_spans[i];

		if (span->sizeclass > g_config.kNumClasses)
			span->corrupt = true;
	}

	/*
	 * Verify the global array of spans is proerply sorted by pageid
	 */
	if (g_spans_count < 2)
		return true;

	for (i = 0; i < g_spans_count - 1; i++) {
		if (g_spans[i].start + g_spans[i].length >
		    g_spans[i + 1].start) {
			CA_PRINT("Spans are not sorted properly at "
			    "%ld\n", i);
			return false;
		}
	}

	for (i = 0; i < g_spans_count; i++) {
		for (l = 0; l < g_spans[i].length; l++) {
			address_t addr = ((g_spans[i].start + l) <<
			    g_config.kPageShift) + 1;

			if (span_get(addr) == NULL) {
				CA_PRINT("failed to query span with address "
				    "%#lx\n",addr);
				return false;
			}
		}
	}

	return true;
}
