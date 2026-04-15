/*
 * heap_mimalloc.c
 *
 *  Created on: March 30, 2026
 *      Author: Michael Yan
 *
 * This Implementation uses gdb specific types. Hence not portable to non-Linux
 * platforms
 */

#include "segment.h"
#include "heap_mimalloc.h"
#include <set>

#define CA_DEBUG 0
#if CA_DEBUG
#define CA_PRINT_DBG CA_PRINT
#else
#define CA_PRINT_DBG(format,args...)
#endif


// Globals
static int mi_version_major = 0;
static int mi_version_minor = 0;
static int mi_version_patch = 0;
static bool mi_guard_page = false;
static bool mi_encode_freelist = false;

static bool g_initialized = false;
static int g_bin_count = 0;		// number of size classes (or "bins") of pages
static size_t* g_bin_sizes = nullptr;	// Array of bin sizes

static std::set<address_t> g_cached_blocks;	// free blocks
static std::vector<ca_page> g_pages;

// Forward declaration
static bool gdb_symbol_prelude(void);
static bool read_mi_version(void);
static bool parse_thread_local_heap(void);
static bool parse_page(struct value* page_val, int bin_index);
static bool parse_page_queue(struct value* page_queue_val, int bin_index);
static bool parse_abandoned(void);

static ca_page* find_page(address_t addr);
static ca_page* find_next_page(address_t addr);
static bool is_block_cached(address_t);

static void add_one_big_block(struct heap_block *, unsigned int,
    struct heap_block *);

/******************************************************************************
 * Exposed functions
 *****************************************************************************/
static const char *
heap_version(void)
{
	return "mimalloc";
}

static bool
init_heap(void)
{
	// Start with a clean slate
	g_initialized = false;
	g_cached_blocks.clear();
	g_pages.clear();
	g_bin_count = 0;
	delete[] g_bin_sizes;
	g_bin_sizes = nullptr;

	// Start with allocator's version
	read_mi_version();

	// Initialize bin sizes through gv `const mi_heap_t _mi_heap_empty`
	struct symbol* sym = lookup_global_symbol("_mi_heap_empty", nullptr,
		SEARCH_VAR_DOMAIN).symbol;
	if (sym == NULL) {
		CA_PRINT("Failed to lookup gv \"_mi_heap_empty\"\n");
		return false;
	}
	struct value* heap_empty_val = value_of_variable(sym, 0);
	struct value* pages_val = ca_get_field_gdb_value(heap_empty_val, "pages");
	LONGEST low_bound, high_bound;
	if (get_array_bounds (pages_val->type(), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"_mi_heap_empty.pages\" bounds\n");
		return false;
	}
	g_bin_count = high_bound - low_bound + 1;
	g_bin_sizes = new size_t[g_bin_count];
	for (int i = 0; i < g_bin_count; i++) {
		// `_mi_heap_empty.pages` is an array of mi_page_queue_t[g_bin_count]
		struct value* page_queue_val = value_subscript(pages_val, i);
		struct value* block_size_val = ca_get_field_gdb_value(page_queue_val, "block_size");
		g_bin_sizes[i] = value_as_long(block_size_val);
	}

	// Parse thread local heaps
	if (!parse_thread_local_heap()) {
		CA_PRINT("Failed to parse thread local heap\n");
		return false;
	}
	// When thread exits, its heap will be abandoned
	if (!parse_abandoned()) {
		CA_PRINT("Failed to parse abandoned heaps\n");
		return false;
	}

	// Sort pages by start address for future binary search
	std::sort(g_pages.begin(), g_pages.end());

	g_initialized = true;
	return true;
}

static bool
get_heap_block_info(address_t addr, struct heap_block* blk)
{
	if (g_initialized == false) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	// Found the page that contains the block
	ca_page* page = find_page(addr);
	if (page == nullptr)
		return false;

	// Traverse the blocks in the page to find the block that contains the address
	for (address_t block_addr = page->start; block_addr < page->end; block_addr += page->block_size) {
		if (addr >= block_addr && addr < block_addr + page->block_size) {
			blk->addr = block_addr;
			blk->size = page->block_size;
			blk->inuse = !is_block_cached(block_addr);
			return true;
		}
	}
	return false;
}

static bool
get_next_heap_block(address_t addr, struct heap_block* blk)
{
	if (g_initialized == false || g_pages.empty()) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	// If addr is 0, return the first block of the first page
	if (addr == 0) {
		blk->addr = g_pages[0].start;
		blk->size = g_pages[0].block_size;
		blk->inuse = !is_block_cached(blk->addr);
		return true;
	}

	// Find the page that contains the address
	ca_page* page = find_page(addr);
	if (page) {
		// If the next block in the same page is valid, return it
		if (addr + page->block_size >= page->start && addr + page->block_size < page->end) {
			blk->addr = addr + page->block_size;
			blk->size = page->block_size;
			blk->inuse = !is_block_cached(blk->addr);
			return true;
		} else {
			// If the page is the last page, return false
			if (page == &g_pages.back())
				return false;
			// Otherwise, return the first block of the next page
			page++;
			blk->addr = page->start;
			blk->size = page->block_size;
			blk->inuse = !is_block_cached(blk->addr);
			return true;
		}
	} else {
		// If the address is not in any page,
		// find the next page that has a start address greater than the given address
		page = find_next_page(addr);
		if (page) {
			blk->addr = page->start;
			blk->size = page->block_size;
			blk->inuse = !is_block_cached(blk->addr);
			return true;
		}
	}

	return false;
}

/* Return true if the block belongs to a heap */
static bool
is_heap_block(address_t addr)
{

	if (g_initialized == false) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	return find_page(addr) != nullptr;
}

/*
 * Traverse all pages unless a non-zero address is given, in which case the
 * specific page is walked
 */
static bool
heap_walk(address_t heapaddr, bool verbose)
{
	if (g_initialized == false) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	// If heapaddr is given, find the page that contains the address and display blocks in the page
	if (heapaddr) {
		ca_page* page = find_page(heapaddr);
		if (page) {
			CA_PRINT("Page [%#lx - %#lx], block size: %zu\n", page->start, page->end, page->block_size);
			for (address_t addr = page->start; addr < page->end; addr += page->block_size) {
				bool inuse = !is_block_cached(addr);
				CA_PRINT("\t[%#lx - %#lx] %ld bytes %s\n", addr, addr + page->block_size,
					page->block_size, inuse ? "inuse" : "free");
			}
			return true;
		} else {
			CA_PRINT("No page found for address %p\n", (void*)heapaddr);
			return false;
		}
	}

	// If heapaddr is not given, display all pages and blocks
	std::unique_ptr<ca_bin[]> bins(new ca_bin[g_bin_count]);
	for (const auto& page : g_pages) {
		if (page.bin_index >= 0 && page.bin_index < g_bin_count) {
			bins[page.bin_index].bin_index = page.bin_index;
			bins[page.bin_index].page_count++;
			bins[page.bin_index].block_size = page.block_size;
			for (address_t addr = page.start; addr < page.end; addr += page.block_size) {
				if (is_block_cached(addr))
					bins[page.bin_index].free_blks++;
				else
					bins[page.bin_index].inuse_blks++;
			}
		} else {
			CA_PRINT("Invalid bin index %d for page [%#lx - %#lx]\n", page.bin_index, page.start, page.end);
			return false;
		}
	}

	// Display version and tuning parameters
	CA_PRINT("mimalloc version: %d.%d.%d\n", mi_version_major, mi_version_minor, mi_version_patch);
	CA_PRINT("\tguard page: %s\n", mi_guard_page ? "enabled" : "disabled");
	CA_PRINT("\tencode freelist: %s\n", mi_encode_freelist ? "enabled" : "disabled");
	// Print one blank line
	CA_PRINT("\n");

	// Display statistics
	CA_PRINT("  size_class   num_pages  block_size  inuse_blks inuse_bytes   free_blks  free_bytes\n");
	for (int i = 0; i < g_bin_count; i++) {
		size_t inuse_bytes = bins[i].inuse_blks * bins[i].block_size;
		size_t free_bytes = bins[i].free_blks * bins[i].block_size;
		CA_PRINT("%10d %10zu %10zu %10zu %12zu %10zu %12zu\n",
			i, bins[i].page_count, bins[i].block_size, bins[i].inuse_blks, inuse_bytes, bins[i].free_blks, free_bytes);
	}

	size_t total_inuse_blks = 0;
	size_t total_free_blks = 0;
	size_t total_inuse_bytes = 0;
	size_t total_free_bytes = 0;
	for (int i = 0; i < g_bin_count; i++) {
		total_inuse_blks += bins[i].inuse_blks;
		total_free_blks += bins[i].free_blks;
		total_inuse_bytes += bins[i].inuse_blks * bins[i].block_size;
		total_free_bytes += bins[i].free_blks * bins[i].block_size;
	}
	CA_PRINT("------------------------------------------------------------------------------------\n");
	CA_PRINT("     Total %10zu %10s %10zu %12zu %10zu %12zu\n",
		g_pages.size(), "", total_inuse_blks, total_inuse_bytes, total_free_blks, total_free_bytes);

	return true;
}

static bool
get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	if (g_initialized == false) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	if (num == 0)
		return true;
	memset(blks, 0, num * sizeof *blks);

	// Traverse big blocks (size class MI_BIN_FULL) first and populate the returned array
	for (auto const& page : g_pages) {
		if (page.bin_index == MI_BIN_FULL) {
			for (address_t addr = page.start; addr < page.end; addr += page.block_size) {
				if (!is_block_cached(addr)) {
					struct heap_block blk = {addr, page.block_size, true};
					add_one_big_block(blks, num, &blk);
				}
			}
		}
	}

	// Return if we have enough big blocks
	struct heap_block* smallest = &blks[num - 1];
	if (smallest->size > 0)
		return true;

	// continue to traverse normal blocks (index != MI_BIN_FULL) and populate the returned array
	for (auto const& page : g_pages) {
		if (page.bin_index != MI_BIN_FULL) {
			for (address_t addr = page.start; addr < page.end; addr += page.block_size) {
				if (!is_block_cached(addr) && page.block_size > smallest->size) {
					struct heap_block blk = {addr, page.block_size, true};
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
	if (g_initialized == false) {
		CA_PRINT("mimalloc heap was not initialized successfully\n");
		return false;
	}

	if (opCount == nullptr)
		return false;

	// Traverse all pages and blocks to find inuse blocks
	*opCount = 0;
	for (const auto& page : g_pages) {
		for (address_t addr = page.start; addr < page.end; addr += page.block_size) {
			if (!is_block_cached(addr)) {
				(*opCount)++;
				if (opBlocks) {
					opBlocks->addr = addr;
					opBlocks->size = page.block_size;
					opBlocks++;
				}
			}
		}
	}
	return true;
}


static CoreAnalyzerHeapInterface sMiMallHeapManager = {
   heap_version,
   init_heap,
   heap_walk,
   is_heap_block,
   get_heap_block_info,
   get_next_heap_block,
   get_biggest_blocks,
   walk_inuse_blocks,
};

void register_mi_malloc_v2() {
	bool my_heap = gdb_symbol_prelude();
    return register_heap_manager("mi v2", &sMiMallHeapManager, my_heap);
}
/******************************************************************************
 * Helper Functions
 *****************************************************************************/
static bool read_mi_version(void)
{
	// hack it by reading the 2nd byte of funciton mi_version()
	struct symbol* sym = lookup_symbol("mi_version", nullptr, SEARCH_FUNCTION_DOMAIN, nullptr).symbol;
	if (sym == nullptr) {
		CA_PRINT_DBG("Failed to lookup function \"mi_version\"\n");
		return false;
	}
	struct value* func_val = value_of_variable(sym, 0);
	address_t func_addr = value_as_address(func_val);
	unsigned char version = 0;
	if (!read_memory_wrapper(nullptr, func_addr + 1, &version, sizeof(version))) {
		CA_PRINT_DBG("Failed to read mi_version at address %p\n", (void*)(func_addr + 1));
		return false;
	}
	mi_version_major = version/100;
	mi_version_minor = (version%100)/10;
	mi_version_patch = version%10;
	CA_PRINT_DBG("Detected mimalloc version: %d.%d.%d\n",
		mi_version_major, mi_version_minor, mi_version_patch);

	return true;
}

static bool parse_page(struct value* page_val, int bin_index)
{
	struct ca_segment *segment;

	CA_PRINT_DBG("\tParsing mi_page_t at address %p for bin index %d\n",
		(void*)(page_val->address()), bin_index);

	// If the page has "keys" field, it means the free list is encoded.
	// We currently don't support parsing encoded free list, so skip this page
	static bool once = false;
	if (!once) {
		struct value* keys_val = ca_get_field_gdb_value(page_val, "keys");
		if (keys_val != nullptr) {
			mi_encode_freelist = true;
			CA_PRINT_DBG("\tmi_page_t has encoded free list\n");
		}
		once = true;
	}

	// Calculate address of the blocks in the page
	struct value* page_start_val = ca_get_field_gdb_value(page_val, "page_start");
	struct value* capacity_val = ca_get_field_gdb_value(page_val, "capacity");
	struct value* block_size_val = ca_get_field_gdb_value(page_val, "block_size");
	if (page_start_val == nullptr || capacity_val == nullptr || block_size_val == nullptr) {
		CA_PRINT("Failed to get fields of mi_page_t: page_start, capacity, block_size\n");
		return false;
	}
	address_t block_start = value_as_address(page_start_val);
	size_t capacity = value_as_long(capacity_val);
	size_t block_size = value_as_long(block_size_val);
	if (block_start == 0 || block_size == 0 || capacity == 0) {
		CA_PRINT("Invalid block_start, block_size or capacity in mi_page_t\n");
		return false;
	}
	address_t block_end = block_start + block_size * capacity;
	// Get the free blocks in the page
	// include mi_page_t::free, mi_page_t::local_free and mi_page_t::xthread_free
	size_t free_blk_count = 0;
	struct value* free_val = ca_get_field_gdb_value(page_val, "free");
	address_t block_addr = value_as_address(free_val);
	while (block_addr != 0) {
		if (block_addr < block_start || block_addr >= block_end) {
			CA_PRINT("Invalid free block address %p in mi_page_t\n", (void*)block_addr);
			return false;
		}
		g_cached_blocks.insert(block_addr);
		free_blk_count++;

		// read the next pointer in the free list
		if (!read_memory_wrapper(nullptr, block_addr, &block_addr, sizeof(block_addr))) {
			CA_PRINT("Failed to read free block at address %p\n", (void*)block_addr);
			return false;
		}
	}
	size_t local_free_blk_count = 0;
	struct value* local_free_val = ca_get_field_gdb_value(page_val, "local_free");
	block_addr = value_as_address(local_free_val);
	while (block_addr != 0) {
		if (block_addr < block_start || block_addr >= block_end) {
			CA_PRINT("Invalid local free block address %p in mi_page_t\n", (void*)block_addr);
			return false;
		}
		g_cached_blocks.insert(block_addr);
		local_free_blk_count++;

		// read the next pointer in the local free list
		if (!read_memory_wrapper(nullptr, block_addr, &block_addr, sizeof(block_addr))) {
			CA_PRINT("Failed to read local free block at address %p\n", (void*)block_addr);
			return false;
		}
	}
	size_t xthread_free_blk_count = 0;
	struct value* xthread_free_val = ca_get_field_gdb_value(page_val, "xthread_free");
	block_addr = value_as_address(xthread_free_val);
	// bottom 2 bits of the pointer for mi_delayed_t flags
	block_addr &= ~0x3;
	while (block_addr != 0) {
		if (block_addr < block_start || block_addr >= block_end) {
			CA_PRINT("Invalid xthread free block address %p in mi_page_t %p\n", (void*)block_addr, (void*)page_val->address());
			return false;
		}
		g_cached_blocks.insert(block_addr);
		xthread_free_blk_count++;

		// read the next pointer in the xthread free list
		if (!read_memory_wrapper(nullptr, block_addr, &block_addr, sizeof(block_addr))) {
			CA_PRINT("Failed to read xthread free block at address %p\n", (void*)block_addr);
			return false;
		}
		block_addr &= ~0x3;
	}

	// Check the free block count against the page used and capacity
	// `used + |free| + |local_free| == capacity`
	// actual blocks that are in use (alive) == `used - |xthread_free|`
	struct value* used_val = ca_get_field_gdb_value(page_val, "used");
	size_t used_blk_count = value_as_long(used_val);
	if (used_blk_count + free_blk_count + local_free_blk_count != capacity) {
		CA_PRINT_DBG("Invalid used or free block count in mi_page_t: used %zu + free %zu + local_free %zu != capacity %zu\n",
			used_blk_count, free_blk_count, local_free_blk_count, capacity);
	}

	// Adjust bin index if necessary
	if (bin_index == 0) {
		// index 0 is not used, calculate the appropriate bin index by block size
		for (int i = g_bin_count-1; i >= 0; i--) {
			if (block_size >= g_bin_sizes[i]) {
				bin_index = i;
				break;
			}
		}
	}

	// Add the page to the global page list for future reference
	ca_page page = { page_val->address(), block_start, block_end, block_size, bin_index };
	g_pages.push_back(page);

	// update the segment that the page belongs to
	segment = get_segment(block_start, block_end - block_start);
	if (segment && segment->m_type == ENUM_UNKNOWN) {
		segment->m_type = ENUM_HEAP;
	}
	return true;
}

static bool parse_page_queue(struct value* page_queue_val, int bin_index)
{
	struct value* first_val = ca_get_field_gdb_value(page_queue_val, "first");
	struct value* page = first_val;
	while (page && value_as_address(page) != 0) {
		page = value_ind(page);
		if (!parse_page(page, bin_index)) {
			CA_PRINT("Failed to parse mi_page_t at address %p\n", (void*)value_as_address(page));
			return false;
		}
		// Get the next page in the queue
		page = ca_get_field_gdb_value(page, "next");
	}

	return true;
}

static int thread_local_heap (struct thread_info *info, void *data)
{
	struct symbol *sym;
	struct value *thread_heap_p, *thread_heap;

	switch_to_thread (info);

	// __thread mi_heap_t* _mi_heap_default
	sym = lookup_global_symbol("_mi_heap_default", nullptr,
		SEARCH_VAR_DOMAIN).symbol;
	if (sym == NULL) {
		CA_PRINT("Failed to lookup gv \"_mi_heap_default\"\n");
		return false;
	}
	thread_heap_p = value_of_variable(sym, 0);
	CA_PRINT_DBG("Thread %d: _mi_heap_default at address %p\n", info->global_num, (void*)value_as_address(thread_heap_p));
	thread_heap = value_ind(thread_heap_p);

	// If the heap has "guarded_size_min" field, it means the heap has guard page enabled
	static bool once = false;
	if (!once) {
		struct value* guarded_size_min_val = ca_get_field_gdb_value(thread_heap, "guarded_size_min");
		if (guarded_size_min_val) {
			mi_guard_page = true;
		}
		once = true;
	}

	// Traverse heap list
	while (thread_heap)
	{
		CA_PRINT_DBG("Process heap at address %p\n", (void*)thread_heap->address());
		struct value* page_count_val = ca_get_field_gdb_value(thread_heap, "page_count");
		if (page_count_val && value_as_long(page_count_val) > 0) {
			// Field "pages" is an array of mi_page_queue_t
			struct value* pages_val = ca_get_field_gdb_value(thread_heap, "pages");
			for (int index = 0; index < g_bin_count; index++) {
				struct value *val = value_subscript(pages_val, index);
				if (parse_page_queue(val, index) == false) {
					CA_PRINT("Failed to parse mi_page_queue_t at index %d\n", index);
					break;
				}
			}
		}
		// mi_heap_t::thread_delayed_free is a list of delayed free blocks.
		struct value* delayed_free_val = ca_get_field_gdb_value(thread_heap, "thread_delayed_free");
		address_t block_addr = value_as_address(delayed_free_val);
		while (block_addr != 0) {
			g_cached_blocks.insert(block_addr);
			// Assume singly linked list
			if (!read_memory_wrapper(nullptr, block_addr, &block_addr, sizeof(block_addr))) {
				CA_PRINT("Failed to read mi_heap_t::thread_delayed_free at address %p\n", (void*)block_addr);
				break;
			}
		}

		// next heap
		struct value* heap_next = ca_get_field_gdb_value(thread_heap, "next");
		if (heap_next == nullptr || value_as_address(heap_next) == 0)
			thread_heap = nullptr;
		else
			thread_heap = value_ind(heap_next);
	}

	return 0;
}

static bool parse_thread_local_heap(void)
{
	struct thread_info* old;
	// Traverse all threads for thread-local variables `_mi_heap_default`
	// remember current thread
	old = inferior_thread();
	// switch to all threads
	iterate_over_threads(thread_local_heap, NULL);
	// resume the old thread
	switch_to_thread (old);

	return true;
}

static void add_one_big_block(struct heap_block *blks, unsigned int num,
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

static bool parse_segment(struct value* segment_val)
{
	// filed "slices[MI_SLICES_PER_SEGMENT+1]" is an array of mi_slice_t,
	// which are candidates for pages.
	struct value* slices_val = ca_get_field_gdb_value(segment_val, "slices");
	if (slices_val == nullptr) {
		CA_PRINT("Failed to get field \"slices\" of mi_segment_t\n");
		return false;
	}
	LONGEST low_bound, high_bound;
	if (get_array_bounds (slices_val->type(), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"slices\" bounds\n");
		return false;
	}
	for (LONGEST index = low_bound; index <= high_bound; index++) {
		// slice is a page under disguise "typedef mi_page_t  mi_slice_t;"
		struct value* page_val = value_subscript(slices_val, index);
		// For a real page, fields slice_count!=0 and slice_offset==0 and page_start!=0
		// We can use this to filter out the slices that are not real pages.
		struct value* slice_count_val = ca_get_field_gdb_value(page_val, "slice_count");
		struct value* slice_offset_val = ca_get_field_gdb_value(page_val, "slice_offset");
		struct value* page_start_val = ca_get_field_gdb_value(page_val, "page_start");
		if (!slice_count_val || !slice_offset_val || !page_start_val) {
			CA_PRINT("Failed to get fields of mi_slice_t: slice_count, slice_offset or page_start\n");
			continue;
		} else if (value_as_long(slice_count_val) == 0 || value_as_long(slice_offset_val) != 0 || value_as_address(page_start_val) == 0) {
			continue;
		}
		if (!parse_page(page_val, 0)) {
			CA_PRINT("Failed to parse mi_slice_t at index %ld as mi_page_t\n", index);
			continue;
		}
	}
	return true;
}

static bool parse_abandoned(void)
{
	// Starts with gv "mi_arenas[MI_MAX_ARENAS]"
	// When pages/segments are abandoned, they are detached from thread local data.
	// But they are still reachable from the global arena, which mark them in a bitmap
	struct symbol *sym = lookup_symbol("mi_arenas", nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"mi_arenas\"\n");
		return false;
	}
	struct value* mi_arenas_val = value_of_variable(sym, 0);
	LONGEST low_bound, high_bound;
	if (get_array_bounds (mi_arenas_val->type(), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"mi_arenas\" bounds\n");
		return false;
	}
	unsigned int mi_arenas_len = high_bound - low_bound + 1;
	// Get gv "mi_arena_count", which is the actual number of arenas in use (can be less than MI_MAX_ARENAS)
	sym = lookup_symbol("mi_arena_count", nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol;
	if (sym == nullptr) {
		CA_PRINT("Failed to lookup gv \"mi_arena_count\"\n");
		return false;
	}
	struct value* mi_arena_count_val = value_of_variable(sym, 0);
	size_t mi_arena_count = value_as_long(mi_arena_count_val);
	if (mi_arena_count > mi_arenas_len) {
		CA_PRINT("Invalid mi_arena_count %zu greater than mi_arenas array length %u\n",
			mi_arena_count, mi_arenas_len);
		return false;
	}
	// Traverse mi_arenas array and find the arenas in use (with non-nullptr value)
	for (unsigned int index = 0; index < mi_arena_count; index++) {
		struct value *val = value_subscript(mi_arenas_val, index);
		if (value_as_address(val)) {
			val = value_ind(val);
			// Get field "field_count", which is the size of the bitmap
			struct value* field_count_val = ca_get_field_gdb_value(val, "field_count");
			if (field_count_val == nullptr) {
				CA_PRINT("Failed to get field \"field_count\" of mi_arenas[%d]\n", index);
				return false;
			}
			size_t field_count = value_as_long(field_count_val);
			size_t bitmap_size = field_count * sizeof(mi_bitmap_field_t);
			unsigned char* bitmap = new unsigned char[bitmap_size];
			// Get field "blocks_abandoned", which is the bitmap for abandoned segments
			struct value* blocks_abandoned_val = ca_get_field_gdb_value(val, "blocks_abandoned");
			if (blocks_abandoned_val == nullptr) {
				CA_PRINT("Failed to get field \"blocks_abandoned\" of mi_arenas[%d]\n", index);
				delete[] bitmap;
				return false;
			}
			if (!read_memory_wrapper(nullptr, value_as_address(blocks_abandoned_val), bitmap, bitmap_size)) {
				CA_PRINT("Failed to read blocks_abandoned bitmap of mi_arenas[%d] at address %p\n",
					index, (void*)value_as_address(blocks_abandoned_val));
				delete[] bitmap;
				return false;
			}
			// Get the start address with field "start"
			struct value* start_val = ca_get_field_gdb_value(val, "start");
			if (start_val == nullptr) {
				CA_PRINT("Failed to get field \"start\" of mi_arenas[%d]\n", index);
				delete[] bitmap;
				return false;
			}
			address_t start_addr = value_as_address(start_val);
			// Traverse the bitmap, for any bit set, it means the corresponding segment is abandoned,
			// and we can calculate the segment address by start address + index * MI_ARENA_BLOCK_SIZE
			//
			// First get the type of "mi_segment_t*"" for future use in value_at() through gv "mi_subproc_default"
			struct symbol* mi_subproc_default_sym = lookup_symbol("mi_subproc_default", nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol;
			if (mi_subproc_default_sym == nullptr) {
				CA_PRINT("Failed to lookup gv \"mi_subproc_default\"\n");
				delete[] bitmap;
				return false;
			}
			struct value* mi_subproc_default_val = value_of_variable(mi_subproc_default_sym, 0);
			struct value* abandoned_os_list_val = ca_get_field_gdb_value(mi_subproc_default_val, "abandoned_os_list");
			if (abandoned_os_list_val == nullptr) {
				CA_PRINT("Failed to get field \"abandoned_os_list\" of mi_subproc_default\n");
				delete[] bitmap;
				return false;
			}
			struct type* mi_segment_type = value_ind(abandoned_os_list_val)->type();

			for (size_t bit_index = 0; bit_index < bitmap_size * 8; bit_index++) {
				size_t byte_index = bit_index / 8;
				size_t bit_offset = bit_index % 8;
				if (bitmap[byte_index] & (1 << bit_offset)) {
					address_t block_addr = start_addr + bit_index * MI_ARENA_BLOCK_SIZE;
					// Parse the abandoned segment
					struct value* segment_val = value_at(mi_segment_type, block_addr);
					if (segment_val == nullptr) {
						CA_PRINT("Failed to create value for mi_segment_t at address %p\n", (void*)block_addr);
						continue;
					}
					if (!parse_segment(segment_val)) {
						CA_PRINT("Failed to parse mi_segment_t at address %p\n", (void*)block_addr);
						continue;
					}
				}
			}
		}
	}

	return true;
}

static bool gdb_symbol_prelude(void)
{
	// static __attribute__((aligned(64))) mi_arena_t* mi_arenas[MI_MAX_ARENAS];
	struct symbol *sym = lookup_symbol("mi_arenas", nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol;
	if (sym == nullptr) {
		CA_PRINT_DBG("Failed to lookup gv \"mi_arenas\"\n");
		return false;
	}
	return true;
}

static bool is_block_cached(address_t addr)
{
	auto itr = g_cached_blocks.find(addr);
	return itr != g_cached_blocks.end();
}

static ca_page* find_next_page(address_t addr)
{
	// Found the next page after the address
	auto page_itr = std::upper_bound(g_pages.begin(), g_pages.end(), addr, [](const address_t& pageaddr, const ca_page& page) {
		return pageaddr < page.start;
	});
	if (page_itr == g_pages.end())
		return nullptr;
	return &(*page_itr);
}

static ca_page* find_page(address_t addr)
{
	// Found the page that contains the block
	auto page_itr = std::upper_bound(g_pages.begin(), g_pages.end(), addr, [](const address_t& pageaddr, const ca_page& page) {
		return pageaddr < page.start;
	});
	if (page_itr == g_pages.begin())
		return nullptr;
	page_itr--;
	if (addr < page_itr->start || addr >= page_itr->end)
		return nullptr;
	return &(*page_itr);
}
