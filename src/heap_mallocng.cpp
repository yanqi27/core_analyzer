/*
 * heap_mallocng.c
 *
 *  Created on: Feb 15, 2022
 *      Author: gamingrobot
 */
#include "heap_mallocng.h"
#include "segment.h"


#define CA_DEBUG 1
#if CA_DEBUG
#define CA_PRINT_DBG CA_PRINT
#else
#define CA_PRINT_DBG(format,args...)
#endif


/*
 * Internal data structures
 */


/*
 * Globals
 */
static bool g_initialized = false;

static struct ca_meta *g_metas;
static unsigned long g_metas_capacity;
static unsigned long g_metas_count;

/*
 * Forward declaration
 */
static struct value *get_field_value(struct value *, const char *);
bool walk_active(struct value *malloc_context);
bool parse_meta(struct value *meta, address_t address, struct type *group_type);
bool walk_sizeclass_meta(struct value *head_meta, address_t head_address, struct type* meta_type, struct type *group_type);
static int meta_storage_compare(const void *, const void *);
	
/******************************************************************************
 * Exposed functions
 *****************************************************************************/
const char *
heap_version(void)
{
	return "mallocng";
}

bool
init_heap(void)
{
	struct symbol *malloc_context_;
	struct value *malloc_context;
	struct value *mmap_counter_val;
	struct value *init_done_val;
	unsigned long i;

	CA_PRINT_DBG("init_heap()\n");
	/*
	 * Start with a clean slate
	 */
	g_initialized = false;
	for (i = 0; i < g_metas_count; i++)
	{
		struct ca_meta *meta = &g_metas[i];
		memset(meta, 0, sizeof *meta);
	}
	g_metas_count = 0;

	malloc_context_ = lookup_global_symbol("__malloc_context", 0,
	    VAR_DOMAIN).symbol;
	if (malloc_context_ == NULL) {
		CA_PRINT("Failed to lookup gv "
		    "\"__malloc_context\"\n");
		return false;
	}
	malloc_context = value_of_variable(malloc_context_, 0);

	init_done_val = get_field_value(malloc_context, "init_done");
	if(value_as_long(init_done_val) == 0){
		CA_PRINT("malloc_context not initalized! \n");
		return false;
	}

	if(!walk_active(malloc_context))
	{
		CA_PRINT("Failed to walk active metas! \n");
		return false;
	}

	//sort meta's by storage address
	qsort(g_metas, g_metas_count, sizeof(*g_metas), meta_storage_compare);

	//TODO verify sorted

	CA_PRINT_DBG("%ld metas are found\n", g_metas_count);
	for (i = 0; i < g_metas_count; i++) {
		struct ca_meta *meta = &g_metas[i];

		CA_PRINT_DBG("[%ld] {\n"
		    "\taddress 0x%lx\n"
		    "\tavail_mask %u\n"
		    "\tfreed_mask %u\n"
		    "\tinuse_mask %u\n"
		    "\tlast_slot_count %d\n"
		    "\tactive_slot_count %d\n"
		    "\tfreeable %d\n"
		    "\tsize_class %d\n"
		    "\tmaplen %d\n"
		    "\tstorage_start 0x%lx\n"
		    "}\n",
		    i, meta->address, meta->avail_mask, meta->freed_mask,
			meta->inuse_mask, meta->last_slot_count, meta->active_slot_count, meta->freeable, 
			meta->size_class, meta->maplen, meta->storage_start);
	}

	CA_PRINT("mallocng heap is initialized successfully\n");
	g_initialized = true;
	return true;
}

bool
get_heap_block_info(address_t addr, struct heap_block* blk)
{
	CA_PRINT_DBG("get_heap_block_info(" PRINT_FORMAT_POINTER ")\n", addr);

	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}

	return true;
}

bool
get_next_heap_block(address_t addr, struct heap_block* blk)
{
	CA_PRINT_DBG("get_next_heap_block(" PRINT_FORMAT_POINTER ")\n", addr);

	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}

	return true;
}

/* Return true if the block belongs to a heap */
bool
is_heap_block(address_t addr)
{
	CA_PRINT_DBG("is_heap_block(" PRINT_FORMAT_POINTER ")\n", addr);

	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}

	return true;
}

/*
 * Traverse all metas unless a non-zero address is given, in which case the
 * specific meta is walked
 */
bool
heap_walk(address_t heapaddr, bool verbose)
{
	CA_PRINT_DBG("heap_walk(" PRINT_FORMAT_POINTER ")\n", heapaddr);

	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}

	return true;
}

bool
get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	CA_PRINT_DBG("get_biggest_blocks()\n");
	
	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}
	
	return true;
}

bool
walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	CA_PRINT_DBG("walk_inuse_blocks()\n");

	unsigned long i;
	struct ca_meta *meta;

	if (g_initialized == false) {
		CA_PRINT("mallocng heap was not initialized successfully\n");
		return false;
	}

	*opCount = 0;
	for (i = 0; i < g_metas_count; i++) {
		meta = &g_metas[i];

		//TODO: handle nested meta's, it maplen is 0 if its nested in another groups slot
		if(meta->maplen == 0)
		{
			CA_PRINT_DBG("Skipping nested meta at: " PRINT_FORMAT_POINTER "\n", meta->address);
			continue;
		}

		address_t base = meta->storage_start;
		unsigned int index;
		size_t slot_size = UNIT*class_to_size[meta->size_class];

		for (index = 0; index < meta->active_slot_count; index++)
		{
			if (meta->inuse_mask & (1 << index)) {
				//TODO calculate size as slot_size - reserved?
				(*opCount)++;
				if (opBlocks != NULL) {
					address_t slot_addr = base + slot_size * index;
					CA_PRINT_DBG("Meta: 0x%lx Slot: %d Address: 0x%lx Size: %d\n", meta->address, index, slot_addr, slot_size);
					opBlocks->addr = slot_addr;
					opBlocks->size = slot_size;
					opBlocks++;
				}
			}
		}
	}

	return true;
}

/******************************************************************************
 * Helper Functions
 *****************************************************************************/
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
		CA_PRINT("Failed to find member \"%s\"\n", field_name);
		return NULL;
	}
	return value_field(val, fieldno);
}

int
meta_storage_compare(const void *k, const void *m)
{
	const struct ca_meta *k_meta = (const struct ca_meta *)k;
	const struct ca_meta *m_meta = (const struct ca_meta *)m;

	return (k_meta->storage_start > m_meta->storage_start) - (m_meta->storage_start > k_meta->storage_start);
}


bool walk_active(struct value *malloc_context)
{
	struct type *meta_type, *group_type;
	struct value *active;
	LONGEST low_bound, high_bound, index;

	meta_type = lookup_transparent_type("meta");
	if (meta_type == NULL) {
		CA_PRINT("Failed to lookup type \"meta\"\n");
		CA_PRINT("Do you forget to load debug symbols?\n");
		return false;
	}
	CA_PRINT_DBG("current meta type \"%d\"\n", TYPE_CODE (meta_type));
	meta_type = lookup_pointer_type(meta_type);
	CA_PRINT_DBG("current meta pointer type \"%d\"\n", TYPE_CODE (meta_type));

	group_type = lookup_transparent_type("group");
	if (group_type == NULL) {
		CA_PRINT("Failed to lookup type \"group\"\n");
		CA_PRINT("Do you forget to load debug symbols?\n");
		return false;
	}
	CA_PRINT_DBG("current group type \"%d\"\n", TYPE_CODE (group_type));
	group_type = lookup_pointer_type(group_type);
	CA_PRINT_DBG("current group pointer type \"%d\"\n", TYPE_CODE (group_type));

	//array of head meta's per sizeclass
	active = get_field_value(malloc_context, "active"); //malloc_context->active
	if (TYPE_CODE (value_type(active)) != TYPE_CODE_ARRAY) {
		CA_PRINT("Unexpected: \"active\" is not an array\n");
		return false;
	}

	if (get_array_bounds (value_type(active), &low_bound, &high_bound) == 0) {
		CA_PRINT("Could not determine \"active\" bounds\n");
		return false;
	}
	CA_PRINT_DBG("malloc_context.active[%ld-%ld] array "
	    "length %ld\n", low_bound, high_bound, high_bound - low_bound + 1);

	for (index = low_bound; index <= high_bound; index++) {
		struct value *v, *meta_p, *meta;
		address_t value_address;

		v = value_subscript(active, index); //active[index]
		CA_PRINT_DBG("current active index \"%d\"\n", index);
		CA_PRINT_DBG("current active type \"%d\"\n", TYPE_CODE (value_type(v)));
		CA_PRINT_DBG("current active address " PRINT_FORMAT_POINTER "\n", value_as_address(v));
		value_address = value_as_address(v); 
		if (value_address == 0)
			continue;

		meta_p = value_cast(meta_type, v);
		meta = value_ind(meta_p); //*meta

		if (!walk_sizeclass_meta(meta, value_address, meta_type, group_type))
		{
			CA_PRINT("Could not parse head meta at: " PRINT_FORMAT_POINTER "\n", value_address);
			return false;
		}
	}
	return true;
}

bool walk_sizeclass_meta(struct value *head_meta, address_t head_address, struct type *meta_type, struct type *group_type)
{
	struct ca_meta *current;
	struct value *next_p, *next;
	address_t next_address;

	//head meta
	if(!parse_meta(head_meta, head_address, group_type))
	{
		CA_PRINT("Could not parse head meta\n");
		return false;
	}

	//get head meta
	current = &g_metas[g_metas_count-1];
	while(true) //gross
	{
		next_address = value_as_address(current->next);
		if(next_address == head_address)
		{
			break;
		}
		next_p = value_cast(meta_type, current->next);
		next = value_ind(next_p); //*meta

		if(!parse_meta(next, next_address, group_type))
		{
			CA_PRINT("Could not parse meta\n");
			return false;
		}
		current = &g_metas[g_metas_count-1];
	}

	return true;
}


bool parse_meta(struct value *meta, address_t address, struct type *group_type)
{
	struct ca_meta *my_meta;
	struct value *m, *m_p, *group;

	if (g_metas_count >= g_metas_capacity) {
		unsigned long goal;

		if (g_metas_capacity == 0)
			goal = 1024;
		else
			goal = g_metas_capacity * 2;
		g_metas = (struct ca_meta *)realloc(g_metas, goal * sizeof(struct ca_meta));
		if (g_metas == NULL)
			return false;
		g_metas_capacity = goal;
	}

	my_meta = &g_metas[g_metas_count++];
	memset(my_meta, 0, sizeof *my_meta);

	my_meta->address = address;
	CA_PRINT("Parsing meta at: " PRINT_FORMAT_POINTER "\n", address);

	m = get_field_value(meta, "next");
	my_meta->next = value_copy(m);

	m = get_field_value(meta, "prev");
	my_meta->prev = value_copy(m);

	m = get_field_value(meta, "avail_mask");
	my_meta->avail_mask = value_as_long(m);
	CA_PRINT_DBG("meta.avail_mask \"0x%x\"\n", my_meta->avail_mask);

	m = get_field_value(meta, "freed_mask");
	my_meta->freed_mask = value_as_long(m);
	CA_PRINT_DBG("meta.freed_mask \"0x%x\"\n", my_meta->freed_mask);

	my_meta->inuse_mask = ~(my_meta->avail_mask | my_meta->freed_mask);
	CA_PRINT_DBG("meta.inuse_mask \"0x%x\"\n", my_meta->inuse_mask);

	m = get_field_value(meta, "freeable");
	my_meta->freeable = value_as_long(m);
	CA_PRINT_DBG("meta.freeable \"%d\"\n", my_meta->freeable);

	m = get_field_value(meta, "sizeclass");
	my_meta->size_class = value_as_long(m);
	CA_PRINT_DBG("meta.size_class \"%d\"\n", my_meta->size_class);

	m = get_field_value(meta, "maplen");
	my_meta->maplen = value_as_long(m);
	CA_PRINT_DBG("meta.maplen \"%d\"\n", my_meta->maplen);

	m = get_field_value(meta, "last_idx");
	my_meta->last_slot_count = value_as_long(m);
	CA_PRINT_DBG("meta.last_slot_count \"%d\"\n", my_meta->last_slot_count);

	m = get_field_value(meta, "mem"); //group
	m_p = value_cast(group_type, m);
	group = value_ind(m_p);

	m = get_field_value(group, "storage"); //group->storage
	my_meta->storage_start = value_as_long(m);
	CA_PRINT_DBG("meta.storage_start " PRINT_FORMAT_POINTER "\n", my_meta->storage_start);

	m = get_field_value(group, "active_idx"); //group->active_idx
	my_meta->active_slot_count = value_as_long(m);
	CA_PRINT_DBG("meta.active_slot_count \"%d\"\n", my_meta->active_slot_count);

	return true;


}