/*
 * gdbplus_dep.c
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "segment.h"
#include "heap.h"
#include "search.h"
#include "stl_container.h"
#include "decode.h"

#ifdef linux
#include <elf.h>
#endif

#include <sys/param.h>
#include "dis-asm.h"
#include "readline/readline.h"

#ifndef PN_XNUM
#define PN_XNUM 0xffff
#endif

/* True if target is a dump file, false for live process */
bool g_debug_core = false;

/* Target's bit mode, 32 or 64 */
unsigned int g_ptr_bit = 64;

/* Currently seleceted thread/frame */
struct ca_debug_context g_debug_context = {0, 0, 0, NULL};

static int g_rsp_regnum = -1;

static bool g_quit = false;

/*
 * Exposed helper
 */
bool
inferior_memory_read (address_t addr, void* buffer, size_t sz)
{
	if (target_read_memory(addr, (gdb_byte *)buffer, sz) == 0)
		return true;
	else
		return false;
}

static int
thread_callback (struct thread_info *info, void *data)
{
	address_t rsp = 0;
	struct regcache *regcache = get_thread_regcache (info->ptid);

	if (regcache)
		regcache_raw_read_unsigned (regcache, g_rsp_regnum, &rsp);

	if (rsp)
	{
		struct ca_segment* segment = get_segment(rsp, 1);
		if (segment)
		{
			segment->m_type   = ENUM_STACK;
			segment->m_thread.tid = info->per_inf_num;
			segment->m_thread.lwp = info->ptid.lwp();
			segment->m_thread.context = info;
			if (segment->m_thread.tid == 1 && segment->m_vsize > 2*1024*1024)
			{
				segment->m_fsize = segment->m_vsize = 1024*1024;
			}
		}
	}
	return 0;
}

static int
mmap_core_file(const char* fname)
{
	struct stat lStatBuf;
	size_t mFileSize;
	int mFileDescriptor;
	char* mpStartAddr;
	int total_phnum;
	int i, n;

	if (!fname)
		return false;
	/* stat the core file */
	if (stat(fname, &lStatBuf))
		return false;
	gdb_assert(lStatBuf.st_size > 0);
	mFileSize = lStatBuf.st_size;
	/* open core file */
	mFileDescriptor = open(fname, O_RDONLY);
	if (mFileDescriptor == -1)
		return false;
	/* mmap core file */
	mpStartAddr = (char*) mmap(0, mFileSize, PROT_READ, MAP_PRIVATE, mFileDescriptor, 0);
	if(mpStartAddr == MAP_FAILED)
		return false;

	/* walk through the mmap-ed core file and fix the corresponding ca_segments */
	if (g_ptr_bit == 64)
	{
		Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)mpStartAddr;
		if (elfhdr->e_phnum == PN_XNUM)
		{
			Elf64_Shdr* shdr = (Elf64_Shdr*)(mpStartAddr + elfhdr->e_shoff);
			total_phnum = shdr->sh_info;
		}
		else
			total_phnum = elfhdr->e_phnum;
		for(i=0; i<total_phnum; i++)
		{
			Elf64_Phdr* phdr = (Elf64_Phdr*) (mpStartAddr + elfhdr->e_phoff + i * elfhdr->e_phentsize);
			if (phdr->p_type == PT_LOAD && phdr->p_filesz > 0
				&& phdr->p_offset + phdr->p_filesz <= mFileSize) /* aware of truncated core */
			{
				for (n=0; n<g_segment_count; n++)
				{
					struct ca_segment* segment = &g_segments[n];
					if (phdr->p_vaddr == segment->m_vaddr && phdr->p_memsz == segment->m_vsize)
					{
						segment->m_fsize = phdr->p_filesz;
						segment->m_faddr = mpStartAddr + phdr->p_offset;
						break;
					}
				}
			}
		}
	}
	else
	{
		Elf32_Ehdr* elfhdr = (Elf32_Ehdr*)mpStartAddr;
		if (elfhdr->e_phnum == PN_XNUM)
		{
			Elf32_Shdr* shdr = (Elf32_Shdr*)(mpStartAddr + elfhdr->e_shoff);
			total_phnum = shdr->sh_info;
		}
		else
			total_phnum = elfhdr->e_phnum;
		for(i=0; i<total_phnum; i++)
		{
			Elf32_Phdr* phdr = (Elf32_Phdr*) (mpStartAddr + elfhdr->e_phoff + i * elfhdr->e_phentsize);
			if (phdr->p_type == PT_LOAD && phdr->p_filesz > 0
				&& phdr->p_offset + phdr->p_filesz <= mFileSize) /* aware of truncated core */
			{
				for (n=0; n<g_segment_count; n++)
				{
					struct ca_segment* segment = &g_segments[n];
					if (phdr->p_vaddr == segment->m_vaddr && phdr->p_memsz == segment->m_vsize)
					{
						segment->m_fsize = phdr->p_filesz;
						segment->m_faddr = mpStartAddr + phdr->p_offset;
						break;
					}
				}
			}
		}
	}

	return true;
}

static int
read_mapping (FILE *mapfile,
	      long long *addr,
	      long long *endaddr,
	      char *permissions,
	      long long *offset,
	      char *device, long long *inode, char *filename)
{
  int ret = fscanf (mapfile, "%llx-%llx %s %llx %s %llx",
		    addr, endaddr, permissions, offset, device, inode);

  filename[0] = '\0';
  if (ret > 0 && ret != EOF)
    {
      /* Eat everything up to EOL for the filename.  This will prevent
         weird filenames (such as one with embedded whitespace) from
         confusing this code.  It also makes this code more robust in
         respect to annotations the kernel may add after the filename.

         Note the filename is used for informational purposes
         only.  */
      ret += fscanf (mapfile, "%[^\n]\n", filename);
    }

  return (ret != 0 && ret != EOF);
}

/*
 * For a live process, read the process's memory map from /proc
 * when create is true, build ca_segments
 * when create is false, return true if process's regions haven't changed a bit
 */
static bool
linux_nat_find_memory_regions(bool create)
{
	int pid = ptid_get_pid (inferior_ptid);
	char mapsfilename[MAXPATHLEN];
	FILE *mapsfile;
	long long addr, endaddr, offset, inode;
	char permissions[8], device[8], filename[MAXPATHLEN];
	unsigned int count = 0;

	/* Compose the filename for the /proc memory map, and open it.  */
	sprintf (mapsfilename, "/proc/%d/maps", pid);
	if ((mapsfile = fopen (mapsfilename, "r")) == NULL)
	{
		fprintf_filtered (gdb_stdout, "Could not open %s\n", mapsfilename);
		return false;
	}
	/* Now iterate until end-of-file.  */
	while (read_mapping (mapsfile, &addr, &endaddr, &permissions[0],
		   &offset, &device[0], &inode, &filename[0]))
	{
		int read, write, exec;
		/* Get the segment's permissions.  */
		read = (strchr (permissions, 'r') != 0);
		write = (strchr (permissions, 'w') != 0);
		exec = (strchr (permissions, 'x') != 0);

		if (create)
			add_one_segment(addr, endaddr - addr, read, write, exec);
		else if (count >= g_segment_count
			|| g_segments[count].m_vaddr != addr || g_segments[count].m_vsize != endaddr - addr
			|| g_segments[count].m_read != read || g_segments[count].m_write != write || g_segments[count].m_exec != exec)
		{
			fclose(mapsfile);
			return false;
		}
		count++;
	}
	fclose(mapsfile);

	return true;
}

static void
set_segment_module_type(enum storage_type type,
		address_t low, address_t high, const char* modname)
{
	while (low < high)
	{
		struct ca_segment* segment = get_segment(low, 1);
		if (segment)
		{
			segment->m_type = type;
			segment->m_module_name = strdup(modname);
			low = segment->m_vaddr + segment->m_vsize;
		}
		else
			low += 4096;	 /* system page size */
	}
}

static int
build_segments(void)
{
	unsigned int i;
	struct so_list *so = NULL;	/* link map state variable */
	struct thread_info *tp;
	struct ca_segment* segment;

	/*
	 *  It has been built previously.
	 */
	if (g_segments && g_segment_count)
		release_all_segments();

	g_ptr_bit = gdbarch_ptr_bit(target_gdbarch());
	if (g_ptr_bit != 64 && g_ptr_bit != 32)
	{
		printf_filtered(_("Target's bit mode %d is not supported\n"), g_ptr_bit);
		return false;
	}

	if (target_has_execution)
	{
		if (!linux_nat_find_memory_regions(true))
			printf_filtered(_("No memory segments found\n"));
	}
	else if (core_bfd && core_bfd->xvec->flavour == bfd_target_elf_flavour)
	{
		Elf_Internal_Phdr *phdr = elf_tdata(core_bfd)->phdr;
		g_debug_core = true;
		for (i = 0; i < elf_elfheader(core_bfd)->e_phnum; i++, phdr++)
		{
			if (phdr->p_vaddr && phdr->p_memsz > 0)
			{
				add_one_segment(phdr->p_vaddr, phdr->p_memsz,
							(phdr->p_flags & PF_R) != 0 ? 1 : 0,
							(phdr->p_flags & PF_W) != 0 ? 1 : 0,
							(phdr->p_flags & PF_X) != 0 ? 1 : 0);
			}
		}
		if (mmap_core_file(bfd_get_filename(core_bfd)) == false)
		{
			error (_("Failed to mmap core file %s"), bfd_get_filename(core_bfd));
			return false;
		}
	}
	else
	{
		error (_("Failed to build memory segments"));
		return false;
	}
	/* Verify that segments are sorted by address */
	if (!test_segments(true))
	{
		error (_("Memory segments are not properly sorted"));
		return false;
	}
#if 0
	/*
	 * find/set storage types of segments of shared modules
	 */
	for (so = master_so_list(); so; so = so->next)
	{
		if (so->so_name[0])
		{
			struct target_section *sectptr;
			for (sectptr = so->sections; sectptr < so->sections_end; sectptr++)
			{
				enum storage_type type = ENUM_UNKNOWN;
				if (strcmp (sectptr->the_bfd_section->name, ".data") == 0
					|| strcmp (sectptr->the_bfd_section->name, ".bss") == 0)
					type = ENUM_MODULE_DATA;
				/* .rodata and .text sections are in the same segment */
				else if (strcmp (sectptr->the_bfd_section->name, ".text") == 0
						|| strcmp (sectptr->the_bfd_section->name, ".rodata") == 0)
					type = ENUM_MODULE_TEXT;
				if (type != ENUM_UNKNOWN)
					set_segment_module_type(type, sectptr->addr, sectptr->endaddr, so->so_name);
			}
		}
	}
#endif
	/* Set segments' type by tranversing all target sections */
	if (current_target_sections) {
			struct target_section *p;
			for (p =  current_target_sections->sections;
				p < current_target_sections->sections_end;
				p++) {
				struct bfd_section *psect = p->the_bfd_section;
				bfd *pbfd = psect->owner;
				enum storage_type type = ENUM_UNKNOWN;
				const char *name = bfd_section_name (pbfd, psect);

				if (strcmp (name, ".data") == 0 || strcmp (name, ".bss") == 0) {
					type = ENUM_MODULE_DATA;
				} else if (strcmp (name, ".text") == 0 || strcmp (name, ".rodata") == 0) {
					/* .rodata and .text sections are in the same segment */
					type = ENUM_MODULE_TEXT;
				}
				if (type != ENUM_UNKNOWN)
					set_segment_module_type(type, p->addr, p->endaddr, bfd_get_filename (pbfd));
			}
	}

	/* thread stacks */
	{
		ptid_t old;

		/* set the rsp/esp regnum */
		g_rsp_regnum = gdbarch_sp_regnum (target_gdbarch());
		/* remember current thread */
		old = inferior_ptid;
		/* switch to all threads */
		iterate_over_threads(thread_callback, NULL);
		/* resume the old thread */
		inferior_ptid = old;
		registers_changed ();
	}

	/* alloc buffer for future reference search */
	alloc_bit_vec();

	return true;
}

bool
update_memory_segments_and_heaps(void)
{
	bool rc = true;

	/* reset internal quit flag */
	g_quit = false;

	/* set up thread context */
	{
		/* Get current function's low, pc and high instruction addresses */
		struct frame_info *selected_frame = get_selected_frame (NULL);
		if (selected_frame)
		{
			g_debug_context.frame_level = frame_relative_level(selected_frame);
			g_debug_context.sp = get_frame_sp (selected_frame);
		}
		else
			memset(&g_debug_context, 0, sizeof(g_debug_context));
		g_debug_context.tid = ptid_to_global_thread_id (inferior_ptid);
	}
	/* clear up old types */
	clear_addr_type_map();

	if (g_segments && g_segment_count)
	{
		/*
		 * Don't need to update if target is core file, or live process
		 * didn't change 
		 */
		if (g_debug_core || linux_nat_find_memory_regions(false))
			return true;
		printf_filtered(_("Target process has changed. Rebuild heap information\n"));
		/* release old ca_segments */
		release_all_segments();
	}

	/* make sure this function won't change debug context */
	scoped_restore_current_thread restore_current_thread;
	/* Query Target Process's address space */
	if (!build_segments())
	{
		error(_("Failed to build memory segments"));
		return false;
	}
	/* Probe for heap segments */
	init_heap();

	return rc;
}

int
get_frame_number(const struct ca_segment* segment, address_t addr, int* offset)
{
	int frame;
	address_t sp;
	struct frame_info* fp;
	const struct thread_info* tp = (const struct thread_info*) segment->m_thread.context;

	if (!tp)
		return -1;

	switch_to_thread (tp->ptid);
	/*
	 * find the frame that addr belongs to
	 * start from the innermost frame
	 */
	frame = -1;
	*offset = -1;
	fp = get_current_frame ();
	while (fp)
	{
		sp = get_frame_sp(fp);
		if (addr < sp)
			break;
		frame++;
		*offset = (int)((long)addr - (long)sp);
		fp = get_prev_frame(fp);
	}

	return frame;
}

address_t
get_rsp(const struct ca_segment* segment)
{
	address_t rsp = 0;
	const struct thread_info *info = (const struct thread_info*) segment->m_thread.context;
	struct regcache *regcache = get_thread_regcache (info->ptid);

	if (regcache)
	{
		regcache_raw_read_unsigned (regcache, g_rsp_regnum, &rsp);
		return rsp;
	}
	return 0;
}

/*
 * Get the value of the registers of the thread context
 * If buffer is NULL, return number of registers could be returned
 */
int
read_registers(const struct ca_segment* segment, struct reg_value* regs, int bufsz)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct gdbarch *gdbarch = get_current_arch();
	const int numregs = gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);
	if (regs)
	{
		const struct thread_info *info = (const struct thread_info*) segment->m_thread.context;
		struct regcache *regcache = get_thread_regcache (info->ptid);
		if (regcache)
		{
			if (bufsz >= numregs)
			{
				int i;
				for (i=0; i<numregs; i++)
				{
					ULONGEST val;
					regs[i].reg_num = i;
					regs[i].reg_width = register_size(gdbarch, i);
					if (regs[i].reg_width <= ptr_sz
						&& regcache_cooked_read_unsigned (regcache, i, &val) == REG_VALID)
						regs[i].value = (address_t) val;
					else
						regs[i].value = 0;
				}
				return numregs;
			}
		}
	}
	else
		return numregs;
	return 0;
}

bool
search_registers(const struct ca_segment* segment,
		struct CA_LIST* targets,
		struct CA_LIST* refs)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	int lbFound = false;
	const struct thread_info *info = (const struct thread_info*) segment->m_thread.context;
	struct regcache *regcache = get_thread_regcache (info->ptid);
	if (regcache)
	{
		int i;
		struct gdbarch *gdbarch = get_current_arch();
		const int numregs = gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);
		for (i=0; i<numregs; i++)
		{
			ULONGEST val;
			if (register_size(gdbarch, i) <= ptr_sz
				&& regcache_cooked_read_unsigned (regcache, i, &val) == REG_VALID)
			{
				struct object_range* target;
				ca_list_traverse_start(targets);
				while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
				{
					if (val >= target->low && val < target->high)
					{
						/* this register contains a reference to the target */
						struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
						ref->storage_type  = ENUM_REGISTER;
						ref->where.reg.tid = info->per_inf_num;
						ref->where.reg.reg_num = i;
						ref->where.reg.name    = gdbarch_register_name (gdbarch, i);
						ref->vaddr        = 0;
						ref->value        = val;
						ca_list_push_front(refs, ref);
						lbFound = true;
						break;
					}
				}
			}
		}
	}

	return lbFound;
}

bool
is_heap_object_with_vptr(const struct object_reference* ref,
			 char* name_buf,
			 size_t buf_sz)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	int rs = false;
	address_t addr = ref->where.heap.addr;
	address_t val = 0;
	if (target_read_memory(addr, (gdb_byte *)&val, ptr_sz) == 0 && val)
	{
		struct ca_segment* segment = get_segment(val, 0);
		if (segment && (segment->m_type == ENUM_MODULE_DATA || segment->m_type == ENUM_MODULE_TEXT) )
		{
			/*
			 * the first data belongs to a module's data section, it is likely a vptr
			 * to be sure, check its symbol
			 */
			address_t vptr = val;
			char *name = NULL;
			char *filename = NULL;
			int unmapped = 0;
			int offset = 0;
			int line = 0;
			/* Throw away both name and filename.  */
			struct cleanup *cleanup_chain = make_cleanup (free_current_contents, &name);
			make_cleanup (free_current_contents, &filename);
			if (build_address_symbolic (get_current_arch(), vptr, true /*do_demangle*/,
									&name, &offset,	&filename, &line, &unmapped) == 0)
			{
				if (strncmp(name, "vtable for ", 11) == 0)
				{
					rs = true;
					if (name_buf)
					{
						strncpy(name_buf, name+11, buf_sz);
					}
				}
			}
			do_cleanups (cleanup_chain);
		}
	}
	return rs;
}

/*
 * Type helper funcitons
 */
struct ca_addr_type_pair
{
	address_t addr;
	struct type* type;
	struct symbol* sym;
	unsigned int size;
};

/* FIXME The map should really be a BST instead of an array */
static struct ca_addr_type_pair* addr_type_map = NULL;
static unsigned int addr_type_map_sz = 0;
static unsigned int addr_type_map_buf_sz = 0;

/*
 * return false if the address is already in the map, or invalid params
 */
static bool
add_addr_type(address_t addr, struct type* type, struct symbol* sym)
{
	int i;

	if (sym)
		type = SYMBOL_TYPE(sym);
	if (!type)
		return false;

	check_typedef(type);
	if (TYPE_CODE(type) == TYPE_CODE_PTR || TYPE_CODE(type) == TYPE_CODE_REF)
		type = TYPE_TARGET_TYPE (type);

	/* check duplicate entry */
	for (i = addr_type_map_sz - 1; i >= 0; i--)
	{
		/* The new type is the sub-type of an existing one */
		if (addr >= addr_type_map[i].addr &&
		    addr + TYPE_LENGTH(type) <= addr_type_map[i].addr + addr_type_map[i].size) {
			return true;
		}
		/* The new type is the super-type of an existing one */
		else if (addr_type_map[i].addr >= addr &&
		    addr_type_map[i].addr + addr_type_map[i].size <= addr + TYPE_LENGTH(type)) {
			addr_type_map[i].addr = addr;
			addr_type_map[i].type = type;
			addr_type_map[i].sym  = sym;
			addr_type_map[i].size = TYPE_LENGTH(type);
			return true;
		}
	}
	/* expand buffer if necessary */
	if (addr_type_map_sz >= addr_type_map_buf_sz)
	{
		if (addr_type_map_buf_sz == 0)
			addr_type_map_buf_sz = 64;
		else
			addr_type_map_buf_sz = addr_type_map_buf_sz * 2;
		addr_type_map = (struct ca_addr_type_pair *)
		    realloc(addr_type_map, addr_type_map_buf_sz * sizeof(struct ca_addr_type_pair));
	}
	/* append the newly-discovered type */
	addr_type_map[addr_type_map_sz].addr = addr;
	addr_type_map[addr_type_map_sz].type = type;
	addr_type_map[addr_type_map_sz].sym = sym;
	addr_type_map[addr_type_map_sz].size = TYPE_LENGTH(type);
	addr_type_map_sz++;

	return true;
}

/* find a symbol or type associated with given address */
static struct ca_addr_type_pair*
lookup_type_by_addr(address_t addr)
{
	int i;
	/* pick up the latest first */
	for (i=addr_type_map_sz-1; i>=0; i--)
	{
		if (addr >= addr_type_map[i].addr
			&& addr < addr_type_map[i].addr + addr_type_map[i].size)
			return &addr_type_map[i];
	}
	return NULL;
}

/*
 * return the type of a struct's sub field, located exactly at offset
 * if nested structs exist, drill down to the last non-struct field
 */
struct type*
get_struct_field_type_and_name(struct type *basetype,
			       size_t offset, int lea, char* namebuf,
			       size_t bufsz, int* is_vptr)
{
	*namebuf = '\0';
	check_typedef (basetype);

	if (TYPE_CODE(basetype) == TYPE_CODE_STRUCT || TYPE_CODE(basetype) == TYPE_CODE_UNION)
	{
		int i, num_fields, vptr_fieldno;
		struct type *vptr_basetype = NULL;
		/* sanity check of offset */
		if (offset >= TYPE_LENGTH(basetype))
			return NULL;

		num_fields = TYPE_NFIELDS (basetype);
		vptr_fieldno = get_vptr_fieldno (basetype, &vptr_basetype);	/* -1 if the struct doesn't have a vptr */
		/*
		 * The first num_baseclasses fields are base classes, followed
		 * by type's data member
		 * Their sum is num_fields
		 * Also make sure all field types are fleshed out
		 */
		for (i = 0; i < num_fields; i++)
		{
			check_typedef(TYPE_FIELD_TYPE (basetype, i));
		}
		for (i = 0; i < num_fields; i++)
		{
			size_t pos, field_size;
			struct type* field_type = TYPE_FIELD_TYPE (basetype, i);
			/* static member */
			if (TYPE_FIELD_LOC_KIND(basetype, i) != FIELD_LOC_KIND_BITPOS)
				continue;
			pos = TYPE_FIELD_BITPOS(basetype, i) / 8;
			field_size = field_type->length;
			if ( i+1 < num_fields
				&& field_size == 1
				&& (TYPE_FIELD_BITPOS(basetype, i+1) / 8) == pos )
				continue;
			else if (field_size > 0 && offset >= pos && offset < pos + field_size)
			{
				const char* field_name = TYPE_FIELD_NAME(basetype, i);
				size_t namelen = strlen(field_name);
				strncpy(namebuf, field_name, bufsz);
				namebuf += namelen;
				bufsz   -= namelen;
				/* this is the vptr to "vtable for <basetype>" */
				if (offset > pos)
					return get_struct_field_type_and_name(field_type, offset - pos, lea, namebuf, bufsz, is_vptr);
				else if (i == vptr_fieldno && basetype == vptr_basetype)
				{
					*is_vptr = 1;
					return basetype;
				}
				else if (lea)
					return field_type;
				else if (TYPE_CODE(field_type) == TYPE_CODE_STRUCT || TYPE_CODE(field_type) == TYPE_CODE_UNION)
				{
					struct type* subfield_type;
					if (bufsz > 1)
					{
						*namebuf++ = '.';
						bufsz--;
					}
					subfield_type = get_struct_field_type_and_name(field_type, 0, lea, namebuf, bufsz, is_vptr);
					/*
					 * If _vptr belongs to a nested struct,
					 * the vtable should be of the outmost struct
					 */
					if (*is_vptr)
						return field_type;
					else
						return subfield_type;
				}
				else
					return field_type;
			}
		}
	}
	else if (TYPE_CODE(basetype) == TYPE_CODE_ARRAY)
	{
		struct type *target_type = check_typedef (TYPE_TARGET_TYPE (basetype));
		struct type *range_type;
		if (TYPE_NFIELDS (basetype) == 1
			&& (TYPE_CODE (range_type = TYPE_INDEX_TYPE (basetype)) == TYPE_CODE_RANGE))
		{
			const LONGEST low_bound = TYPE_LOW_BOUND (range_type);
			const LONGEST high_bound = TYPE_HIGH_BOUND (range_type);
			unsigned int elem_sz = TYPE_LENGTH(target_type);
			unsigned int index = low_bound + offset / elem_sz;
			if (index <= high_bound)
			{
				if (offset == index * elem_sz)
				{
					sprintf(namebuf, "[%d]", index);
					return target_type;
				}
			}
		}
		return NULL;
	}
	else if (offset == 0)
	{
		return basetype;
	}

	return NULL;
}

void
clear_addr_type_map(void)
{
	addr_type_map_sz = 0;
}

/*
 * Display a reference
 */
void
print_type_name(struct type *type, const char* field_name,
		const char* prefix, const char* postfix)
{
	int deref_count = 0;
	bool pointer_type = true;

	check_typedef (type);

	/* get base type if it is pointer/reference type */
	if (TYPE_CODE (type) == TYPE_CODE_PTR)
	{
		pointer_type = true;
		while (TYPE_CODE (type) == TYPE_CODE_PTR)
		{
			type = TYPE_TARGET_TYPE(type);
			deref_count++;
		}
	}
	else if (TYPE_CODE (type) == TYPE_CODE_REF)
	{
		pointer_type = false;
		deref_count++;
		type = TYPE_TARGET_TYPE(type);
	}
	else if (TYPE_CODE (type) == TYPE_CODE_ARRAY)
	{
		/* special treatment of array */
		struct type *range_type;
		struct type *target_type = TYPE_TARGET_TYPE (type);
		if (prefix)
			printf_filtered(_("%s"), prefix);
		print_type_name (target_type, NULL, NULL, NULL);
		if (TYPE_NFIELDS (type) == 1
			&& (TYPE_CODE (range_type = TYPE_INDEX_TYPE (type)) == TYPE_CODE_RANGE))
		{
			printf_filtered(_("[%ld]"), TYPE_HIGH_BOUND (range_type)+1);
		}
		else
			printf_filtered(_("[]\")"));
		if (field_name)
			printf_filtered(_(" %s"), field_name);
		if (postfix)
			printf_filtered(_("%s"), postfix);
		return;
	}

	if (type_name_no_tag(type))
	{
		const char* type_name = NULL;

		if (prefix)
			printf_filtered(_("%s"), prefix);

		if (TYPE_TAG_NAME(type))
			printf_filtered("struct ");
		printf_filtered(_("%s"), type_name_no_tag(type));

		for (; deref_count > 0; deref_count--)
		{
			if (pointer_type)
				printf_filtered(_("*"));
		}
		if (field_name)
			printf_filtered(_(" %s"), field_name);
		if (postfix)
			printf_filtered(_("%s"), postfix);
	}
}

/*
 * Display the struct's data member at offset
 */
static void
print_struct_field(const struct object_reference* ref,
		   struct type *type, size_t offset)
{
	check_typedef (type);

	/* If there is nothing referenced, don't drill down to sub field */
	if (offset == 0 && (ref->value==0 || !get_segment(ref->value, 1)) )
		return;

	if (TYPE_CODE(type) == TYPE_CODE_ARRAY)
	{
		struct type *target_type = check_typedef (TYPE_TARGET_TYPE (type));
		struct type *range_type;
		if (TYPE_NFIELDS (type) == 1
			&& (TYPE_CODE (range_type = TYPE_INDEX_TYPE (type)) == TYPE_CODE_RANGE))
		{
			const LONGEST low_bound = TYPE_LOW_BOUND (range_type);
			const LONGEST high_bound = TYPE_HIGH_BOUND (range_type);
			unsigned int elem_sz = TYPE_LENGTH(target_type);
			unsigned int index = low_bound + offset / elem_sz;
			if (offset == 0)
			{
				print_type_name(type, NULL, " (type=\"", "\")");
				return;
			}
			else if (index <= high_bound)
				printf_filtered(_("[%d]"), index);
			else
				printf_filtered(_("[?]"));
			print_struct_field(ref, target_type, offset - index * elem_sz);
		}
		else
			printf_filtered(_("[??]"));
		return;
	}
	else if (TYPE_CODE(type) == TYPE_CODE_STRUCT || TYPE_CODE(type) == TYPE_CODE_UNION)
	{
		int i, num_fields, num_baseclasses;
		num_fields = TYPE_NFIELDS (type);
		num_baseclasses = TYPE_N_BASECLASSES (type);
		/*
		 * The first num_baseclasses fields are base classes, followed
		 * by type's data member
		 * Their sum is num_fields
		 * Also make sure field type is fleshed out before use
		 */
		for (i = 0; i < num_fields; i++)
		{
			struct type* field_type = TYPE_FIELD_TYPE (type, i);
			size_t pos, field_size;

			check_typedef(TYPE_FIELD_TYPE (type, i));
			pos = TYPE_FIELD_BITPOS(type, i) / 8;
			field_size = field_type->length;
			/* static member */
			if (TYPE_FIELD_LOC_KIND(type, i) != FIELD_LOC_KIND_BITPOS)
				continue;
			if ( i+1 < num_fields
				&& field_size == 1
				&& (TYPE_FIELD_BITPOS(type, i+1) / 8) == pos )
				continue;
			else if (field_size > 0 && offset >= pos && offset < pos + field_size)
			{
				/* base classes come first in the type's fields */
				if (i < num_baseclasses)
				{
					const char* name = TYPE_NAME(field_type);
					/* quote the base name that consists of namespace specifier */
					if (strstr(name, "::"))
						printf_filtered(_("::\"%s\""), name);
					else
						printf_filtered(_("::%s"), name);
				}
				else
					printf_filtered(_(".%s"), TYPE_FIELD_NAME(type, i));

				print_struct_field(ref, field_type, offset - pos);
				break;
			}
		}
	}
	else if (TYPE_CODE(type) == TYPE_CODE_PTR || TYPE_CODE(type) == TYPE_CODE_REF)
		add_addr_type(ref->value, TYPE_TARGET_TYPE(type), NULL);
}

void
print_register_ref(const struct object_reference* ref)
{
	const char* reg_name;
	if (!ref->where.reg.name)
	{
		struct gdbarch *gdbarch = get_current_arch();
		reg_name = gdbarch_register_name (gdbarch, ref->where.reg.reg_num);
	}
	else
		reg_name = ref->where.reg.name;
	if (g_debug_context.tid != ref->where.stack.tid)
		CA_PRINT(" thread %d", ref->where.reg.tid);
	CA_PRINT(" %s=" PRINT_FORMAT_POINTER, reg_name, ref->value);
}

int
get_thread_id (const struct ca_segment* segment)
{
	const struct thread_info *info = (const struct thread_info*) segment->m_thread.context;
	return info->per_inf_num;
}

static struct minimal_symbol*
get_global_minimal_sym(const struct object_reference* ref,
		       address_t* sym_addr, size_t* sym_sz)
{
	struct objfile *objfile;
	struct obj_section *osect;

	ALL_OBJSECTIONS (objfile, osect) {
		address_t sect_addr;
		struct bound_minimal_symbol bmsymbol;

		/*
		 * Only process each object file once, even if there's a
		 * separate debug file.
		 */
		if (objfile->separate_debug_objfile_backlink)
			continue;

		sect_addr = overlay_mapped_address (ref->vaddr, osect);

		if (obj_section_addr(osect) <= sect_addr &&
		    sect_addr < obj_section_endaddr(osect)) {
			bmsymbol = lookup_minimal_symbol_by_pc_section(sect_addr, osect);
			if (bmsymbol.minsym != NULL && bmsymbol.objfile != NULL) {
				if (sym_addr != NULL && sym_sz != NULL) {
					*sym_addr = BMSYMBOL_VALUE_ADDRESS(bmsymbol);
					*sym_sz   = MSYMBOL_SIZE (bmsymbol.minsym);
				}
				return bmsymbol.minsym;
			}
			break;
		}
	}

	return NULL;
}

struct symbol*
get_global_sym(const struct object_reference* ref,
	       address_t* sym_addr, size_t* sym_sz)
{
	struct bound_minimal_symbol bmsymbol;
	struct objfile *objfile;
	struct obj_section *osect;
	address_t sect_addr;
	unsigned int offset;
	struct symbol* sym = NULL;

	if (ref->storage_type != ENUM_MODULE_DATA && ref->storage_type != ENUM_MODULE_TEXT)
		return NULL;

	ALL_OBJSECTIONS (objfile, osect)
	{
		/*
		 * Only process each object file once, even if there's a separate
		 * debug file.
		 */
		if (objfile->separate_debug_objfile_backlink)
			continue;

		sect_addr = overlay_mapped_address (ref->vaddr, osect);

		if (obj_section_addr (osect) <= sect_addr &&
		    sect_addr < obj_section_endaddr (osect)) {
			bmsymbol = lookup_minimal_symbol_by_pc_section (sect_addr, osect);
			if (bmsymbol.minsym != NULL && bmsymbol.objfile != NULL) {
				const char *msym_name;
				char *loc_string;
				struct cleanup *old_chain = NULL;

				offset = sect_addr - BMSYMBOL_VALUE_ADDRESS(bmsymbol);
				msym_name = MSYMBOL_PRINT_NAME(bmsymbol.minsym);

				loc_string = xstrprintf ("%s", msym_name);

				/* Use a cleanup to free loc_string in case the user quits
				   a pagination request inside printf_filtered.  */
				old_chain = make_cleanup (xfree, loc_string);

				gdb_assert (osect->objfile && osect->objfile->original_name);

				sym = lookup_symbol(loc_string, 0, VAR_DOMAIN, 0).symbol;
				if (sym != NULL) {
					struct type* type = sym->type;
					add_addr_type (ref->vaddr - offset, type, sym);
					if (sym_addr && sym_sz) {
						*sym_addr = ref->vaddr - offset;
						*sym_sz   = TYPE_LENGTH(type);
					}
				} else if (sym_addr != 0 && sym_sz != 0) {
					*sym_addr = BMSYMBOL_VALUE_ADDRESS(bmsymbol);
					*sym_sz   = MSYMBOL_SIZE(bmsymbol.minsym);
				}

				do_cleanups (old_chain);
			}
			break;
		}
	}

	return sym;
}

struct symbol*
get_stack_sym(const struct object_reference* ref,
	      address_t* sym_addr, size_t* sym_sz)
{
	struct symbol *sym;
	bool found_local_var = false;
	struct ca_segment*segment = get_segment (ref->vaddr, 1);
	if (ref->where.stack.frame >= 0 && segment && segment->m_type == ENUM_STACK)
	{
		struct frame_info* frame;
		const struct block *block;
		address_t pc;
		int i;
		const struct thread_info *tp = (const struct thread_info*) segment->m_thread.context;

		/* switch to the thread/frame */
		switch_to_thread (tp->ptid);
		frame = get_current_frame ();
		for (i=0; i<ref->where.stack.frame; i++)
			frame = get_prev_frame(frame);

		/* check local vars */
		if (get_frame_pc_if_available (frame, &pc) &&
		    (block = get_frame_block (frame, 0) ) ) {
			while (block && !found_local_var) {
				struct block_iterator iter;
				volatile struct gdb_exception except;

				ALL_BLOCK_SYMBOLS (block, iter, sym) {
					switch (SYMBOL_CLASS (sym)) {
					case LOC_LOCAL:
					case LOC_REGISTER:
					case LOC_STATIC:
					case LOC_COMPUTED:
						TRY {
							struct value *val = read_var_value (sym, NULL, frame);
							address_t val_addr = value_address(val);
							struct type * type = value_type(val);
							size_t val_size = type->length;
							if (ref->vaddr >= val_addr && ref->vaddr < val_addr + val_size)
							{
								found_local_var = true;
								if (sym_addr && sym_sz)
								{
									*sym_addr = val_addr;
									*sym_sz = val_size;
								}
							}
						} CATCH (except, RETURN_MASK_ERROR) {
						}
						END_CATCH
						break;
					default:
						break;
					}
					if (found_local_var)
						break;
				}

				/* move up to super block until reach function scope */
				if (BLOCK_FUNCTION (block))
					break;
				block = BLOCK_SUPERBLOCK (block);
			}
		}
	}
	return found_local_var ? sym : NULL;
}

struct type*
get_heap_object_type(const struct object_reference* ref)
{
	struct type* type = NULL;

	if (ref->storage_type == ENUM_HEAP && ref->where.heap.inuse)
	{
		size_t size_t_sz = g_ptr_bit >> 3;
		char obj_name[NAME_BUF_SZ];
		/*
		 * some application put multiple objects on a pre-allocated
		 * buffer; make sure we get the type right
		 */
		struct ca_addr_type_pair* addr_type = lookup_type_by_addr(ref->vaddr);
		if (addr_type)
			type = addr_type->type;
		/* special care is taken for heap object w/ _vptr */
		else if (is_heap_object_with_vptr(ref, obj_name, NAME_BUF_SZ)) {
			/*
			 * make sure the size of the object agrees with the
			 * size of the heap block
			 */
			struct symbol *sym = lookup_symbol(obj_name, 0, STRUCT_DOMAIN, 0).symbol;
			if (sym != NULL) {
				if (TYPE_LENGTH(sym->type) <= ref->where.heap.size &&
				    TYPE_LENGTH(sym->type) + 2 * size_t_sz >= ref->where.heap.size) {
					type = sym->type;
					add_addr_type (ref->where.heap.addr, type, NULL);
				}
			}
		}
	}

	return type;
}

bool
known_global_sym(const struct object_reference* ref,
		 address_t* sym_addr, size_t* sym_sz)
{
	struct minimal_symbol* msym = get_global_minimal_sym(ref, sym_addr, sym_sz);
	return (msym != NULL);
}

bool
known_stack_sym(const struct object_reference* ref,
		address_t* sym_addr, size_t* sym_sz)
{
	struct symbol* sym = get_stack_sym(ref, sym_addr, sym_sz);
	return (sym != NULL);
}

static bool
known_heap_block(const struct object_reference* ref)
{
	struct type* type = get_heap_object_type(ref);
	return (type != NULL);
}

void
print_stack_ref(const struct object_reference* ref)
{
	struct symbol* sym;
	address_t sym_addr;
	size_t    sym_size;

	/* display thread id and frame number if they are not selected values */
	if (g_debug_context.tid != ref->where.stack.tid)
	{
		CA_PRINT(" thread %d", ref->where.stack.tid);
		CA_PRINT(" frame %d", ref->where.stack.frame);
	}
	else if (g_debug_context.frame_level != ref->where.stack.frame)
		CA_PRINT(" frame %d", ref->where.stack.frame);

	sym = get_stack_sym(ref, &sym_addr, &sym_size);
	if (sym)
	{
		/* if the ref belongs to a local symbol, display in detail */
		printf_filtered(_(" %s"), SYMBOL_PRINT_NAME (sym));
		print_struct_field(ref, SYMBOL_TYPE(sym), ref->vaddr - sym_addr);
	}
	else
	{
		/* if no named local var is found, just print its sp offset */
		if (ref->where.stack.frame >= 0)
		{
			if (ref->where.stack.offset == 0)
				printf_filtered(_(" SP"));
			else
				printf_filtered(_(" rsp%+d"), ref->where.stack.offset);
		}
		else
			printf_filtered(" below rsp");
	}

	printf_filtered(" @0x%lx", ref->vaddr);
	if (ref->value)
		printf_filtered(_(": 0x%lx"), ref->value);
}

void
print_global_ref (const struct object_reference* ref)
{
	struct symbol* sym;
	struct minimal_symbol* msym;
	address_t sym_addr;
	size_t    sym_size;

	printf_filtered(_(" %s"), ref->where.module.name);
	if ( (sym = get_global_sym(ref, &sym_addr, &sym_size)) ) {
		/* if the ref belongs to a global symbol, display in detail */
		printf_filtered(_(" %s"), SYMBOL_PRINT_NAME (sym));
		print_struct_field(ref, SYMBOL_TYPE(sym), ref->vaddr - sym_addr);
		if (ref->target_index >= 0)
			printf_filtered (_(" @0x%lx"), ref->vaddr);
	} else if ( (msym = get_global_minimal_sym(ref, &sym_addr, &sym_size)) ) {
		printf_filtered(_(" %s (0x%lx--0x%lx)"),
		    MSYMBOL_PRINT_NAME(msym), sym_addr, sym_addr+sym_size);
		if (ref->target_index >= 0)
			printf_filtered (_(" @0x%lx"), ref->vaddr);
	} else {
		printf_filtered (_(" Unknown global 0x%lx"), ref->vaddr);
	}

	if (ref->target_index >= 0 && ref->value)
		printf_filtered (_(": 0x%lx"), ref->value);
}

void
print_heap_ref(const struct object_reference* ref)
{
	if (ref->where.heap.inuse)
	{
		address_t vptr;
		char obj_name[NAME_BUF_SZ];
		struct type *type = NULL;
		size_t offset = 0;

		/*
		 * some application put multiple objects on a pre-allocated buffer
		 * make sure we get the type right
		 */
		struct ca_addr_type_pair* addr_type = lookup_type_by_addr(ref->vaddr);
		if (addr_type)
		{
			type = addr_type->type;
			if (addr_type->sym)
			{
				/*
				 * the heap block is pointed to by a symbol
				 * (e.g. local/global variable)
				 */
				printf_filtered (" %s", SYMBOL_PRINT_NAME (addr_type->sym));
			}
			else if (addr_type->type)
			{
				/* This heap block is referenced by an object
				 * whose type is known
				 */
				print_type_name(type, NULL, " (type=\"", "\")");
			}
			offset = ref->vaddr - addr_type->addr;
		}
		/* special care is taken for heap object w/ _vptr */
		else if (is_heap_object_with_vptr(ref, obj_name, NAME_BUF_SZ))
		{
			size_t size_t_sz = g_ptr_bit >> 3;
			/*
			 * make sure the size of the object agrees with the size
			 * of the heap block
			 */
			struct symbol *sym = lookup_symbol(obj_name, 0, STRUCT_DOMAIN, 0).symbol;
			if (sym != NULL &&
			    TYPE_LENGTH(sym->type) <= ref->where.heap.size &&
			    TYPE_LENGTH(sym->type) + 2 * size_t_sz >= ref->where.heap.size) {
				type = sym->type;
				print_type_name(type, NULL, " (type=\"", "\")");
				add_addr_type (ref->where.heap.addr, type, NULL);
			} else {
				printf_filtered(_(" (type=\"%s\")"), obj_name);
			}
			offset = ref->vaddr - ref->where.heap.addr;
		}

		/* print sub field if any */
		if (type &&
		    (TYPE_CODE (type) == TYPE_CODE_STRUCT || TYPE_CODE (type) == TYPE_CODE_UNION) &&
		    (ref->value || offset > 0) ) {
			print_struct_field(ref, type, offset);
		}
	}
	else {
		CA_PRINT(" FREE");
	}
}

address_t
get_var_addr_by_name(const char* var_name, bool ask)
{
	struct symbol *sym = lookup_symbol (var_name, 0, VAR_DOMAIN, 0).symbol;
	if (sym != NULL) {
		return SYMBOL_VALUE(sym);
	} else {
		struct bound_minimal_symbol bmsymbol;

		bmsymbol = lookup_minimal_symbol(var_name, NULL, NULL);
		if (bmsymbol.minsym != NULL && bmsymbol.objfile != NULL)
			return BMSYMBOL_VALUE_ADDRESS (bmsymbol);
	}
	return 0;
}

void
print_func_locals (void)
{
	struct frame_info* frame;
	const struct block *block;

	/* switch to the thread/frame */
	frame = get_selected_frame (NULL);
	/* check local vars */
	block = get_frame_block (frame, 0);
	while (block) {
		struct block_iterator iter;
		struct symbol *sym;
		volatile struct gdb_exception except;
		struct value *val;
		address_t val_addr;

		ALL_BLOCK_SYMBOLS (block, iter, sym) {
			switch (SYMBOL_CLASS (sym)) {
			case LOC_LOCAL:
			case LOC_REGISTER:
			case LOC_STATIC:
			case LOC_COMPUTED:
				TRY {
					val = read_var_value (sym, NULL, frame);
					val_addr = value_address(val);
					printf_filtered(_("%s: %p\n"),
					    SYMBOL_PRINT_NAME (sym), (void*)val_addr);
				} CATCH (except, RETURN_MASK_ERROR) {
				}
				END_CATCH
				break;
			default:
				break;
			}
		}
		/* move up to super block until reach function scope */
		if (BLOCK_FUNCTION (block))
			break;
		block = BLOCK_SUPERBLOCK (block);
	}
}

static void
print_type_members(struct type *type, int indent)
{
	int i, num_fields, num_baseclasses, offset=0;
	num_fields = TYPE_NFIELDS (type);
	num_baseclasses = TYPE_N_BASECLASSES (type);
	/*
	 * The first num_baseclasses fields are base classes, followed by type's
	 * data member
	 * Their sum is num_fields
	 * Also make sure all field types are fleshed out
	 */
	for (i = 0; i < num_fields; i++)
	{
		struct type* field_type = TYPE_FIELD_TYPE (type, i);
		int pos, k;

		check_typedef (field_type);
		/* print indent */
		for (k=0; k<indent; k++)
			printf_filtered(_("  "));
		/* static member */
		if (TYPE_FIELD_LOC_KIND(type, i) != FIELD_LOC_KIND_BITPOS)
		{
			printf_filtered("static ");
			print_type_name(field_type, NULL, NULL, NULL);
			printf_filtered("\n");
			continue;
		}
		pos = TYPE_FIELD_BITPOS(type, i) / 8;
		if (pos < 0)
			pos = offset;
		/* print offset of data member */
		printf_filtered(_("+%d"), pos);
		if (pos >= 100)
			printf_filtered(" ");
		else if (pos >= 10)
			printf_filtered("  ");
		else
			printf_filtered("   ");
		/* print base class if applicable */
		if (i < num_baseclasses)
		{
			printf_filtered("(base) ");
			print_type_name(field_type, NULL, NULL, NULL);
		}
		else
			print_type_name(field_type, TYPE_FIELD_NAME(type, i), NULL, NULL);
		printf_filtered(_("  size=%d\n"), field_type->length);
		offset += field_type->length;
		/* the field is a base class */
		if (i < num_baseclasses)
		{
			for (k=0; k<indent; k++)
				printf_filtered("  ");
			printf_filtered("{\n");
			print_type_members (field_type, indent+1);
			for (k=0; k<indent; k++)
				printf_filtered("  ");
			printf_filtered("}\n");
		}
	}
}

static struct type *
get_real_type_from_exp(char* exp)
{
	expression_up expr;
	struct value *val;
	struct type *type;

    expr = parse_expression (exp);
    val = evaluate_type (expr.get());
    type = value_type (val);
    if (type)
    {
    	int full = 0;
    	LONGEST top = -1;
    	int using_enc = 0;
    	int indirect = 0;
    	struct type *real_type = NULL;
    	int is_ptr = 0;
    	int is_ref = 0;

    	if (TYPE_CODE (type) == TYPE_CODE_PTR)
    		is_ptr = 1;
    	else if (TYPE_CODE (type) == TYPE_CODE_REF)
    		is_ref = 1;
    	/* given base pointer, find out the concrete class type */
		if ((is_ptr || is_ref)
		  && (TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_STRUCT))
		{
			real_type = value_rtti_indirect_type (val, &full, &top, &using_enc);
			if (real_type)
			{
				if (is_ptr)
					real_type = lookup_pointer_type (real_type);
				else
					real_type = lookup_lvalue_reference_type (real_type);
			}
		}
		else if (TYPE_CODE (type) == TYPE_CODE_STRUCT)
			real_type = value_rtti_type (val, &full, &top, &using_enc);

		if (real_type)
			type = real_type;
    }
	return type;
}

/* search C++ vtables of the type of the input expression */
bool
get_vtable_from_exp(const char*expression,
		    struct CA_LIST*vtables,
		    char* type_name,
		    size_t bufsz, size_t* type_sz)
{
	char* exp = strdup (expression);
	struct type *type = get_real_type_from_exp (exp);
	size_t vtbl_sz = 0;
	address_t vtbl_addr = 0;
	bool rc = false;

	if (type) {
		/* if the type is pointer/reference, print the base type */
		while (TYPE_CODE (type) == TYPE_CODE_PTR ||
		    TYPE_CODE (type) == TYPE_CODE_REF) {
			type = TYPE_TARGET_TYPE(type);
		}

		if (TYPE_CODE(type) == TYPE_CODE_STRUCT && TYPE_NAME (type)) {
			char* vtbl_name;
			struct bound_minimal_symbol bmsym;

			vtbl_name = (char *)xmalloc(strlen(TYPE_NAME (type)) + 16);
			sprintf(vtbl_name, "vtable for %s", TYPE_NAME (type));

			bmsym = lookup_minimal_symbol (vtbl_name, NULL, NULL);
			if (bmsym.minsym != NULL && bmsym.objfile != NULL) {
				struct object_range* vtable = (struct object_range*)
				    malloc(sizeof(struct object_range));

				vtable->low = BMSYMBOL_VALUE_ADDRESS(bmsym);
				vtable->high = vtable->low  + MSYMBOL_SIZE(bmsym.minsym);
				ca_list_push_front(vtables, vtable);
				snprintf(type_name, bufsz, "%s", TYPE_NAME (type));
				*type_sz = TYPE_LENGTH (type);
				rc = true;
			}
			xfree (vtbl_name);
		}
	}
	xfree (exp);
	return rc;
}

/* print structure layout in windbg "dt" style */
void
print_type_layout (char* exp)
{
	struct type *type = get_real_type_from_exp (exp);
    if (type)
    {
    	int indirect = 0;
    	int is_ptr = 0;
    	if (TYPE_CODE (type) == TYPE_CODE_PTR)
			is_ptr = 1;
		/* print type name */
		printf_filtered (_("type="));
		type_print (type, "", gdb_stdout, -1);
		printf_filtered (_("  size=%d\n"), type->length);
		/* if the type is pointer/reference, print the base type */
		while (TYPE_CODE (type) == TYPE_CODE_PTR || TYPE_CODE (type) == TYPE_CODE_REF)
		{
			type = TYPE_TARGET_TYPE(type);
			indirect++;
		}
		if (TYPE_CODE(type) == TYPE_CODE_STRUCT || TYPE_CODE(type) == TYPE_CODE_UNION)
		{
			printf_filtered (_("{\n"));
			print_type_members (type, 1);
			printf_filtered (_("}"));
			while (indirect > 0)
			{
				if (is_ptr)
					printf_filtered (_("*"));
				else
					printf_filtered (_("&"));
				indirect--;
			}
			printf_filtered (_(";\n"));
		}
    }
}

/*
 * SIGINT or Control-C is pressed
 */
bool
user_request_break(void)
{
	/* this call will reset the flag */
	if (check_quit_flag ())
		g_quit = true;
	return g_quit;
}

/*********************************************************************
 * Annotated disassembly instructions
 ********************************************************************/
struct ca_x86_register
{
	const char*  name;		/* intel syntax */
	unsigned int index:6;		/* internal index (see x_type.h) */
	unsigned int size:5;		/* 1/2/4/8/16 bytes */
	unsigned int x64_only:1;	/* set if only used by 64bit */
	unsigned int param_x64:4;	/* nth (1..6) parameter, 0 means not a param reg */
	unsigned int preserved_x64:1;	/* 64bit - preserved across function call */
	unsigned int preserved_x32:1;	/* 32bit - preserved across function call */
	unsigned int float_reg:1;	/* 1=float 0=integer */
	int gdb_regnum;			/* regnum known to gdb */
};

/*
 * this name list corresponds to the register index defined in x_type.h
 */
static struct ca_x86_register g_reg_infos[] = {
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
	{"rax",   RAX,    8,  1,    0,     0,     0,    0,    -1},
	{"rcx",   RCX,    8,  1,    4,     0,     0,    0,    -1},
	{"rdx",   RDX,    8,  1,    3,     0,     0,    0,    -1},
	{"rbx",   RBX,    8,  1,    0,     1,     0,    0,    -1},
	{"rsp",   RSP,    8,  1,    0,     0,     0,    0,    -1},
	{"rbp",   RBP,    8,  1,    0,     1,     0,    0,    -1},
	{"rsi",   RSI,    8,  1,    2,     0,     0,    0,    -1},
	{"rdi",   RDI,    8,  1,    1,     0,     0,    0,    -1},
	{"r8",    R8,     8,  1,    5,     0,     0,    0,    -1},
	{"r9",    R9,     8,  1,    6,     0,     0,    0,    -1},
	{"r10",   R10,    8,  1,    0,     0,     0,    0,    -1},
	{"r11",   R11,    8,  1,    0,     0,     0,    0,    -1},
	{"r12",   R12,    8,  1,    0,     1,     0,    0,    -1},
	{"r13",   R13,    8,  1,    0,     1,     0,    0,    -1},
	{"r14",   R14,    8,  1,    0,     1,     0,    0,    -1},
	{"r15",   R15,    8,  1,    0,     1,     0,    0,    -1},
	{"rip",   RIP,    8,  1,    0,     0,     0,    0,    -1},
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
	{"eax",   RAX,    4,  0,    0,     0,     0,    0,    -1},
	{"ecx",   RCX,    4,  0,    4,     0,     0,    0,    -1},
	{"edx",   RDX,    4,  0,    3,     0,     0,    0,    -1},
	{"ebx",   RBX,    4,  0,    0,     0,     1,    0,    -1},
	{"esp",   RSP,    4,  0,    0,     0,     0,    0,    -1},
	{"ebp",   RBP,    4,  0,    0,     0,     0,    0,    -1},
	{"esi",   RSI,    4,  0,    2,     0,     1,    0,    -1},
	{"edi",   RDI,    4,  0,    1,     0,     1,    0,    -1},
	{"r8d",   R8,     4,  1,    5,     0,     0,    0,    -1},
	{"r9d",   R9,     4,  1,    6,     0,     0,    0,    -1},
	{"r10d",  R10,    4,  1,    0,     0,     0,    0,    -1},
	{"r11d",  R11,    4,  1,    0,     0,     0,    0,    -1},
	{"r12d",  R12,    4,  1,    0,     0,     0,    0,    -1},
	{"r13d",  R13,    4,  1,    0,     0,     0,    0,    -1},
	{"r14d",  R14,    4,  1,    0,     0,     0,    0,    -1},
	{"r15d",  R15,    4,  1,    0,     0,     0,    0,    -1},
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
	{"di",    RDI,    2,  0,    1,     0,     0,    0,    -1},
	{"si",    RSI,    2,  0,    2,     0,     0,    0,    -1},
	{"dx",    RDX,    2,  0,    3,     0,     0,    0,    -1},
	{"cx",    RCX,    2,  0,    4,     0,     0,    0,    -1},
	{"r8w",   R8,     2,  0,    5,     0,     0,    0,    -1},
	{"r9w",   R9,     2,  0,    6,     0,     0,    0,    -1},
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
	{"dil",  RDI,    1,  0,    1,     0,     0,    0,    -1},
	{"sil",  RSI,    1,  0,    2,     0,     0,    0,    -1},
	{"dl",   RDX,    1,  0,    3,     0,     0,    0,    -1},
	{"cl",   RCX,    1,  0,    4,     0,     0,    0,    -1},
	{"r8b",  R8,     1,  0,    5,     0,     0,    0,    -1},
	{"r9b",  R9,     1,  0,    6,     0,     0,    0,    -1},
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
	{"xmm0",  RXMM0,  16,  0,    1,     0,     0,    1,    -1},
	{"xmm1",  RXMM1,  16,  0,    2,     0,     0,    1,    -1},
	{"xmm2",  RXMM2,  16,  0,    3,     0,     0,    1,    -1},
	{"xmm3",  RXMM3,  16,  0,    4,     0,     0,    1,    -1},
	{"xmm4",  RXMM4,  16,  0,    5,     0,     0,    1,    -1},
	{"xmm5",  RXMM5,  16,  0,    6,     0,     0,    1,    -1},
	{"xmm6",  RXMM6,  16,  0,    7,     0,     0,    1,    -1},
	{"xmm7",  RXMM7,  16,  0,    8,     0,     0,    1,    -1},
	{"xmm8",  RXMM8,  16,  1,    0,     0,     0,    1,    -1},
	{"xmm9",  RXMM9,  16,  1,    0,     0,     0,    1,    -1},
	{"xmm10", RXMM10, 16,  1,    0,     0,     0,    1,    -1},
	{"xmm11", RXMM11, 16,  1,    0,     0,     0,    1,    -1},
	{"xmm12", RXMM12, 16,  1,    0,     0,     0,    1,    -1},
	{"xmm13", RXMM13, 16,  1,    0,     0,     0,    1,    -1},
	{"xmm14", RXMM14, 16,  1,    0,     0,     0,    1,    -1},
	{"xmm15", RXMM15, 16,  1,    0,     0,     0,    1,    -1}
	/* name  index  size x64 par64 prsv64 prev32 float regnum */
};
#define NUM_KNOWN_REGS (sizeof(g_reg_infos)/sizeof(g_reg_infos[0]))

/*
 * return my internal index (g_reg_infos[]::index) by name
 * -1 when not found
 */
static int
reg_name_to_index(const char* regname)
{
	int i;
	for (i = 0; i < NUM_KNOWN_REGS; i++)
	{
		if (strcmp(regname, g_reg_infos[i].name) == 0)
			return g_reg_infos[i].index;
	}
	return -1;
}

static void
build_regno_map(struct gdbarch *gdbarch)
{
	if (g_reg_infos[0].gdb_regnum == -1)
	{
		int i;
		for (i = 0; i < NUM_KNOWN_REGS; i++)
		{
			const char* regname = g_reg_infos[i].name;
			g_reg_infos[i].gdb_regnum = user_reg_map_name_to_regnum (gdbarch, regname, strlen(regname));
		}
	}
}

static int
get_reg_param_index(unsigned int int_reg_param_ordinal,
		    unsigned int reg_size, int float_param)
{
	int i;
	for (i = 0; i < NUM_KNOWN_REGS; i++)
	{
		if (g_reg_infos[i].size == reg_size
			&& g_reg_infos[i].param_x64 == int_reg_param_ordinal
			&& g_reg_infos[i].float_reg == float_param)
			return i;
	}
	return -1;
}

static bool
ca_get_frame_register(struct frame_info *frame, int regnum, size_t* valp)
{
	int optimized;
	int unavailable;
	CORE_ADDR addr;
	int realnum;
	enum lval_type lval;

	frame_register_unwind (frame, regnum, &optimized, &unavailable,
			&lval, &addr, &realnum, (gdb_byte *)valp);

	if (optimized || unavailable)
		return false;
	else
		return true;
}

static int
sse_class(struct type* type)
{
	if (TYPE_CODE(type) == TYPE_CODE_FLT)
		return 1;
	else
		return 0;
}

static int
integer_class(struct type* type)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	int len = TYPE_LENGTH(type);
	if (len <= ptr_sz)
	{
		switch(TYPE_CODE(type))
		{
		case TYPE_CODE_PTR:
		case TYPE_CODE_ARRAY:
		case TYPE_CODE_ENUM:
		case TYPE_CODE_FUNC:
		case TYPE_CODE_INT:
		case TYPE_CODE_STRING:
		case TYPE_CODE_METHOD:
		case TYPE_CODE_METHODPTR:
		case TYPE_CODE_MEMBERPTR:
		case TYPE_CODE_REF:
		case TYPE_CODE_CHAR:
		case TYPE_CODE_BOOL:
			return 1;
			break;
		default:
			break;
		}
	}
	return 0;
}

#define MAX_INT_PARAM_BY_REG 6
#define MAX_FLT_PARAM_BY_REG 8

static bool
validate_and_set_reg_param(const char* cursor, struct ca_reg_value* param_regs)
{
	int ptr_bit = g_ptr_bit;
	int i;
	for (i = 0; i < NUM_KNOWN_REGS; i++)
	{
		if (ptr_bit == 32 && g_reg_infos[i].x64_only)
			continue;
		else
		{
			const char* reg_name = g_reg_infos[i].name;
			int len = strlen(reg_name);
			if (strncmp(cursor, reg_name, len) == 0 && *(cursor + len) == '=')
			{
				int index = g_reg_infos[i].index;
				param_regs[index].has_value = 1;
				param_regs[index].value = parse_and_eval_address ((char*)(cursor + len + 1));
				return true;
			}
		}
	}
	return false;
}

/*
 * By x86_64 ABI, the frist six integer parameters are passed through
 *  registers (rdi, rsi, rdx, rcx, r8, r9)
 */
static void
get_function_parameters(struct gdbarch *gdbarch,
			struct frame_info *selected_frame,
			struct ca_reg_value* param_regs)
{
	int ptr_bit = g_ptr_bit;
	struct ui_out *uiout = current_uiout;
	struct symbol *func = get_frame_function (selected_frame);
	if (func && ptr_bit == 64) {
		/* Address of the argument list for this frame, or 0.  */
		CORE_ADDR arg_list = get_frame_args_address (selected_frame);
		if (arg_list != 0) {
			/* print_frame_args (func, fi, -1, gdb_stdout); */
			int num_params = 0;
			const struct block *b;
			struct block_iterator iter;
			struct symbol *sym;
			struct value *val;
			struct cleanup *list_chain;
			int int_reg_param_ordinal = 1, float_reg_param_ordinal = 1;
			int reg_index = -1;
			struct type* param_type = NULL;
			int reg_size = 0;
			string_file stb;

			printf_filtered (_("\nParameters: "));
			b = SYMBOL_BLOCK_VALUE (func);
			ALL_BLOCK_SYMBOLS (b, iter, sym) {

				QUIT;

				if (!SYMBOL_IS_ARGUMENT (sym))
					continue;

				if (*SYMBOL_LINKAGE_NAME(sym) != '\0') {
					struct block_symbol bsym;

					bsym = lookup_symbol(SYMBOL_LINKAGE_NAME (sym),
					    b, VAR_DOMAIN, NULL);

					if (SYMBOL_CLASS(bsym.symbol) != LOC_REGISTER)
						sym = bsym.symbol;
				}
				if (num_params)
					uiout->text(", ");
				list_chain = make_cleanup_ui_out_tuple_begin_end (uiout, NULL);
				fprintf_symbol_filtered (&stb, SYMBOL_PRINT_NAME (sym),
										SYMBOL_LANGUAGE (sym),
										DMGL_PARAMS | DMGL_ANSI);
				uiout->field_stream("name", stb);
				/* find the corresponding register used to pass this parameter */
				{
					const char* reg_name = NULL;
					int internal_index = -1;
					param_type = SYMBOL_TYPE(sym);
					check_typedef(param_type);
					if (int_reg_param_ordinal <= MAX_INT_PARAM_BY_REG && integer_class(param_type))
					{
						reg_size = TYPE_LENGTH(param_type);
						internal_index = get_reg_param_index(int_reg_param_ordinal, reg_size, 0);
						int_reg_param_ordinal++;
					}
					else if (float_reg_param_ordinal <= MAX_FLT_PARAM_BY_REG && sse_class(param_type))
					{
						internal_index = get_reg_param_index(float_reg_param_ordinal, 16, 1);
						float_reg_param_ordinal++;
					}
					/* if the parameter is passed by a integer/float register */
					if (internal_index > 0)
					{
						reg_name = g_reg_infos[internal_index].name;
						reg_index = g_reg_infos[internal_index].index;
					}
					/* we have determine a register class parameter and its register */
					if (reg_name)
					{
						fputs_filtered ("(", &stb);
						fputs_filtered (reg_name, &stb);
						fputs_filtered (")", &stb);
						uiout->field_stream("reg", stb);
					}
					if (reg_index >= 0)
					{
						if (param_regs[reg_index].sym_name)
							free (param_regs[reg_index].sym_name);
						param_regs[reg_index].sym_name = strdup(SYMBOL_PRINT_NAME (sym));
						param_regs[reg_index].type = param_type;
					}
				}
				uiout->text("=");

				val = read_var_value (sym, NULL, selected_frame);
				if (val)
				{
					int summary = 1;
					const struct language_defn *language;
					struct value_print_options opts;
					volatile struct gdb_exception ex;

					if (language_mode == language_mode_auto)
						language = language_def (SYMBOL_LANGUAGE (sym));
					else
						language = current_language;
					get_user_print_options (&opts);
					opts.deref_ref = 0;
					opts.summary = summary;
					common_val_print (val, &stb, 2, &opts, language);
					uiout->field_stream("value", stb);
					if (reg_index >= 0 && !param_regs[reg_index].has_value && !value_optimized_out(val))
					{
						size_t param_val = (size_t) value_as_long (val);
						param_regs[reg_index].value = param_val;
						if ((TYPE_CODE(param_type) == TYPE_CODE_PTR || TYPE_CODE(param_type) == TYPE_CODE_REF))
							add_addr_type (param_val, NULL, sym);
						param_regs[reg_index].has_value = 1;
					}
				}
				do_cleanups (list_chain);
				num_params++;
			}
			printf_filtered (_("\n"));
		}
	}
}

static void
display_saved_registers(struct gdbarch *gdbarch,
			struct frame_info *selected_frame,
			struct ca_reg_value* param_regs,
			bool verbose)
{
	int i, count, numregs;
	int ptr_bit = g_ptr_bit;
	size_t ptr_sz = ptr_bit >> 3;

	count = 0;
	numregs = gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);
	for (i = 0; i < numregs; i++)
	{
		if (i != gdbarch_sp_regnum (gdbarch)
			/*&& gdbarch_register_reggroup_p (gdbarch, i, all_reggroup)*/)
		{
			int optimized, unavailable, realnum;
			enum lval_type lval;
			CORE_ADDR addr;
			frame_register_unwind (selected_frame, i, &optimized, &unavailable,
									&lval, &addr, &realnum, NULL);
			if (!optimized && !unavailable && lval == lval_memory)
			{
				const char* regname = gdbarch_register_name (gdbarch, i);
				int my_index = reg_name_to_index(regname);
				size_t value = 0;
				if (verbose)
				{
					if (count > 0)
						puts_filtered (",");
					printf_filtered (" %s", regname);
				}
				count++;
				if (target_read_memory(addr, (gdb_byte *)&value, ptr_sz) == 0)
				{
					if (param_regs && my_index >= 0)
					{
						/* the value should have been set previously, set it again anyway */
						param_regs[my_index].value = value;
						param_regs[my_index].has_value = 1;
					}
					if (verbose)
						printf_filtered ("(0x%lx)", value);
				}
			}
		}
	}
	if (verbose && count == 0)
		printf_filtered (_(" none"));
}

/*
 * Parse user options and prepare execution context at function entry,
 * then call disassemble function
 */
void
decode_func(const char *arg)
{
	int ptr_bit = g_ptr_bit;
	size_t ptr_sz = ptr_bit >> 3;
	struct ui_out *uiout = current_uiout;
	struct frame_info *selected_frame, *fi;
	struct gdbarch *gdbarch;
	CORE_ADDR user_low=0, user_high=0;
	int i, count, numregs;
	bool multi_frame = false;
	int frame_lo = 0;
	int frame_hi = 0;
	int  frame;
	struct ca_reg_value user_input_regs[TOTAL_REGS];
	struct ca_reg_value param_regs[TOTAL_REGS];
	bool verbose = false;
	bool user_regs = false;

	/* Get current frame */
	selected_frame = get_selected_frame (_("No frame selected."));
	if (!selected_frame)
		return;
	frame = frame_relative_level(selected_frame);
	/* build map to gdb used register number for the first time */
	gdbarch = get_frame_arch (selected_frame);
	build_regno_map(gdbarch);

	/* Init registers' state */
	memset(param_regs, 0, REG_SET_SZ);
	memset(user_input_regs, 0, REG_SET_SZ);

	/* initialize type map for heap objects */
	clear_addr_type_map();

	/* Parse user input options */
	if (arg)
	{
		gdb::unique_xmalloc_ptr<char> myarg(xstrdup(arg));
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(myarg.get(), options);
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];
			if (*option == '%')
			{
				/* Take register entry value, such as %rdi=0x12345678 */
				if (!validate_and_set_reg_param(option+1, user_input_regs))
				{
					printf_filtered ("Error: unsupported register: %s\n", option);
					return;
				}
				user_regs = true;
			}
			else if (strcmp(option, "/v") == 0)
				verbose = true;
			else if (strncmp(option, "from=", 5) == 0)
			{
				/* disassemble from this address instead of function start */
				user_low = parse_and_eval_address(option+5);
			}
			else if (strncmp(option, "to=", 3) == 0)
			{
				user_high = parse_and_eval_address(option+3);
			}
			else if (strncmp(option, "frame=", 6) == 0)
			{
				/* frame=n or frame=n-m */
				const char* subexp = option+6;
				const char* hyphen = strchr(subexp, '-');
				/*
				 * count total number of frames of selected thread
				 * start from the innermost frame
				 */
				int max_frame = 0;
				fi = get_current_frame ();
				while (fi)
				{
					max_frame = frame_relative_level (fi);
					fi = get_prev_frame(fi);
				}
				/* retrieve frame number */
				if (hyphen && hyphen > subexp)
				{
					int k;
					const char* cursor = subexp;
#define NUM_BUF_SZ 32
					char numbuf[NUM_BUF_SZ];
					for (k = 0; k < NUM_BUF_SZ - 1 && *cursor != '-'; k++)
						numbuf[k] = *cursor++;
					numbuf[k] = '\0';
					frame_lo = atoi(numbuf);
					frame_hi = atoi(hyphen + 1);
					/* check the frame number */
					if (frame_lo < 0 || frame_lo > max_frame || frame_hi < 0 || frame_hi > max_frame)
					{
						CA_PRINT("Valid frame # for current thread is [0 - %d]\n", max_frame);
						return;
					}
					else if (frame_lo > frame_hi)
					{
						CA_PRINT("Invalid option %s (frame number %d is bigger than %d)\n",
								option, frame_lo, frame_hi);
						return;
					}
					multi_frame = true;
					frame = frame_hi;
				}
				else
				{
					frame = atoi(option+6);
					if (frame < 0 || frame > max_frame)
					{
						CA_PRINT("Valid frame # for current thread is [0 - %d]\n", max_frame);
						return;
					}
				}
			}
			else
			{
				printf_filtered ("Unknown command argument: %s\n", option);
				return;
			}
		}
	}

	/*
	 * if user chooses a frame other than the current frame
	 * get the frame by number
	 */
	if (frame != frame_relative_level(selected_frame))
	{
		fi = get_current_frame ();
		while (fi)
		{
			if (frame == frame_relative_level(fi))
			{
				selected_frame = fi;
				break;
			}
			fi = get_prev_frame(fi);
		}
	}

	/* disassemble one frame or multiple frames */
	do
	{
		CORE_ADDR pc, dis_hi, sp, func_lo, func_hi;
		const char *funcname;

		g_debug_context.frame_level = frame_relative_level(selected_frame);
		g_debug_context.sp = get_frame_sp (selected_frame);
		g_debug_context.segment = get_segment(g_debug_context.sp, 1);
		/* Get function's instruction address range */
		pc = get_frame_pc (selected_frame); /* include the "call" instr */
		if (frame == 0)
			pc += 1;
		if (find_pc_partial_function (pc, &funcname, &func_lo, &func_hi) == 0)
			error (_("No function contains program counter for selected frame."));
		func_lo += gdbarch_deprecated_function_start_offset (gdbarch);
		/* By default, disassemble from function entry to current instruction */
		dis_hi = pc;

		/* rsp at function entry */
		sp = get_frame_base (selected_frame);	/* sp address before function prologue */
		param_regs[RSP].value = sp - ptr_sz; 	/* "CALL" would push return address on stack */
		param_regs[RSP].has_value = 1;

		/*
		 * For single frame, or the 1st frame of multi-frame disassembling
		 * validate user-input start/end instruction addresses
		 */
		if (!multi_frame || frame == frame_hi)
		{
			if (user_low)
			{
				if (user_low < func_lo || user_low > func_hi)
				{
					printf_filtered ("Error: input start address 0x%lx is out of the function range\n", user_low);
					return;
				}
			}
			else
				user_low = func_lo;
			if (user_high)
			{
				if (user_high < func_lo || user_high > func_hi)
				{
					printf_filtered ("Error: input end address 0x%lx is out of the function range\n", user_high);
					return;
				}
				dis_hi = user_high;
			}
		}

		if (multi_frame)
			CA_PRINT("\n------------------------------ Frame %d ------------------------------\n", frame_relative_level(selected_frame));

		/*
		 * Get the preserved registers' initial values at the entry of the current function
		 * i.e. the values before the function prologue
		 */
		for (i = 0; i < NUM_KNOWN_REGS; i++)
		{
			if ( (ptr_bit == 64 && g_reg_infos[i].preserved_x64)
				|| (ptr_bit == 32 && g_reg_infos[i].preserved_x32) )
			{
				int index = g_reg_infos[i].index;
				if (ca_get_frame_register (selected_frame, g_reg_infos[i].gdb_regnum, &param_regs[index].value))
					param_regs[index].has_value = 1;
			}
		}

		/* parameters at function entry */
		get_function_parameters(gdbarch, selected_frame, param_regs);

		/*
		 * Debugger may know better what registers are saved across function call
		 * mark saved registers
		 */
		if (verbose)
			printf_filtered (_("\nSaved registers:"));
		display_saved_registers(gdbarch, selected_frame, param_regs, verbose);
		if (verbose)
			printf_filtered (_("\n"));

		/* display the registers at function entry */
		if (verbose)
		{
			printf_filtered (_("\nThe following registers are assumed at the beginning: "));
			count = 0;
			for (i=0; i<TOTAL_REGS; i++)
			{
				/* saved RIP is the next instruction address when current function returns */
				if (param_regs[i].has_value && i != RIP)
				{
					if (count > 0)
						printf_filtered (_(", "));
					printf_filtered (_("%s=0x%lx"), g_reg_infos[i].name, param_regs[i].value);
					if (param_regs[i].sym_name)
						printf_filtered (_("(%s)"), param_regs[i].sym_name);
					count++;
				}
			}
			if (count == 0)
				printf_filtered (_("none"));
			printf_filtered (_("\n"));
		}

		printf_filtered ("\nDump of assembler code for function %s:\n", funcname);
		{
			struct decode_control_block decode_cb;

			decode_cb.gdbarch = gdbarch;
			decode_cb.uiout   = uiout;
			decode_cb.low     = user_low;
			decode_cb.high    = dis_hi;
			decode_cb.current = pc;
			decode_cb.func_start = func_lo;
			decode_cb.func_end   = func_hi;
			decode_cb.param_regs = param_regs;
			if (user_regs)
				decode_cb.user_regs = user_input_regs;
			else
				decode_cb.user_regs = NULL;
			decode_cb.verbose    = verbose ? 1:0;
			decode_cb.innermost_frame = frame == 0 ? 1:0;

			decode_insns(&decode_cb);
		}
		printf_filtered ("End of assembler dump.\n");

		/* display registers at the call site if this is not the innermost function */
		if (frame > 0 && verbose)
		{
			printf_filtered (_("\nThe following registers are known at the call: "));
			count = 0;
			for (i=0; i<TOTAL_REGS; i++)
			{
				if (param_regs[i].has_value)
				{
					if (count > 0)
						printf_filtered (_(", "));
					printf_filtered (_("%s=0x%lx"), g_reg_infos[i].name, param_regs[i].value);
					count++;
				}
			}
			if (count == 0)
				printf_filtered (_("none"));
			printf_filtered (_("\n"));
		}

		/* Move to the next frame or wrap up the last one */
		if (multi_frame && frame_relative_level(selected_frame) > frame_lo)
		{
			selected_frame = get_next_frame(selected_frame);
			frame--;
		}
		else
		{
			/*
			 * if there is a next frame, get the saved registers to
			 * collaborate our deduced values
			 */
			if (verbose && frame_relative_level(selected_frame) > 0)
			{
				selected_frame = get_next_frame(selected_frame);
				printf_filtered (_("\nRegisters saved by the next frame:"));
				display_saved_registers(gdbarch, selected_frame, NULL, verbose);
				printf_filtered (_("\n"));
				count = 0;
				printf_filtered (_("\nRegisters preserved by callee:"));
				for (i = 0; i < NUM_KNOWN_REGS; i++)
				{
					if ( (ptr_bit == 64 && g_reg_infos[i].preserved_x64)
						|| (ptr_bit == 32 && g_reg_infos[i].preserved_x32) )
					{
						size_t value;
						if (ca_get_frame_register (selected_frame, g_reg_infos[i].gdb_regnum, &value))
						{
							if (count > 0)
								printf_filtered (_(", "));
							count++;
							printf_filtered (_(" %s=0x%lx"), g_reg_infos[i].name, value);
						}
					}
				}
				if (count == 0)
					printf_filtered (_("none"));
				printf_filtered (_("\n"));
			}
			break;
		}
	} while (1);

	/* scrub and clean register values */
	for (i = 0; i < TOTAL_REGS; i++)
	{
		if (param_regs[i].sym_name)
			free(param_regs[i].sym_name);
		if (user_input_regs[i].sym_name)
			free(user_input_regs[i].sym_name);
	}
	memset(param_regs, 0, REG_SET_SZ);
	memset(user_input_regs, 0, REG_SET_SZ);

	/* flush output */
	gdb_flush (gdb_stdout);

	/* clean up type/context states */
	clear_addr_type_map();
}

/*
 * Display known symbol/type of an instruction's operand value
 */
void
print_op_value_context(size_t op_value, int op_size,
		       address_t loc, int offset, int lea)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct type* type = NULL;
	struct ca_addr_type_pair* addr_type;
	struct object_reference aref;

	/* if op_value is known stack or global symbol */
	if (op_size == ptr_sz && op_value)
	{
		memset(&aref, 0, sizeof(aref));
		aref.vaddr = op_value;
		aref.value = 0;
		aref.target_index = -1;
		fill_ref_location(&aref);
		if ( (aref.storage_type == ENUM_MODULE_TEXT || aref.storage_type == ENUM_MODULE_DATA)
			&& known_global_sym(&aref, NULL, NULL) )
		{
			/* global symbol */
			printf_filtered (" ");
			print_ref(&aref, 0, false, true);
			return;
		}
		else if (aref.storage_type == ENUM_STACK && known_stack_sym(&aref, NULL, NULL))
		{
			/* stack symbol */
			printf_filtered (" ");
			print_ref(&aref, 0, false, true);
			return;
		}
		else if (aref.storage_type == ENUM_HEAP && known_heap_block(&aref))
		{
			/* heap block with known type */
			printf_filtered (" ");
			print_ref(&aref, 0, false, true);
			return;
		}
	}

	/*
	 * we are here because we don't know anything about the op_value
	 * try if we know anything of its source if any
	 */
	if (loc && (addr_type = lookup_type_by_addr(loc)) )
	{
		aref.vaddr = loc + offset;
		aref.value = op_value;
		aref.target_index = 0;

		printf_filtered (" src=[");
		offset += loc - addr_type->addr;
		type = addr_type->type;
		if (addr_type->sym)
		{
			printf_filtered ("%s%s", lea?"&":"", SYMBOL_PRINT_NAME (addr_type->sym));
			if (offset > 0)
			{
				if (TYPE_CODE (type) == TYPE_CODE_PTR || TYPE_CODE (type) == TYPE_CODE_REF)
					type = TYPE_TARGET_TYPE(type);
				print_struct_field(&aref, type, offset);
			}
		}
		else if (type)
		{
			if (offset > 0)
			{
				print_type_name(type, NULL, "\"", "\"");
				print_struct_field(&aref, type, offset);
			}
			else
				print_type_name(type, NULL, "(type=\"", "\")");
		}
		printf_filtered ("]\n");
		return;
	}

	/* lastly, we can still provide something useful, like heap/stack info */
	if (op_size == ptr_sz && op_value)
	{
		aref.vaddr = op_value;
		aref.value = 0;
		aref.target_index = -1;

		if (aref.storage_type != ENUM_UNKNOWN)
		{
			printf_filtered (" ");
			print_ref(&aref, 0, false, true);
			return;
		}
	}

	printf_filtered ("\n");
}

void
calc_heap_usage(char *exp)
{
	expression_up expr;
	struct value *val;

	expr = parse_expression (exp);
	val = evaluate_expression (expr.get());
	if (val && value_type(val))
	{
		struct type *type = value_type (val);
		enum lval_type val_type;
		size_t var_len;
		size_t ptr_sz = g_ptr_bit >> 3;

		check_typedef(type);
		var_len = TYPE_LENGTH(type);
		val_type = value_lval_const (val);

		/* treat all integer (short,int,long), e.g. 0x100, as pointer */
		if (TYPE_CODE(type) == TYPE_CODE_INT)
			var_len = ptr_sz;

		if (var_len >= ptr_sz)
		{
			struct object_reference ref;
			ref.vaddr = 0;
			ref.value = 0;

			if (TYPE_CODE(type) == TYPE_CODE_INT)
			{
				ref.vaddr = value_as_address(val);
				fill_ref_location(&ref);
				if (ref.storage_type != ENUM_HEAP || !ref.where.heap.inuse)
					ref.vaddr = 0;
			}
			else if (val_type == lval_memory)
			{
				ref.vaddr = value_address (val);
				fill_ref_location(&ref);
			}
			else if (val_type == lval_register)
			{
				ref.storage_type = ENUM_REGISTER;
				ref.vaddr = value_as_address(val);
				ref.value = ref.vaddr;
				ref.where.reg.tid = ptid_to_global_thread_id (inferior_ptid);
				ref.where.reg.reg_num = VALUE_REGNUM(val);
				ref.where.reg.name = NULL;
			}
			else
				printf_filtered("Expect input expression is associated with a register or memory\n");

			/* we understand the input expression enough */
			if (ref.vaddr)
			{
				struct inuse_block *inuse_blocks = NULL;
				unsigned long num_inuse_blocks;

				/* First, create and populate an array of all in-use blocks */
				inuse_blocks = build_inuse_heap_blocks(&num_inuse_blocks);
				if (!inuse_blocks || num_inuse_blocks == 0)
				{
					printf_filtered("Failed: no in-use heap block is found\n");
				}
				else
				{
					unsigned long aggr_count = 0;
					size_t aggr_size = 0;

					CA_PRINT("Heap memory consumed by ");
					print_ref(&ref, 0, false, false);
					/* Include all reachable blocks */
					if (calc_aggregate_size(&ref, var_len, true, inuse_blocks, num_inuse_blocks, &aggr_size, &aggr_count))
					{
						CA_PRINT("All reachable:\n");
						CA_PRINT("    |--> ");
						print_size(aggr_size);
						CA_PRINT(" (%ld blocks)\n", aggr_count);
					}
					else
						CA_PRINT("Failed to calculate heap usage\n");
					/* Directly referenced heap blocks only */
					if (calc_aggregate_size(&ref, var_len, false, inuse_blocks, num_inuse_blocks, &aggr_size, &aggr_count))
					{
						CA_PRINT("Directly referenced:\n");
						CA_PRINT("    |--> ");
						print_size(aggr_size);
						CA_PRINT(" (%ld blocks)\n", aggr_count);
					}
					/* remember to cleanup */
					free_inuse_heap_blocks (inuse_blocks, num_inuse_blocks);
				}
			}
			else
				printf_filtered("Input expression doesn't reference any heap memory\n");
		}
		else
			printf_filtered("Input expression doesn't reference any heap memory(type_len=%ld)\n", var_len);
	}
	else
		printf_filtered("Can't understand the input expression\n");
}

/*
 * A simple progress bar for commands taking long time
 */
#define DEFAULT_WIDTH 80
static unsigned long pb_total = 0;
static int screen_width;
static int scrren_height;
static int pb_cur_pos;
void
init_progress_bar(unsigned long total)
{
	pb_total = total;

	screen_width = 0;
	scrren_height = 0;
	rl_get_screen_size(&scrren_height, &screen_width);
	if (screen_width == 0)
		screen_width = DEFAULT_WIDTH;
	pb_cur_pos = 0;
}

void
set_current_progress(unsigned long val)
{
	int pos = val * screen_width / pb_total;
	while (pos > pb_cur_pos)
	{
		CA_PRINT(".");
		pb_cur_pos++;
	}
	fflush (stdout);
}

void
end_progress_bar(void)
{
	CA_PRINT("\n");
}

address_t
ca_eval_address(const char* expr)
{
	return parse_and_eval_address(expr);
}
