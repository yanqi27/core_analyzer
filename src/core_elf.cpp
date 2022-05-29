/************************************************************************
** FILE NAME..... elf64.cpp
**
** (c) COPYRIGHT
**
** FUNCTION......... elf64 core file reader
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
** CHANGES:
**
************************************************************************/
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <vector>

#include "cmd_impl.h"
#include "ca_elf.h"
#include "segment.h"
#include "stl_container.h"

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#ifdef linux
static const char* reg_names[ELF_NGREG] = {
	"%r15",
	"%r14",
	"%r13",
	"%r12",
	"%rbp",
	"%rbx",
	"%r11",
	"%r10",
	"%r9",
	"%r8",
	"%rax",
	"%rcx",
	"%rdx",
	"%rsi",
	"%rdi",
	"%orig_rax",
	"%rip",
	"%cs",
	"%eflags",
	"%rsp",
	"%rss",
	"%thread_fs",
	"%thread_gs",
	"%ds",
	"%es",
	"%fs",
	"%gs"
};

#elif defined(sun)
static const char* reg_names[] = {
	"%g0",
	"%g1",
	"%g2",
	"%g3",
	"%g4",
	"%g5",
	"%g6",
	"%g7",
	"%o0",
	"%o1",
	"%o2",
	"%o3",
	"%o4",
	"%o5",
	"%o6",
	"%o7",
	"%l0",
	"%l1",
	"%l2",
	"%l3",
	"%l4",
	"%l5",
	"%l6",
	"%l7",
	"%i0",
	"%i1",
	"%i2",
	"%i3",
	"%i4",
	"%i5",
	"%i6",
	"%i7",
	"%ccr",
	"%pc",
	"%npc",
	"%y",
	"%asi",
	"%fprs"
};

#endif //linux/sun

typedef unsigned int ptr_t_32;

struct link_map_32
{
	ptr_t_32 l_addr;
	ptr_t_32 l_name;
	ptr_t_32 l_ld;
	ptr_t_32 l_next;
	ptr_t_32 l_prev;
};

struct r_debug_32
{
	int r_version;
	ptr_t_32 r_map; // struct link_map_32
	ptr_t_32 r_brk;
	enum {RT_CONSISTENT, RT_ADD, RT_DELETE} r_state;
	ptr_t_32 r_ldbase;
};

/////////////////////////////////////////////////////////
// Global Vars
/////////////////////////////////////////////////////////
const char* gExecName = NULL;

unsigned int g_ptr_bit = 64;

static struct link_map*    gLinkMap    = NULL;
static struct link_map_32* gLinkMap_32 = NULL;

static std::vector<thread_context *> gThreadVec;

//////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////

#if defined(linux) || defined(__hpux)
#define GetULong(p) (*(p))
#elif defined(sun)
// sparc64 core doesn't align 8-byte type properly
unsigned long GetULong(void* ipData)
{
	unsigned long value;
	// dereference directly if already aligned on long (8 bytes)
	if (((unsigned long)ipData & ~0x7ul) == 0)
		return *(unsigned long*) ipData;
	else if (((unsigned long)ipData & ~0x3ul) == 0)
	{
		// aligned on 4 bytes at least
		int* des = (int*)&value;
		int* src = (int*)ipData;
		*des++ = *src++;
		*des = *src;
	}
	else
	{
		char* des = (char*)&value;
		char* src = (char*)ipData;
		des[0] = src[0];
		des[1] = src[1];
		des[2] = src[2];
		des[3] = src[3];
		des[4] = src[4];
		des[5] = src[5];
		des[6] = src[6];
		des[7] = src[7];
	}
	return value;
}
#endif

#define GetUInt(p) (*(unsigned int*)(p))

#define PN_XNUM 0xffff

/////////////////////////////////////////////////////////
// Called at program starts
/////////////////////////////////////////////////////////
static bool BuildSegments(MmapFile& irCore)
{
	char* lpCoreStart = irCore.GetStartAddr();
	char* lpCoreEnd   = irCore.GetEndAddr();

	static bool done = false;
	if (!done)
	{
		Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)lpCoreStart;
		// Elf64_Ehdr::e_phnum is a unsigned short
		// if number of segments exceeds 0xffff, extension is used.
		int total_phnum;
		if (elfhdr->e_phnum == PN_XNUM)
		{
			// section 0 has the extension info
			Elf64_Shdr* shdr = (Elf64_Shdr*)(lpCoreStart + elfhdr->e_shoff);
			if (shdr->sh_type != SHT_NULL)
			{
				printf("Expected extended section type is SHT_NULL, but get %d\n", shdr->sh_type);
				return false;
			}
			total_phnum = shdr->sh_info;
		}
		else
			total_phnum = elfhdr->e_phnum;

		// Fill up the vector with related info
		size_t lMaxOffset = 0;
		// build up thread and stack list
		for(int i=0; i<total_phnum; i++)
		{
			Elf64_Phdr* phdr = (Elf64_Phdr*) (lpCoreStart + elfhdr->e_phoff + i * elfhdr->e_phentsize);

			// NOTE segment is an array of note entries.
			/*
			**	the structure of a note entry
			**
			**		  	   |-----------|
			**		  	   |  namesz   |
			**		  	   |-----------|
			**		  	   |  descsz   |
			**		  	   |-----------|
			**		  	   |   type    |
			**		  	   |-----------|
			**		  	   |   name    |
			**		  	   |-----------|
			**		  	   |   desc    |
			**		  	   |-----------|
			*/
			if (phdr->p_type == PT_NOTE)
			{
				char* lpNextEntry = lpCoreStart + phdr->p_offset;
				while (lpNextEntry - (lpCoreStart + phdr->p_offset) < phdr->p_filesz)
				{
					Elf64_Nhdr* elfnote = (Elf64_Nhdr *)lpNextEntry;
					const char* name = (char*)(elfnote + 1);
					// process status is essentially a thread context
#ifdef linux
					if (elfnote->n_type == NT_PRSTATUS)
					{
						thread_context *prstat = (thread_context *)(name + ALIGN_LONG(elfnote->n_namesz));
						gThreadVec.push_back(prstat);
					}
					else if (elfnote->n_type == NT_PRPSINFO)
					{
						struct elf_prpsinfo *prpsinfo = (struct elf_prpsinfo *)(name + ALIGN_LONG(elfnote->n_namesz));
						gExecName = prpsinfo->pr_fname;
					}
					lpNextEntry += sizeof(Elf64_Nhdr) + ALIGN_LONG(elfnote->n_namesz) + ALIGN_LONG(elfnote->n_descsz);
#elif defined(sun)
					if (elfnote->n_type == NT_LWPSTATUS)
					{
						thread_context *lwp = (thread_context *)(name + ALIGN_FOUR(elfnote->n_namesz));
						gThreadVec.push_back(lwp);
					}
					lpNextEntry += sizeof(Elf64_Nhdr) + ALIGN_FOUR(elfnote->n_namesz) + ALIGN_FOUR(elfnote->n_descsz);
#elif defined(__hpux)
#endif
				}
			}
			// NOTE segment is always the first segment in core followed by many LOAD segments
			// we should have thread list ready now.
			else if (phdr->p_type == PT_LOAD)
			{
				//ca_segment* a_seg = new ca_segment(phdr->p_vaddr, phdr->p_memsz,
				//								lpCoreStart + phdr->p_offset, phdr->p_filesz,
				//								phdr->p_flags);
				//g_segments.push_back(a_seg);
				struct ca_segment* a_seg = add_one_segment(phdr->p_vaddr,
												phdr->p_memsz,
												phdr->p_flags & PERMISSION_R,
												phdr->p_flags & PERMISSION_W,
												phdr->p_flags & PERMISSION_X);
				if (a_seg)
				{
					a_seg->m_faddr = lpCoreStart + phdr->p_offset;
					a_seg->m_fsize = phdr->p_filesz;
				}
				if (phdr->p_offset + phdr->p_filesz > lMaxOffset)
					lMaxOffset = phdr->p_offset + phdr->p_filesz;
			}
		}
		// Warn if core is truncated
		if (lMaxOffset > irCore.GetFileSize())
			printf("\n!!Warning!! Process image has %ld bytes while core file is only %ld bytes\n", lMaxOffset, irCore.GetFileSize());

		// now set all segments that are thread stacks.
		for (int tindex=0; tindex<gThreadVec.size(); tindex++)
		{
			thread_context* lpThreadCnxt = gThreadVec[tindex];
			unsigned long rsp = GET_RSP(lpThreadCnxt);

			for (int i=0; i<g_segment_count; i++)
			{
				ca_segment* segment = &g_segments[i];
				// stack has to be writable and non-zero size
				if (segment->m_write && segment->m_fsize > 0
					&& rsp > segment->m_vaddr && rsp < segment->m_vaddr + segment->m_vsize)
				{
					segment->m_type = ENUM_STACK;
					segment->m_thread.context = gThreadVec[tindex];
#ifdef linux
					segment->m_thread.tid = tindex+1;
					//segment->m_thread.tid        = lpThreadCnxt->pr_pid;
#elif defined(sun)
					segment->m_thread.tid = lpThreadCnxt->pr_lwpid;
#endif
					break;
				}
			}
		}

		done = true;
	}
	return true;
}

static bool BuildSegments_32(MmapFile& irCore)
{
	char* lpCoreStart = irCore.GetStartAddr();
	char* lpCoreEnd   = irCore.GetEndAddr();

	static bool done = false;
	if (!done)
	{
		Elf32_Ehdr* elfhdr = (Elf32_Ehdr*)lpCoreStart;
		// Elf32_Ehdr::e_phnum is a unsigned short
		// if number of segments exceeds 0xffff, extension is used.
		int total_phnum;
		if (elfhdr->e_phnum == PN_XNUM)
		{
			// section 0 has the extension info
			Elf32_Shdr* shdr = (Elf32_Shdr*)(lpCoreStart + elfhdr->e_shoff);
			if (shdr->sh_type != SHT_NULL)
			{
				printf("Expected extended section type is SHT_NULL, but get %d\n", shdr->sh_type);
				return false;
			}
			total_phnum = shdr->sh_info;
		}
		else
			total_phnum = elfhdr->e_phnum;

		// Fill up the vector with related info
		unsigned int lMaxOffset = 0;
		// build up thread and stack list
		for(int i=0; i<total_phnum; i++)
		{
			Elf32_Phdr* phdr = (Elf32_Phdr*) (lpCoreStart + elfhdr->e_phoff + i * elfhdr->e_phentsize);

			// NOTE segment is an array of note entries.
			/*
			**	the structure of a note entry
			**
			**		  	   |-----------|
			**		  	   |  namesz   |
			**		  	   |-----------|
			**		  	   |  descsz   |
			**		  	   |-----------|
			**		  	   |   type    |
			**		  	   |-----------|
			**		  	   |   name    |
			**		  	   |-----------|
			**		  	   |   desc    |
			**		  	   |-----------|
			*/
			if (phdr->p_type == PT_NOTE)
			{
				char* lpNextEntry = lpCoreStart + phdr->p_offset;
				while (lpNextEntry - (lpCoreStart + phdr->p_offset) < phdr->p_filesz)
				{
					Elf32_Nhdr* elfnote = (Elf32_Nhdr *)lpNextEntry;
					const char* name = (char*)(elfnote + 1);
					// process status is essentially a thread context
#ifdef linux
					if (elfnote->n_type == NT_PRSTATUS)
					{
						thread_context *prstat = (thread_context *)(name + ALIGN_LONG(elfnote->n_namesz));
						gThreadVec.push_back(prstat);
					}
					else if (elfnote->n_type == NT_PRPSINFO)
					{
						struct elf_prpsinfo *prpsinfo = (struct elf_prpsinfo *)(name + ALIGN_LONG(elfnote->n_namesz));
						gExecName = prpsinfo->pr_fname;
					}
					lpNextEntry += sizeof(Elf32_Nhdr) + ALIGN_FOUR(elfnote->n_namesz) + ALIGN_FOUR(elfnote->n_descsz);
#elif defined(sun)
					if (elfnote->n_type == NT_LWPSTATUS)
					{
						thread_context *lwp = (thread_context *)(name + ALIGN_FOUR(elfnote->n_namesz));
						gThreadVec.push_back(lwp);
					}
					lpNextEntry += sizeof(Elf32_Nhdr) + ALIGN_FOUR(elfnote->n_namesz) + ALIGN_FOUR(elfnote->n_descsz);
#elif defined(__hpux)
#endif
				}
			}
			// NOTE segment is always the first segment in core followed by many LOAD segments
			// we should have thread list ready now.
			else if (phdr->p_type == PT_LOAD)
			{
				struct ca_segment* a_seg = add_one_segment(phdr->p_vaddr,
												phdr->p_memsz,
												phdr->p_flags & PERMISSION_R,
												phdr->p_flags & PERMISSION_W,
												phdr->p_flags & PERMISSION_X);
				if (a_seg)
				{
					a_seg->m_faddr = lpCoreStart + phdr->p_offset;
					a_seg->m_fsize = phdr->p_filesz;
				}
				if (phdr->p_offset + phdr->p_filesz > lMaxOffset)
					lMaxOffset = phdr->p_offset + phdr->p_filesz;
			}
		}
		// Warn if core is truncated
		if (lMaxOffset > irCore.GetFileSize()) {
			printf("\n!!Warning!! Process image has %d bytes "
			    "while core file is only %ld bytes\n", lMaxOffset,
			    irCore.GetFileSize());
		}

		// now set all segments that are thread stacks.
		for (int tindex=0; tindex<gThreadVec.size(); tindex++)
		{
			thread_context* lpThreadCnxt = gThreadVec[tindex];
			unsigned int rsp = GET_RSP(lpThreadCnxt);

			for (int i=0; i<g_segment_count; i++)
			{
				ca_segment* segment = &g_segments[i];
				// stack has to be writable and non-zero size
				if (segment->m_write && segment->m_fsize > 0
					&& rsp > segment->m_vaddr && rsp < segment->m_vaddr + segment->m_vsize)
				{
					segment->m_type = ENUM_STACK;
					segment->m_thread.context = gThreadVec[tindex];
#ifdef linux
					segment->m_thread.tid = tindex+1;
					//segment->m_thread.tid        = lpThreadCnxt->pr_pid;
#elif defined(sun)
					segment->m_thread.tid = lpThreadCnxt->pr_lwpid;
#endif
					break;
				}
			}
		}

		done = true;
	}
	return true;
}

static bool InitLinkMap(MmapFile& irExec, MmapFile& irCore)
{
	char* lpExecStart = irExec.GetStartAddr();
	char* lpCoreStart = irCore.GetStartAddr();
	char* lpCoreEnd   = irCore.GetEndAddr();

	Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)lpExecStart;

	// search for .dynamic section
	Elf64_Dyn* dyn = NULL;
	Elf64_Xword dyn_size = 0;

	Elf64_Shdr* shdr = (Elf64_Shdr*)(lpExecStart + elfhdr->e_shoff);
	Elf64_Shdr* shstrtbl = shdr + elfhdr->e_shstrndx;
	char* shstr = lpExecStart + shstrtbl->sh_offset;
	for (int i=0; i < elfhdr->e_shnum; i++)
	{
		if (0 == strcmp(shstr+shdr->sh_name, ".dynamic")
			&& shdr->sh_type == SHT_DYNAMIC)
		{
			dyn = (Elf64_Dyn*) shdr->sh_addr;
			dyn_size = shdr->sh_size;
			//printf("Exec's .dynamic section vaddr = 0x%lx\n", dyn);
			break;
		}
		shdr++;
	}

	if (!dyn)
	{
		printf("Failed to find Exec's .dynamic\n");
		return false;
	}

	// The content of .dynamic section is in core
	Elf64_Dyn* core_dyn = (Elf64_Dyn*) core_to_mmap_addr((address_t)dyn);
	if (!core_dyn)
	{
		printf("Failed to find Exec's .dynamic section in core\n");
		return false;
	}

	// Find the DT_DEBUG entry in the the .dynamic section.
	Elf64_Dyn* debug_dyn = NULL;
	for (dyn = core_dyn; (char*)dyn - (char*)core_dyn < dyn_size; dyn++)
	{
		if (GetULong(&dyn->d_tag) == DT_DEBUG)
		{
			debug_dyn = dyn;
			break;
		}
	}

	if (!debug_dyn)
	{
		printf("Failed to find debug_dyn\n");
		return false;
	}

	// If the executable's dynamic section has a DT_DEBUG element,
	// the run-time linker sets that element's value to the address
	// where this struct r_debug (link.h) can be found.
	struct r_debug* pdebug = (struct r_debug*)GetULong(&debug_dyn->d_un.d_ptr);
	pdebug = (struct r_debug*) core_to_mmap_addr((address_t)pdebug);
	if (!pdebug)
	{
		printf("Failed to find link map in core\n");
		return false;
	}
	gLinkMap = (struct link_map *) core_to_mmap_addr((address_t)GetULong(&pdebug->r_map));
	if (!gLinkMap)
	{
		printf("Failed to find link map in core\n");
		return false;
	}

	// set executable and library segments.
	struct link_map * linkmap = gLinkMap;
	while (linkmap && (char*)linkmap > lpCoreStart && (char*)linkmap < lpCoreEnd)
	{
		ca_segment* segment = NULL;
#ifdef sun
		address_t load_addr = GetULong(&linkmap->l_addr);
		if (! (segment = get_segment(load_addr, 1) ) )
			break;
#endif
		Elf64_Dyn* dyn = (Elf64_Dyn*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_ld));

		for (; (char*)dyn >lpCoreStart && (char*)dyn < lpCoreEnd; dyn++)
		{
			Elf64_Xword tag = GetULong(&dyn->d_tag);
			if (tag == DT_NULL)
				break;
#ifdef linux
			address_t vaddr = GetULong(&dyn->d_un.d_ptr);
#elif defined(sun)
			address_t vaddr = load_addr + GetULong(&dyn->d_un.d_ptr);
#endif
			if (vaddr)
			{
				// The segment is likely the same as previous dynamic section
				if (!segment || vaddr < segment->m_vaddr || vaddr >= segment->m_vaddr + segment->m_vsize)
					segment = get_segment(vaddr, 1);

				if (segment && segment->m_type == ENUM_UNKNOWN)
				{
					if (segment->m_write)
						segment->m_type = ENUM_MODULE_DATA;
					else
						segment->m_type = ENUM_MODULE_TEXT;

					segment->m_module_name = (char*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_name));
#ifdef linux
					if (segment->m_module_name == NULL)
					{
						if (linkmap == gLinkMap)
							segment->m_module_name = gpInputExecName;
						else
							segment->m_module_name = "/lib64/ld-linux-x86-64.so.2";
					}
#endif
				}
			}
		}

		if ((address_t)GetULong(&linkmap->l_next) == 0)
			break;

		linkmap = (struct link_map*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_next));
		if (linkmap == gLinkMap)
			break;
	}

#ifdef CA_DEBUG
	linkmap = gLinkMap;
	for (int i=0; linkmap; i++)
	{
		char* name = (char*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_name));

		// find the strtab
		void* strtab = NULL;
		dyn = (Elf64_Dyn*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_ld));
		while (dyn && GetULong(&dyn->d_tag))
		{
			if (GetULong(&dyn->d_tag) == DT_STRTAB)
				strtab = (void*)GetULong(&dyn->d_un.d_ptr);
			dyn++;
		};

		printf("[%d] base=[0x%lx] name=%s .dyn=0x%lx\n", i, GetULong(&linkmap->l_addr), name, GetULong(&linkmap->l_ld));
		if (linkmap->l_next == NULL)
			break;
		linkmap = (struct link_map*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_next));
		if (linkmap == gLinkMap)
			break;
	}
#endif
	return true;
}

static bool InitLinkMap_32(MmapFile& irExec, MmapFile& irCore)
{
	char* lpExecStart = irExec.GetStartAddr();
	char* lpCoreStart = irCore.GetStartAddr();
	char* lpCoreEnd   = irCore.GetEndAddr();

	Elf32_Ehdr* elfhdr = (Elf32_Ehdr*)lpExecStart;

	// search for .dynamic section
	Elf32_Dyn* dyn = NULL;
#if defined(linux)
	Elf32_Xword dyn_size = 0;
#elif defined(sun)
	Elf32_Word dyn_size = 0;
#endif
	Elf32_Shdr* shdr = (Elf32_Shdr*)(lpExecStart + elfhdr->e_shoff);
	Elf32_Shdr* shstrtbl = shdr + elfhdr->e_shstrndx;
	char* shstr = lpExecStart + shstrtbl->sh_offset;
	for (int i=0; i < elfhdr->e_shnum; i++)
	{
		if (0 == strcmp(shstr+shdr->sh_name, ".dynamic")
			&& shdr->sh_type == SHT_DYNAMIC)
		{
			dyn = (Elf32_Dyn*) shdr->sh_addr;
			dyn_size = shdr->sh_size;
			//printf("Exec's .dynamic section vaddr = 0x%lx\n", dyn);
			break;
		}
		shdr++;
	}

	if (!dyn)
	{
		printf("Failed to find Exec's .dynamic\n");
		return false;
	}

	// The content of .dynamic section is in core
	Elf32_Dyn* core_dyn = (Elf32_Dyn*) core_to_mmap_addr((address_t)dyn);
	if (!core_dyn)
	{
		printf("Failed to find Exec's .dynamic section in core\n");
		return false;
	}

	// Find the DT_DEBUG entry in the the .dynamic section.
	Elf32_Dyn* debug_dyn = NULL;
	for (dyn = core_dyn; (char*)dyn - (char*)core_dyn < dyn_size; dyn++)
	{
		if (GetUInt(&dyn->d_tag) == DT_DEBUG)
		{
			debug_dyn = dyn;
			break;
		}
	}

	if (!debug_dyn)
	{
		printf("Failed to find debug_dyn\n");
		return false;
	}

	// If the executable's dynamic section has a DT_DEBUG element,
	// the run-time linker sets that element's value to the address
	// where this struct r_debug (link.h) can be found.
	struct r_debug_32* pdebug = (struct r_debug_32*)GetUInt(&debug_dyn->d_un.d_ptr);
	pdebug = (struct r_debug_32*) core_to_mmap_addr((address_t)pdebug);
	if (!pdebug)
	{
		printf("Failed to find link map in core\n");
		return false;
	}
	gLinkMap_32 = (struct link_map_32 *) core_to_mmap_addr((address_t)GetUInt(&pdebug->r_map));
	if (!gLinkMap_32)
	{
		printf("Failed to find link map in core\n");
		return false;
	}

	// set executable and library segments.
	struct link_map_32 * linkmap = gLinkMap_32;
	while (linkmap && (char*)linkmap > lpCoreStart && (char*)linkmap < lpCoreEnd)
	{
		ca_segment* segment = NULL;
#ifdef sun
		address_t load_addr = GetUInt(&linkmap->l_addr);
		if (! (segment = get_segment(load_addr, 1) ) )
			break;
#endif
		Elf32_Dyn* dyn = (Elf32_Dyn*) core_to_mmap_addr((address_t)GetUInt(&linkmap->l_ld));

		for (; (char*)dyn >lpCoreStart && (char*)dyn < lpCoreEnd; dyn++)
		{
#if defined(linux)
			Elf32_Xword tag = GetUInt(&dyn->d_tag);
#elif defined(sun)
			Elf32_Sword tag = GetUInt(&dyn->d_tag);
#endif
			if (tag == DT_NULL)
				break;
#ifdef linux
			address_t vaddr = GetUInt(&dyn->d_un.d_ptr);
#elif defined(sun)
			address_t vaddr = load_addr + GetUInt(&dyn->d_un.d_ptr);
#endif
			if (vaddr)
			{
				// The segment is likely the same as previous dynamic section
				if (!segment || vaddr < segment->m_vaddr || vaddr >= segment->m_vaddr + segment->m_vsize)
					segment = get_segment(vaddr, 1);

				if (segment && segment->m_type == ENUM_UNKNOWN)
				{
					if (segment->m_write)
						segment->m_type = ENUM_MODULE_DATA;
					else
						segment->m_type = ENUM_MODULE_TEXT;

					segment->m_module_name = (char*) core_to_mmap_addr((address_t)GetUInt(&linkmap->l_name));
#ifdef linux
					if (segment->m_module_name == NULL)
					{
						if (linkmap == gLinkMap_32)
							segment->m_module_name = gpInputExecName;
						else
							segment->m_module_name = "/lib/ld-linux-x86-64.so.2";
					}
#endif
				}
			}
		}

		if ((address_t)GetUInt(&linkmap->l_next) == 0)
			break;

		linkmap = (struct link_map_32*) core_to_mmap_addr((address_t)GetULong(&linkmap->l_next));
		if (linkmap == gLinkMap_32)
			break;
	}

#ifdef CA_DEBUG
	linkmap = gLinkMap_32;
	for (int i=0; linkmap; i++)
	{
		char* name = (char*) core_to_mmap_addr((address_t)GetUInt(&linkmap->l_name));

		// find the strtab
		void* strtab = NULL;
		dyn = (Elf32_Dyn*) core_to_mmap_addr((address_t)GetUInt(&linkmap->l_ld));
		while (dyn && GetUInt(&dyn->d_tag))
		{
			if (GetUInt(&dyn->d_tag) == DT_STRTAB)
				strtab = (void*)GetUInt(&dyn->d_un.d_ptr);
			dyn++;
		};

		printf("[%d] base=[0x%lx] name=%s .dyn=0x%lx\n", i, GetUInt(&linkmap->l_addr), name, GetUInt(&linkmap->l_ld));
		if (linkmap->l_next == 0)
			break;
		linkmap = (struct link_map_32*) core_to_mmap_addr((address_t)GetUInt(&linkmap->l_next));
		if (linkmap == gLinkMap_32)
			break;
	}
#endif
	return true;
}

//////////////////////////////////////////////////////////////
// First parse of the core file
//////////////////////////////////////////////////////////////
bool InitCoreAnalyzer(MmapFile& irExec, MmapFile& irCore)
{
	int ptr_bit = g_ptr_bit;
	bool rc;
	if (ptr_bit == 64)
		rc = BuildSegments(irCore);
	else
		rc = BuildSegments_32(irCore);
	if (!rc)
		return false;

	if (!test_segments(true))
		return false;


	if (ptr_bit == 64)
		rc = InitLinkMap (irExec, irCore);
	else
		rc = InitLinkMap_32 (irExec, irCore);

	return init_heap_managers();
}

static bool VerifyELFHeader(Elf64_Ehdr* elfhdr )
{
	// Check elf magic bytes
	if (strncmp((char*)elfhdr->e_ident, ELFMAG, SELFMAG))
	{
		fprintf(stderr, "[Error] Not ELF file\n");
		return false;
	}

	// elf only
	if (elfhdr->e_ident[EI_CLASS] != ELFCLASS64)
	{
		fprintf(stderr, "[Error] Only ELF is supported\n");
		return false;
	}

	// supported archs
#ifdef __hpux
	if (elfhdr->e_machine != EM_IA_64)
#else
	if (elfhdr->e_machine != EM_X86_64
		&& elfhdr->e_machine != EM_SPARCV9)
#endif
	{
		printf("[Error] acceptable architectures: x86_64, sparcv9, ia64\n");
		return false;
	}
	return true;
}

static bool VerifyELFHeader_32(Elf32_Ehdr* elfhdr )
{
	// Check elf magic bytes
	if (strncmp((char*)elfhdr->e_ident, ELFMAG, SELFMAG))
	{
		fprintf(stderr, "[Error] Not ELF file\n");
		return false;
	}

	// elf 32 and 64 only
	if (elfhdr->e_ident[EI_CLASS] != ELFCLASS32)
	{
		fprintf(stderr, "[Error] Only ELF is supported\n");
		return false;
	}

	// supported archs
#ifdef __hpux
	if (elfhdr->e_machine != EM_IA_32)
#else
	if (elfhdr->e_machine != EM_386
		&& elfhdr->e_machine != EM_SPARC
		&& elfhdr->e_machine != EM_SPARC32PLUS)
#endif
	{
		printf("[Error] acceptable architectures: 386, sparc, sparc32plus, ia32\n");
		return false;
	}
	return true;
}

//////////////////////////////////////////////////////////////
// Sanity check of exec file
//////////////////////////////////////////////////////////////
bool VerifyExecFile(char* ipExecStart)
{
	if (g_ptr_bit == 64)
	{
		Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)ipExecStart;
		// ELF file type
		if (elfhdr->e_type != ET_EXEC)
		{
			fprintf(stderr, "[Error] File is NOT an executable \n");
			return false;
		}
		return VerifyELFHeader(elfhdr);
	}
	else
	{
		Elf32_Ehdr* elfhdr = (Elf32_Ehdr*)ipExecStart;
		// ELF file type
		if (elfhdr->e_type != ET_EXEC)
		{
			fprintf(stderr, "[Error] File is NOT an executable \n");
			return false;
		}
		return VerifyELFHeader_32(elfhdr);
	}
}

//////////////////////////////////////////////////////////////
// Sanity check of core file
// It also sets the g_ptr_bit
//////////////////////////////////////////////////////////////
bool VerifyCoreFile(char* ipCoreStart)
{
	Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)ipCoreStart;
	Elf32_Ehdr* elfhdr32 = (Elf32_Ehdr*)ipCoreStart;

	// Check elf magic bytes
	if (strncmp((char*)elfhdr->e_ident, ELFMAG, SELFMAG) == 0
		&& elfhdr->e_ident[EI_CLASS] == ELFCLASS64
		&& (elfhdr->e_machine == EM_X86_64 || elfhdr->e_machine == EM_SPARCV9)
		&& elfhdr->e_type == ET_CORE)
	{
		g_ptr_bit = 64;
	}
	else if (strncmp((char*)elfhdr32->e_ident, ELFMAG, SELFMAG) == 0
			&& elfhdr32->e_ident[EI_CLASS] == ELFCLASS32
			&& (elfhdr->e_machine == EM_386 || elfhdr->e_machine == EM_SPARC)
			&& elfhdr32->e_type == ET_CORE)
	{
		g_ptr_bit = 32;
	}
	else
	{
		fprintf(stderr, "[Error] Core file is NOT a ELF32/64 core\n");
		return false;
	}
	return true;
}

int get_thread_id (const struct ca_segment* segment)
{
	return segment->m_thread.tid;
}

address_t get_rsp(const struct ca_segment* segment)
{
	thread_context* lpThreadContext = (thread_context*) segment->m_thread.context;
	unsigned long rsp = GET_RSP(lpThreadContext);
	return rsp;
}

int read_registers(const struct ca_segment* segment, struct reg_value* regs, int bufsz)
{
	int ptr_sz = g_ptr_bit >> 3;
	if (regs)
	{
		if (bufsz >= TOTAL_REGS)
		{
			thread_context* lpThreadContext = (thread_context*) segment->m_thread.context;
			for (int i=0; i<TOTAL_REGS; i++)
			{
				unsigned long r_val = ptr_sz == 8 ? GetULong(&lpThreadContext->pr_reg[i]) : GetUInt(&lpThreadContext->pr_reg[i]);
				regs[i].reg_num = i;
				regs[i].reg_width = ptr_sz;
				regs[i].value = (address_t) r_val;
			}
			return TOTAL_REGS;
		}
	}
	else
		return TOTAL_REGS;

	return 0;
}

bool search_registers(const struct ca_segment*segment,
    struct CA_LIST* targets, struct CA_LIST* refs)
{
	int ptr_sz = g_ptr_bit >> 3;

	if (segment->m_type != ENUM_STACK)
		return false;

	bool lbFound = false;

	thread_context* lpThreadContext = (thread_context*) segment->m_thread.context;
	for (int i=0; i<TOTAL_REGS; i++)
	{
		unsigned long r_val = ptr_sz == 8 ? GetULong(&lpThreadContext->pr_reg[i]) : GetUInt(&lpThreadContext->pr_reg[i]);
		struct object_range* target;
		ca_list_traverse_start(targets);
		while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
		{
			if (r_val >= target->low && r_val < target->high)
			{
				struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
				ref->storage_type  = ENUM_REGISTER;
				ref->where.reg.tid = segment->m_thread.tid;
				ref->where.reg.reg_num = i;
				ref->where.reg.name    = reg_names[i];
				ref->vaddr        = 0;
				ref->value        = r_val;
				ca_list_push_front(refs, ref);
				lbFound = true;
				break;
			}
		}
	}

	return lbFound;
}

int get_frame_number(const struct ca_segment* segment, address_t vaddr, int* offset)
{
	int frame_num;
	thread_context* lpThreadContext = (thread_context*) segment->m_thread.context;
	unsigned long rsp = GET_RSP(lpThreadContext);
	*offset = (int) (vaddr - rsp);
	if (vaddr < rsp)
	{
		frame_num = -1;
	}
	else
	{
		frame_num = 0;
#ifdef sun
		// we can get frame# on sparcv9
		// This doesn't account for leaf function, hence may under-count frame#
		const char* start = segment->m_faddr;
		for (frame_num=1; ;frame_num++)
		{
			struct frame* pframe = (struct frame*) (start + (rsp - segment->m_vaddr));
			unsigned long next_rsp = GetULong(&pframe->fr_savfp) + 2047;
			if (next_rsp > rsp)
			{
				if (vaddr>=rsp && vaddr<next_rsp)
				{
					break;
				}
				rsp = next_rsp;
			}
			else
				break;
		}
#endif
	}
	return frame_num;
}

const char* get_register_name(int tid)
{
	if (tid >= 0 && tid < TOTAL_REGS)
		return reg_names[tid];
	else
		return NULL;
}
