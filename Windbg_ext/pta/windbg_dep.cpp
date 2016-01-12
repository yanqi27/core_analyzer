/*
 * windbg_dep.cpp
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <vector>
#include <map>

#include "ref.h"
#include "segment.h"
#include "search.h"
#include "heap.h"
#include "stl_container.h"
#include "decode.h"

struct addr_type_pair
{
	ULONG64 addr;
	struct win_type type;
};

struct stack_symbol
{
	ULONG frame;
	ULONG size;
	ULONG64 offset;
	char* name;
	struct win_type type;
};

typedef std::vector<struct stack_symbol*> stack_symbols;

struct frame_info
{
	ULONG   frame_no;
	ULONG64 rbp;
	ULONG64 rsp;
};

typedef std::vector<struct frame_info> frames_t;

/////////////////////////////////////////////////////
// Global Variables
/////////////////////////////////////////////////////
#define MAX_MODULES 512
#define MAX_FRAMES 128
#define SYS_PAGE_SZ 0x1000

bool g_debug_core = false;

unsigned int g_ptr_bit = 64;
static const char* g_sp_name = "rsp";

static ULONG g_total_threads = 0;
static std::vector<stack_symbols*> g_all_stack_symbols;
static std::vector<frames_t*> g_all_stack_frames;

static struct addr_type_pair* addr_type_map = NULL;
static unsigned int addr_type_map_sz = 0;
static unsigned int addr_type_map_buf_sz = 0;

extern PDEBUG_CLIENT4 gClient;

struct ca_debug_context g_debug_context;

/////////////////////////////////////////////////////
// Forward functions
/////////////////////////////////////////////////////
static bool mmap_core_file(const char* fname);
static void print_struct_field(const struct object_reference*, struct win_type, ULONG);
static bool get_typeinfo(struct win_type, ULONG64, EXT_TYPED_DATA&, bool);
static struct addr_type_pair* lookup_type_by_addr(const struct object_reference*);
static struct stack_symbol* get_stack_sym(const struct object_reference*);
static CA_BOOL resolve_or_print_global_ref(const struct object_reference*, CA_BOOL, address_t*, size_t*);
static bool is_process_segment_changed();
static void release_cached_stack_symbols();
static void release_frame_info_cache();
static bool build_frame_info_cache(int);
static struct stack_symbol* search_cached_stack_symbols(const struct object_reference*);
static void add_addr_type(ULONG64, struct win_type);

/////////////////////////////////////////////////////
// Exposed functions
/////////////////////////////////////////////////////
bool inferior_memory_read (address_t addr, void* buffer, size_t sz)
{
	ULONG cb;
	if (!ReadMemory(addr, buffer, sz, &cb) || cb != sz)
		return false;
	return true;
}

void print_type_name(struct win_type type)
{
	HRESULT hr;
	char type_name[NAME_BUF_SZ];
	ULONG name_sz;
	hr = gDebugSymbols3->GetTypeName(type.mod_base, type.type_id, type_name, NAME_BUF_SZ, &name_sz);
	if (SUCCEEDED(hr) && name_sz < NAME_BUF_SZ)
		dprintf(type_name);
}

void print_heap_ref(const struct object_reference* ref)
{
	HRESULT hr;
	if (ref->where.heap.inuse)
	{
		char type_name[NAME_BUF_SZ];
		struct addr_type_pair* addr_type;
		bool found_type = false;
		ULONG64 mod_base;
		ULONG type_id, type_sz;
		// Get _vptr name .. type_id .. type_sz
		if (is_heap_object_with_vptr(ref, type_name, NAME_BUF_SZ)
			&& gDebugSymbols3->GetSymbolTypeId(type_name, &type_id, &mod_base) == S_OK
			&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK)
		{
			found_type = true;
		}
		else if (addr_type = lookup_type_by_addr(ref))
		{
			ULONG name_sz;
			hr = gDebugSymbols3->GetTypeName(addr_type->type.mod_base, addr_type->type.type_id, type_name, NAME_BUF_SZ, &name_sz);
			if (SUCCEEDED(hr) && name_sz < NAME_BUF_SZ)
			{
				found_type = true;
				mod_base = addr_type->type.mod_base;
				type_id  = addr_type->type.type_id;
				if (gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) != S_OK)
					type_sz = 0;
			}
		}
		// Process known type
		if (found_type && type_name[0])
		{
			struct win_type type;
			type.mod_base = mod_base;
			type.type_id  = type_id;
			if (type_sz > sizeof(address_t))
				dprintf(" (type=\"%s\" size=%d)", type_name, type_sz);
			if ((ref->value || ref->vaddr != ref->where.heap.addr) && ref->vaddr < ref->where.heap.addr + type_sz)
				print_struct_field(ref, type, (ULONG)(ref->vaddr - ref->where.heap.addr));
		}
	}
	else
		dprintf(" FREE");
}

/*
 * Return true if the input addr starts with a _vptr
 */
bool is_heap_object_with_vptr(const struct object_reference* ref, char* type_name, size_t name_buf_sz)
{
	bool rs = false;
	address_t addr = ref->where.heap.addr;
	address_t val;
	if (read_memory_wrapper(NULL, addr, (void*)&val, sizeof(address_t)) && val)
	{
		struct ca_segment* segment = get_segment(val, 1);
		if (segment && (segment->m_type == ENUM_MODULE_DATA || segment->m_type == ENUM_MODULE_TEXT))
		{
			/*
			 * the first data belongs to a module's data section, it is likely a vptr
			 * to be sure, check its symbol
			 */
			char type_name_buf[NAME_BUF_SZ];
			ULONG name_sz;
			ULONG64 displacement = 0;
			char* cursor;
			char* syn_name;
			if (!type_name)
			{
				type_name = type_name_buf;
				name_buf_sz = NAME_BUF_SZ;
			}
			HRESULT hr = gDebugSymbols3->GetNameByOffset(val, type_name, name_buf_sz, &name_sz, &displacement);
			if (SUCCEEDED(hr) && displacement == 0 &&
				((cursor = strstr(type_name, "::`vftable'")) || (cursor = strstr(type_name, "::`vbtable'"))) )
			{
				*cursor = '\0';	// type name is w/o suffix `vftable' or `vbtable'
				ULONG type_id, type_sz;
				ULONG64 mod_base;
				// Compare type size vs heap block size
				if (gDebugSymbols3->GetSymbolTypeId(type_name, &type_id, &mod_base) == S_OK
					&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK
					&& ref->vaddr < addr + type_sz)
					rs = true;
			}
		}
	}
	return rs;
}

void print_register_ref(const struct object_reference* ref)
{
	if (g_debug_context.tid != ref->where.stack.tid)
		dprintf(" thread %d", ref->where.reg.tid);

	char reg_name[NAME_BUF_SZ];
	HRESULT hr = gDebugRegisters2->GetDescription(ref->where.reg.reg_num, reg_name, NAME_BUF_SZ, NULL, NULL);
	if (SUCCEEDED(hr))
		CA_PRINT(" %s="PRINT_FORMAT_POINTER, reg_name, ref->value);
	else
		CA_PRINT(" reg[%d]="PRINT_FORMAT_POINTER, ref->where.reg.reg_num, ref->value);
}

void print_stack_ref(const struct object_reference* ref)
{
	bool found_sym = false;
	bool same_thread = true;
	if (g_debug_context.tid != ref->where.stack.tid)
	{
		dprintf(" thread %d frame %d", ref->where.stack.tid, ref->where.stack.frame);
		same_thread = false;
	}

	if (ref->where.stack.frame >= 0)
	{
		struct stack_symbol* sym = search_cached_stack_symbols(ref);
		if (sym)
		{
			found_sym = true;
			if (same_thread && sym->frame != g_debug_context.frame_level)
				dprintf(" frame %d", sym->frame);
			dprintf(" %s", sym->name);
			// print sub field if any
			print_struct_field(ref, sym->type, (ULONG)(ref->vaddr - sym->offset));
		}
	}
	if (!found_sym)
	{
		if (same_thread && g_debug_context.frame_level != ref->where.stack.frame)
			dprintf(" frame %d", ref->where.stack.frame);
		dprintf(" SP+0x%lx", ref->where.stack.offset);
	}
	if (ref->value)
		dprintf(" @"PRINT_FORMAT_POINTER": "PRINT_FORMAT_POINTER"", ref->vaddr, ref->value);
}

void print_global_ref (const struct object_reference* ref)
{
	resolve_or_print_global_ref (ref, CA_TRUE, NULL, NULL);
}

CA_BOOL known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	return resolve_or_print_global_ref(ref, CA_FALSE, sym_addr, sym_sz);
}

CA_BOOL known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	struct stack_symbol* sym = get_stack_sym(ref);
	if (sym)
	{
		if (sym_addr && sym_sz)
		{
			*sym_addr = sym->offset;
			*sym_sz   = sym->size;
			get_struct_field_type_and_name(sym->type,
									(ULONG)(ref->vaddr - sym->offset),
									sym_addr,
									sym_sz,
									NULL,
									NULL);
		}
		return CA_TRUE;
	}
	else
		return CA_FALSE;
}

/*
 *  search C++ vtables of the type of the input expression
 */
CA_BOOL get_vtable_from_exp(const char*exp, struct CA_LIST*vtables, char* type_name, size_t bufsz, size_t* type_sz)
{
	CA_BOOL rc = CA_FALSE;
	ULONG type_id;
	ULONG64 module;
	if (gDebugSymbols3->GetSymbolTypeId(exp, &type_id, &module) == S_OK
		&& gDebugSymbols3->GetTypeName(module, type_id, type_name, bufsz, NULL) == S_OK
		&& gDebugSymbols3->GetTypeSize(module, type_id, (PULONG)type_sz) == S_OK)
	{
		unsigned int len = strlen(type_name);
		const char* vtbl_postfix = "::`vftable'";
		char* vtbl_name = new char[len + strlen(vtbl_postfix) + 1];
		sprintf(vtbl_name, "%s", type_name);
		// if symbol is of pointer type, we will get type name as "T**", remove the "*"
		while (len >= 1 && (vtbl_name[len-1] == '*' || vtbl_name[len-1] == '&'))
		{
			vtbl_name[len-1] = '\0';
			len--;
		}
		sprintf(&vtbl_name[len], "%s", vtbl_postfix);
		//dprintf("vtable symbol name \"%s\"\n", vtbl_name);

		HRESULT hr;
		ULONG64 vtbl_addr;
		ULONG64 handle;
		hr = gDebugSymbols3->StartSymbolMatch (vtbl_name, &handle);
		if (hr == S_OK)
		{
			while (1)
			{
				char sym_name[NAME_BUF_SZ];
				hr = gDebugSymbols3->GetNextSymbolMatch (handle, sym_name, NAME_BUF_SZ, 0, &vtbl_addr);
				if (hr == S_OK || hr == S_FALSE)
				{
					struct object_range* vtbl = new struct object_range;
					vtbl->low = vtbl_addr;
					vtbl->high = vtbl->low + 1;
					ca_list_push_front(vtables, vtbl);
					//dprintf("vtable address %p\n", vtbl_addr);
					rc = CA_TRUE;
				}
				else
					break;
			}
			hr = gDebugSymbols3->EndSymbolMatch (handle);
			// clean up
			delete[] vtbl_name;
		}
	}

	return rc;
}

/*
 * Prepare pta for user request:
 *  construct process map if it changed since last time
 */
bool update_memory_segments_and_heaps()
{
	bool rc = false;
	HRESULT Hr;
	struct ca_segment* seg;

	/*
	 *  It has been built previously.
	 */
	if (g_segments && g_segment_count)
	{
		// Don't need to update if target is core file, or live process didn't change
		if (g_debug_core || !is_process_segment_changed())
		{
			rc = true;
			goto NormalExit;
		}
		dprintf("Target process has changed. Rebuild heap information\n");
		// release old ca_segments
		release_all_segments();
		// drop cache
		release_cached_stack_symbols();
		release_frame_info_cache();
		g_total_threads = 0;
	}

	dprintf("Query Target Process Information\n");
	//////////////////////////////////////////////////////////
	// Get target type
	//////////////////////////////////////////////////////////
	char namebuf[NAME_BUF_SZ];
	ULONG target_class, target_qualifier;
	if ((Hr = gDebugControl->GetDebuggeeType(&target_class, &target_qualifier) ) == S_OK
			&& target_class == DEBUG_CLASS_USER_WINDOWS )
	{
		if (target_qualifier == DEBUG_USER_WINDOWS_PROCESS)
			dprintf("\tDebuggee is a user-mode process on the same computer\n");
		else if (target_qualifier == DEBUG_USER_WINDOWS_SMALL_DUMP)
		{
			dprintf("\tDebuggee is a user-mode minidump file");
			{
				ULONG namesz, type;
				if ((Hr = gDebugClient4->GetDumpFile(0, namebuf, NAME_BUF_SZ, &namesz, NULL, &type)) == S_OK)
				{
					dprintf(" \"%s\"", namebuf);
					g_debug_core = true;
				}
			}
			dprintf("\n");
		}
		else
			dprintf("\tError: debuggee (%d) is not supported\n", target_qualifier);
	}
	if (gDebugControl->IsPointer64Bit() == S_OK)
	{
		g_ptr_bit = 64;
		g_sp_name = "rsp";
	}
	else
	{
		g_ptr_bit = 32;
		g_sp_name = "esp";
	}
	//////////////////////////////////////////////////////////
	// Get all segments by querying the whole space space
	//////////////////////////////////////////////////////////
	address_t start = 0;
	address_t end   = ~start;
	while (start < end)
	{
		MEMORY_BASIC_INFORMATION64 info;
		if ((Hr = gDebugDataSpaces4->QueryVirtual(start, &info)) == S_OK)
		{
			// Free region is inaccessible virtual address
			// Valid address is either MEM_COMMIT or MEM_RESERVE
			if (!(info.State & MEM_FREE))
			{
				enum storage_type st = ENUM_UNKNOWN;
				int read  = info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE);
				int write = info.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE);
				int exec  = info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
				seg = add_one_segment(info.BaseAddress, info.RegionSize, read!=0, write!=0, exec!=0);
			}
			start = info.BaseAddress + info.RegionSize;
		}
		else
			break;
	}
	dprintf("\tThere are %ld segments\n", g_segment_count);
	if (g_debug_core)
	{
		if (!mmap_core_file(namebuf))
		{
			// Can't map the dump file.
			g_debug_core = false;
		}
	}

	//////////////////////////////////////////////////////////
	// Get module list
	//////////////////////////////////////////////////////////
	ULONG unloaded = 0;
	ULONG num_modules;
    if (gDebugSymbols3->GetNumberModules(&num_modules, &unloaded) != S_OK)
		goto Fail;
	dprintf("\tThere are %ld loaded modules\n", num_modules);
	for (ULONG mi = 0; mi < num_modules; mi++)
	{
		address_t mod_base;
		char module_name_buf[NAME_BUF_SZ];
		DEBUG_MODULE_PARAMETERS module_params;
		if (gDebugSymbols3->GetModuleByIndex((ULONG)mi, (PULONG64) &mod_base) == S_OK
			&& gDebugSymbols3->GetModuleParameters(1, NULL, (ULONG)mi, &module_params) == S_OK
			&& gDebugSymbols3->GetModuleNames((ULONG)mi, 0, module_name_buf, NAME_BUF_SZ, NULL, NULL, 0, NULL, NULL, 0, NULL) == S_OK)
		{
			// PE module's headers is allocated a distinct segment
			seg = get_segment(mod_base, 1);
			if (seg && seg->m_type == ENUM_UNKNOWN)
			{
				seg->m_type = ENUM_MODULE_TEXT;
				seg->m_module_name = _strdup(module_name_buf);
			}
			else
				continue;
			// The module base starts with a DOS header
			IMAGE_DOS_HEADER dos_hdr;
			if (!read_memory_wrapper(seg, mod_base, &dos_hdr, sizeof(dos_hdr)))
				continue;
			// NT header is specified by dos header
			ULONG64 nt_hdr_addr = mod_base + dos_hdr.e_lfanew;
			ULONG num_sections;
			ULONG64 sec_addr;
			if (g_ptr_bit == 64)
			{
				IMAGE_NT_HEADERS nt_hdr;
				if (!read_memory_wrapper(seg, nt_hdr_addr, &nt_hdr, sizeof(nt_hdr)))
					continue;
				num_sections = nt_hdr.FileHeader.NumberOfSections;
				sec_addr = nt_hdr_addr + sizeof(IMAGE_NT_HEADERS);
			}
			else
			{
				IMAGE_NT_HEADERS32 nt_hdr_32;
				if (!read_memory_wrapper(seg, nt_hdr_addr, &nt_hdr_32, sizeof(nt_hdr_32)))
					continue;
				num_sections = nt_hdr_32.FileHeader.NumberOfSections;
				sec_addr = nt_hdr_addr + sizeof(IMAGE_NT_HEADERS32);
			}

			IMAGE_SECTION_HEADER* sec_hdrs = new IMAGE_SECTION_HEADER[num_sections];
			// Now iterate each section and its corresponding segment in memory
			if (read_memory_wrapper(seg, sec_addr, sec_hdrs, sizeof(IMAGE_SECTION_HEADER)*num_sections))
			{
				for (ULONG sec_index=0; sec_index<num_sections; sec_index++)
				{
					ULONG64 sec_addr = mod_base + sec_hdrs[sec_index].VirtualAddress;
					seg = get_segment(sec_addr, sec_hdrs[sec_index].Misc.VirtualSize);
					if (seg && seg->m_type == ENUM_UNKNOWN)
					{
						seg->m_module_name = _strdup(module_name_buf);
						if (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_CODE)
							seg->m_type = ENUM_MODULE_TEXT;
						else if ( (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
								|| (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) )
							seg->m_type = ENUM_MODULE_DATA;
						else if (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_MEM_WRITE)
							seg->m_type = ENUM_MODULE_DATA;
						else
							seg->m_type = ENUM_MODULE_TEXT;
					}
				}
				delete[] sec_hdrs;
			}
		}
		else
			goto Fail;
	}
	//////////////////////////////////////////////////////////
	// Get thread list
	//////////////////////////////////////////////////////////
	// total number of threads
	ULONG num_threads;
	if (gDebugSystemObjects->GetNumberThreads(&num_threads) != S_OK)
		goto Fail;
	g_total_threads = num_threads;
	// Register index of rsp
	ULONG rsp_index = ULONG_MAX;
	if (gDebugRegisters2->GetIndexByName(g_sp_name, &rsp_index) != S_OK)
		goto Fail;

	for (ULONG i = 0; i < num_threads; i++)
	{
		DEBUG_VALUE reg_val;
		ULONG engine_tid;
		// there are pseudo tid, engine tid and system tid
		// Here we get engine tid (not interested in sys tid) by pseudo tid
		if ((Hr = gDebugSystemObjects->GetThreadIdsByIndex(i, 1, &engine_tid, NULL)) != S_OK
			|| (Hr = gDebugSystemObjects->SetCurrentThreadId(engine_tid)) != S_OK)
			goto Fail;
		// get rsp
		if ((Hr = gDebugRegisters2->GetValue(rsp_index, &reg_val)) != S_OK)
			goto Fail;
		//rsp_values[i] = reg_val.I64;
		seg = get_segment(reg_val.I64, 1);
		if (seg && seg->m_type == ENUM_UNKNOWN)
		{
			seg->m_type = ENUM_STACK;
			seg->m_thread.tid = i;
		}
	}
	// thread is restored at top level
	dprintf("\tThere are %ld threads\n", num_threads);

	// dry run to mark heap segments
	if (!init_heap() || !test_segments(CA_TRUE) || !alloc_bit_vec())
		goto Fail;

	//////////////////////////////////////////////////////////
	// Done
	//////////////////////////////////////////////////////////
	dprintf("----Initialization Succeeded----\n", g_segment_count);
	rc = true;
	goto NormalExit;

Fail:
	dprintf("----Initialization Failed----\n", g_segment_count);
NormalExit:
	// clear up old types
	clear_addr_type_map();

	return rc;
}

/*
 * Get the value of the registers of the thread context
 * If buffer is NULL, return number of registers could be returned
 */
int read_registers(const struct ca_segment* segment, struct reg_value* regs, int bufsz)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	ULONG numRegs = 0;
	HRESULT Hr;
	if ((Hr = gDebugRegisters2->GetNumberRegisters(&numRegs)) != S_OK)
		return 0;
	if (regs)
	{
		if ((ULONG)bufsz >= numRegs)
		{
			static DEBUG_VALUE* reg_vaules = NULL;
			if (reg_vaules == NULL)
				reg_vaules = new DEBUG_VALUE[numRegs];

			// switch thread
			ULONG engine_tid;
			if (gDebugSystemObjects->GetThreadIdsByIndex(segment->m_thread.tid, 1, &engine_tid, NULL) != S_OK
				|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
				return 0;

			::memset(reg_vaules, 0, sizeof(DEBUG_VALUE)*numRegs);
			Hr = gDebugRegisters2->GetValues(numRegs, NULL, 0, reg_vaules);
			for (ULONG k=0; k<numRegs; k++)
			{
				regs[k].reg_num = k;
				if (ptr_sz == 8 && reg_vaules[k].Type == DEBUG_VALUE_INT64)
				{
					regs[k].reg_width = 8;
					regs[k].value = (address_t) reg_vaules[k].I64;
				}
				else if (ptr_sz == 4 && reg_vaules[k].Type == DEBUG_VALUE_INT32)
				{
					regs[k].reg_width = 4;
					regs[k].value = (address_t) reg_vaules[k].I32;
				}
				else
					regs[k].reg_width = 0;
			}
			return numRegs;
		}
	}
	else
		return numRegs;
	return 0;
}

address_t get_rsp(const struct ca_segment* segment)
{
	// Register index of rsp
	ULONG rsp_index = ULONG_MAX;
	if (gDebugRegisters2->GetIndexByName(g_sp_name, &rsp_index) != S_OK)
		return 0;

	DEBUG_VALUE reg_val;
	ULONG engine_tid;
	if (gDebugSystemObjects->GetThreadIdsByIndex(segment->m_thread.tid, 1, &engine_tid, NULL) != S_OK
		|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
		return 0;
	// get rsp
	if (gDebugRegisters2->GetValue(rsp_index, &reg_val) != S_OK)
		return 0;
	return reg_val.I64;
}

int get_thread_id (const struct ca_segment* segment)
{
	return segment->m_thread.tid;
}

bool search_registers(const struct ca_segment* segment,
					struct CA_LIST* targets,
					struct CA_LIST* refs)
{
	bool lbFound = false;
	struct reg_value* reg_values = NULL;
	size_t ptr_sz = g_ptr_bit >> 3;

	// Query total number of registers
	int numRegs = read_registers (segment, NULL, 0);
	if (numRegs == 0)
		goto Fail;
	// Allocate buffer for all registers
	reg_values = new reg_value[numRegs];
	if (read_registers (segment, reg_values, numRegs) != numRegs)
		goto Fail;

	// check all registers for a match
	for (int k = 0; k < numRegs; k++)
	{
		if (reg_values[k].reg_width == ptr_sz)
		{
			struct object_range* target;
			ca_list_traverse_start(targets);
			while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
			{
				if (reg_values[k].value >= target->low && reg_values[k].value < target->high)
				{
					// stack unwinding is not working yet,
					// check registers of frame 0 only
					struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
					ref->storage_type  = ENUM_REGISTER;
					ref->where.reg.tid = segment->m_thread.tid;
					ref->where.reg.reg_num = k;
					ref->where.reg.name    = NULL;
					ref->vaddr        = 0;
					ref->value        = reg_values[k].value;
					ca_list_push_back(refs, ref);
					lbFound = true;
					break;
				}
			}
			ca_list_traverse_start(targets);
		}
	}
	// thread is restored at top level

	goto NormalExit;

Fail:
	dprintf("Fatal error in SearchValueInternal\n");
NormalExit:
	// clean up
	delete [] reg_values;

	return lbFound;
}

/*
 * Return the frame number with given address
 */
int get_frame_number(const struct ca_segment* segment, address_t addr, int* offset)
{
	int frame = -1;
	int tid = segment->m_thread.tid;

	// sanity check
	if ((ULONG)tid > g_total_threads - 1)
	{
		CA_PRINT("Internal error: tid=%d is out of range\n", tid);
		return -1;
	}

	// build frame cache if not yet
	if (g_all_stack_frames.empty() || g_all_stack_frames[tid] == NULL)
		build_frame_info_cache(tid);

	// search the cache
	std::vector<struct frame_info>* frame_infos = g_all_stack_frames[tid];
	ULONG total_frames = frame_infos->size();
	if (total_frames > 0 && addr >= frame_infos->at(0).rsp && addr <= frame_infos->at(total_frames-1).rbp)
	{
		for (ULONG i=0; i<total_frames; i++)
		{
			if (addr >= frame_infos->at(i).rsp && addr <= frame_infos->at(i).rbp)
			{
				frame = i;
				*offset = (int) (addr - frame_infos->at(i).rsp);
				break;
			}
		}
	}

	return frame;
}

address_t get_var_addr_by_name(const char* var_name, CA_BOOL ask)
{
	address_t rs = 0;
	DEBUG_VALUE val;
	// get the address
	if (gDebugControl->Evaluate(var_name, DEBUG_VALUE_INT64, &val, NULL) == S_OK)
		rs = val.I64;
	else
	{
		size_t len = strlen(var_name)+3;
		char* namebuf = new char[len];
		snprintf(namebuf, len, "@$%s", var_name);
		if (gDebugControl->Evaluate(namebuf, DEBUG_VALUE_INT64, &val, NULL) == S_OK)
			rs = val.I64;
		// clenaup
		delete[] namebuf;
	}
	return rs;
}

void clear_addr_type_map()
{
	addr_type_map_sz = 0;
}

CA_BOOL user_request_break()
{
	if (CheckControlC() )
		return CA_TRUE;
	return CA_FALSE;
}

/////////////////////////////////////////////////////
// Type helper functions
/////////////////////////////////////////////////////
enum SymTagEnum get_type_code(struct win_type type, ULONG64 addr)
{
	EXT_TYPED_DATA typed_data;
	// Get the type category, pointer/array/function/...
	if (!get_typeinfo(type, addr, typed_data, CA_FALSE))
		return SymTagNull;
	else
		return (enum SymTagEnum) typed_data.OutData.Tag;
}

static bool
get_typeinfo(struct win_type type, ULONG64 addr, EXT_TYPED_DATA& typed_data, bool detail)
{
	ULONG64 mod_base = type.mod_base;
	ULONG type_id    = type.type_id;
	HRESULT hr;
	EXT_TYPED_DATA typed_data_in;
	memset(&typed_data_in, 0, sizeof(EXT_TYPED_DATA));
	memset(&typed_data, 0, sizeof(EXT_TYPED_DATA));
	typed_data_in.Operation = EXT_TDOP_SET_FROM_TYPE_ID_AND_U64;
	typed_data_in.Flags     = 0;
	typed_data_in.InData.ModBase = mod_base;
	typed_data_in.InData.Offset  = addr;
	typed_data_in.InData.TypeId  = type_id;

	hr = gDebugAdvanced2->Request(DEBUG_REQUEST_EXT_TYPED_DATA_ANSI,
								&typed_data_in, sizeof(EXT_TYPED_DATA),
								&typed_data, sizeof(EXT_TYPED_DATA),
								NULL);
	if (FAILED(hr))
		return false;

	enum SymTagEnum tag = (enum SymTagEnum) typed_data.OutData.Tag;
	if (detail && typed_data.OutData.TypeId == typed_data.OutData.BaseTypeId
		&& (tag == SymTagPointerType || tag == SymTagArrayType))
	{
		char type_name[NAME_BUF_SZ];
		ULONG type_name_sz;
		hr = gDebugSymbols3->GetTypeName(mod_base, type_id, type_name, NAME_BUF_SZ, &type_name_sz);
		if (SUCCEEDED(hr) && type_name_sz < NAME_BUF_SZ-1)
		{
			if (tag == SymTagPointerType)
			{
				int cursor = type_name_sz - 1;
				while (cursor >= 0)
				{
					if (type_name[cursor] == '*')
					{
						type_name[cursor] = '\0';
						break;
					}
					cursor--;
				}
			}
			else // SymTagArrayType
			{
				char* pos = strstr(type_name, "[]");
				if (pos)
					*pos = '\0';
			}
			ULONG base_type_id;
			hr = gDebugSymbols3->GetTypeId(mod_base, type_name, &base_type_id);
			if (hr == S_OK)
				typed_data.OutData.BaseTypeId = base_type_id;
		}
	}
	return true;
}

struct win_type
get_struct_field_type_and_name(struct win_type type,
					ULONG displacement,
					address_t* sym_addr,
					size_t*    sym_sz,
					char* namebuf,
					size_t namebuf_sz)
{
	struct win_type field_type = type;
	EXT_TYPED_DATA typed_data;
	// Get the type category, pointer/array/function/...
	if (!get_typeinfo(type, *sym_addr, typed_data, CA_FALSE))
		return type;
	enum SymTagEnum tag = get_type_code(type, *sym_addr);

	if (namebuf && namebuf_sz)
		*namebuf = '\0';

	if (tag == SymTagUDT)
	{
		for (int field_index = 0; ; field_index++)
		{
			HRESULT hr;
			//  Get field name
			char field_name[NAME_BUF_SZ];
			ULONG name_sz;
			hr = gDebugSymbols3->GetFieldName(type.mod_base, type.type_id, field_index, field_name, NAME_BUF_SZ, &name_sz);
			if (FAILED(hr) || name_sz >= NAME_BUF_SZ-1)
				break;
			// Get field type and its offset
			ULONG field_type_id;
			ULONG field_offset;
			if (gDebugSymbols3->GetFieldTypeAndOffset(type.mod_base, type.type_id, field_name, &field_type_id, &field_offset) != S_OK)
				break;
			// Get field size
			ULONG field_sz;
			if (gDebugSymbols3->GetTypeSize(type.mod_base, field_type_id, &field_sz) != S_OK)
				break;
			// Now we may check if ref to this field
			if (displacement >= field_offset && displacement < field_offset + field_sz)
			{
				ULONG base_type_sz;
				// update symbol address/size to the field member
				*sym_addr += field_offset;
				*sym_sz = field_sz;
				if (namebuf && namebuf_sz > name_sz)
				{
					strcpy(namebuf, field_name);
					namebuf += name_sz;
					*namebuf = '\0';
					namebuf_sz -= name_sz;
				}
				field_type.type_id = field_type_id;
				if (get_typeinfo(field_type, *sym_addr - field_offset, typed_data, CA_FALSE)
					&& (enum SymTagEnum) typed_data.OutData.Tag == SymTagArrayType
					&& gDebugSymbols3->GetTypeSize(type.mod_base, typed_data.OutData.BaseTypeId, &base_type_sz) == S_OK)
				{
					ULONG array_index = (displacement - field_offset)/base_type_sz;
					*sym_addr += array_index * base_type_sz;
					field_type.type_id = typed_data.OutData.BaseTypeId;
					return get_struct_field_type_and_name(field_type,
										displacement - field_offset - array_index * base_type_sz,
										sym_addr,
										sym_sz,
										namebuf,
										namebuf_sz);
				}
				else
					return get_struct_field_type_and_name(field_type,
										displacement - field_offset,
										sym_addr,
										sym_sz,
										namebuf,
										namebuf_sz);
			}
		}
	}

	return field_type;
}

void get_stack_sym_and_type(address_t addr, const char** symname, struct win_type* ptype)
{
	struct object_reference aref;

	*symname = 0;
	ptype->mod_base = 0;
	ptype->type_id  = 0;

	memset(&aref, 0, sizeof(aref));
	aref.vaddr = addr;
	aref.value = 0;
	aref.target_index = -1;
	fill_ref_location(&aref);
	if (aref.storage_type == ENUM_STACK)
	{
		struct stack_symbol* sym = search_cached_stack_symbols(&aref);
		if (sym)
		{
			address_t sym_addr = addr;
			size_t    sym_size = sym->size;
			// symbol name
			*symname = sym->name;
			// symbol type
			*ptype = get_struct_field_type_and_name(sym->type,
									(ULONG)(aref.vaddr - sym->offset),
									&sym_addr,
									&sym_size,
									NULL,
									NULL);
		}
	}
}

static struct stack_symbol*
get_stack_sym(const struct object_reference* ref)
{
	if (ref->storage_type == ENUM_STACK && ref->where.stack.frame >= 0)
		return search_cached_stack_symbols(ref);
	else
		return NULL;
}

static CA_BOOL resolve_or_print_global_ref(const struct object_reference* ref, CA_BOOL printit, address_t* sym_addr, size_t* sym_sz)
{
	CA_BOOL rc = CA_FALSE;
	HRESULT hr;
	// Get symbol at the address
	char sym_name[NAME_BUF_SZ];
	ULONG name_sz;
	ULONG64 displacement = 0;
	hr = gDebugSymbols3->GetNameByOffset(ref->vaddr, sym_name, NAME_BUF_SZ, &name_sz, &displacement);
	if (FAILED(hr))
	{
		if (printit)
			dprintf(" unknown");
		goto NormalExit;
	}

	if (printit)
		dprintf(" %s", sym_name);

	// Get the type at the address
	ULONG type_id, type_sz;
	ULONG64 mod_base;
	if (gDebugSymbols3->GetOffsetTypeId(ref->vaddr - displacement, &type_id, &mod_base) == S_OK
		&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK)
	{
		if (displacement < type_sz)
		{
			rc = CA_TRUE;
			if (sym_addr && sym_sz)
			{
				*sym_addr = ref->vaddr - displacement;
				*sym_sz   = type_sz;
			}
			if (printit)
			{
				struct win_type type = {mod_base, type_id};
				print_struct_field(ref, type, (ULONG)displacement);
			}
		}
		else if (ref->storage_type == ENUM_MODULE_TEXT)
		{
			// function's size need be dealt with differently
			DEBUG_MODULE_AND_ID id;
			ULONG64 displacement2;
			ULONG num_entry;
			DEBUG_SYMBOL_ENTRY sym_entry;
			if (gDebugSymbols3->GetSymbolEntriesByOffset(ref->vaddr - displacement, 0, &id, &displacement2, 1, &num_entry) == S_OK
				&& gDebugSymbols3->GetSymbolEntryInformation(&id, &sym_entry) == S_OK)
			{
				rc = CA_TRUE;
				if (sym_addr && sym_sz)
				{
					*sym_addr = ref->vaddr - displacement;
					*sym_sz   = sym_entry.Size;
				}
				if (printit)
					dprintf("+0x%I64x", displacement);
			}
		}
	}

NormalExit:
	if (printit)
	{
		if (!rc || ref->value)
			dprintf(" @"PRINT_FORMAT_POINTER, ref->vaddr);
		if (ref->value)
			dprintf(": "PRINT_FORMAT_POINTER, ref->value);
	}

	return rc;
}

static void
print_struct_field(const struct object_reference* ref,
					struct win_type type,
					ULONG displacement)
{
	HRESULT hr;
	EXT_TYPED_DATA typed_data;
	// Get the type category, pointer/array/function/...
	if (!get_typeinfo(type, ref->vaddr - displacement, typed_data, ref->value > 0))
		return;
	enum SymTagEnum tag = (enum SymTagEnum) typed_data.OutData.Tag;
	if (tag == SymTagUDT)
	{
		for (int field_index = 0; ; field_index++)
		{
			//  Get field name
			char field_name[NAME_BUF_SZ];
			ULONG name_sz;
			hr = gDebugSymbols3->GetFieldName(type.mod_base, type.type_id, field_index, field_name, NAME_BUF_SZ, &name_sz);
			if (FAILED(hr) || name_sz >= NAME_BUF_SZ-1)
				break;
			// Get field type and its offset
			ULONG field_type_id;
			ULONG field_offset;
			if (gDebugSymbols3->GetFieldTypeAndOffset(type.mod_base, type.type_id, field_name, &field_type_id, &field_offset) != S_OK)
				break;
			// Get field size
			ULONG field_sz;
			if (gDebugSymbols3->GetTypeSize(type.mod_base, field_type_id, &field_sz) != S_OK)
				break;
			// Now we may check if ref to this field
			if (displacement >= field_offset && displacement < field_offset + field_sz)
			{
				struct win_type field_type = type;
				field_type.type_id = field_type_id;
				ULONG base_type_sz;
				dprintf(".%s", field_name);
				if (get_typeinfo(field_type, ref->vaddr - field_offset, typed_data, ref->value > 0)
					&& (enum SymTagEnum) typed_data.OutData.Tag == SymTagArrayType
					&& gDebugSymbols3->GetTypeSize(type.mod_base, typed_data.OutData.BaseTypeId, &base_type_sz) == S_OK)
				{
					ULONG array_index = (displacement - field_offset)/base_type_sz;
					dprintf("[%d]", array_index);
					field_type.type_id = typed_data.OutData.BaseTypeId;
					print_struct_field(ref, field_type, displacement - field_offset - array_index * base_type_sz);
				}
				else
					print_struct_field(ref, field_type, displacement - field_offset);
				break;
			}
		}
	}
	else
	{
		char type_name[NAME_BUF_SZ];
		ULONG type_name_sz;
		hr = gDebugSymbols3->GetTypeName(type.mod_base, type.type_id, type_name, NAME_BUF_SZ, &type_name_sz);
		if (SUCCEEDED(hr) && type_name_sz < NAME_BUF_SZ-1 && strcmp(type_name, "<function>")!=0)
			dprintf("(type=\"%s\")", type_name);
		if ( (tag == SymTagPointerType || tag == SymTagArrayType) && ref->value)
		{
			struct win_type array_base_type;
			array_base_type.mod_base = type.mod_base;
			array_base_type.type_id  = typed_data.OutData.BaseTypeId;
			add_addr_type(ref->value, array_base_type);
		}
	}
}

/////////////////////////////////////////////////////
// Cached stack symbol helper functions
/////////////////////////////////////////////////////
static void release_cached_stack_symbols()
{
	for (int tid=0; tid<g_all_stack_symbols.size(); tid++)
	{
		stack_symbols* syms = g_all_stack_symbols[tid];
		if (syms)
		{
			for (int i=0; i<syms->size(); i++)
			{
				struct stack_symbol* sym = syms->at(i);
				if (sym->name)
					free(sym->name);
				delete sym;
			}
			syms->clear();
		}
		delete syms;
	}
	g_all_stack_symbols.clear();
}

/*
 * Collect all symbols(local variables) on this thread's stack
 */
static CA_BOOL build_stack_sym_cache( int tid)
{
	// Cache symbols only once
	if (g_all_stack_symbols.empty())
		g_all_stack_symbols.resize(g_total_threads);

	if (g_all_stack_symbols[tid] == NULL)
		g_all_stack_symbols[tid] = new stack_symbols;
	else
		return true;

	// switch thread
	// convert pseudo tid to engine tid and change scope to that thread
	ULONG engine_tid;
	if (gDebugSystemObjects->GetThreadIdsByIndex(tid, 1, &engine_tid, NULL) != S_OK
		|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
		return false;

	// Get the total number of frames
	DEBUG_STACK_FRAME frames[MAX_FRAMES];
	ULONG frameFilled = 0;
	if (gDebugControl->GetStackTrace(0,		// frame offset
									0,		// stack offset
									0,		// instruction offset
									frames,
									MAX_FRAMES,
									&frameFilled) != S_OK )
		return false;

	bool rc = false;
	PDEBUG_SYMBOL_GROUP2 symbolGroup2 = NULL;
	HRESULT hr;
	// Local variables don't seem to be bounded between sp and fp, check all frames
	for (ULONG frame_num = 0; frame_num < frameFilled; frame_num++)
	{
		// Set scope to frame_num
		// Beware, this method returns S_FALSE
		hr = gDebugSymbols3->SetScopeFrameByIndex(frame_num);
		if (FAILED(hr))
			break;
		// Retrieve COM interface to symbols of this scope (frame)
		if (gDebugSymbols3->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ALL, symbolGroup2, &symbolGroup2) != S_OK)
			goto NormalExit;
		// Get number of symbols
		ULONG total_syms;
		if (symbolGroup2->GetNumberSymbols(&total_syms) != S_OK)
			goto NormalExit;
		for (ULONG sym_index=0; sym_index<total_syms; sym_index++)
		{
			// symbol entry includes location/size/type_id, etc.
			DEBUG_SYMBOL_ENTRY entry;
			if (symbolGroup2->GetSymbolEntryInformation(sym_index, &entry) == S_OK)
			{
				// symbol name
				char name_buf[NAME_BUF_SZ];
				hr = symbolGroup2->GetSymbolName(sym_index, name_buf, NAME_BUF_SZ, NULL);
				if (FAILED(hr))
					break;
				struct stack_symbol* sym = new struct stack_symbol;
				sym->frame = frame_num;
				sym->size  = entry.Size;
				sym->offset = entry.Offset;
				sym->name = new char[strlen(name_buf)+1];
				strcpy(sym->name, name_buf);
				sym->type.mod_base = entry.ModuleBase;
				sym->type.type_id = entry.TypeId;
				g_all_stack_symbols[tid]->push_back(sym);
			}
		}
	}
	rc = true;

NormalExit:
	if (symbolGroup2)
		symbolGroup2->Release();

	return rc;
}

static struct stack_symbol* search_cached_stack_symbols(const struct object_reference* ref)
{
	// sanity check
	if ((ULONG)ref->where.stack.tid > g_total_threads - 1)
	{
		CA_PRINT("Internal error: tid=%d is out of range\n", ref->where.stack.tid);
		return NULL;
	}

	// build cache if not yet
	if (g_all_stack_symbols.empty() || g_all_stack_symbols[ref->where.stack.tid]==NULL)
		build_stack_sym_cache(ref->where.stack.tid);

	// search the cache
	stack_symbols* syms = g_all_stack_symbols[ref->where.stack.tid];
	for (int i=0; i<syms->size(); i++)
	{
		struct stack_symbol* sym = syms->at(i);
		if (ref->vaddr >= sym->offset && ref->vaddr < sym->offset + sym->size)
			return sym;
	}
	return NULL;
}

static void release_frame_info_cache()
{
	for (int i=0; i<g_all_stack_frames.size(); i++)
	{
		std::vector<struct frame_info>* frame_infos = g_all_stack_frames[i];
		if (frame_infos)
			delete frame_infos;
	}
	g_all_stack_frames.clear();
}

static bool build_frame_info_cache(int tid)
{
	if (g_all_stack_frames.empty())
		g_all_stack_frames.resize(g_total_threads);

	if (g_all_stack_frames[tid] == NULL)
	{
		g_all_stack_frames[tid] = new std::vector<struct frame_info>;

		std::vector<struct frame_info>* frame_infos = g_all_stack_frames[tid];
		DEBUG_STACK_FRAME frames[MAX_FRAMES];
		ULONG frameFilled = 0;
		// switch thread (remember to convert pseudo tid to engine tid)
		// then retrieve stack trace
		ULONG engine_tid;
		if (gDebugSystemObjects->GetThreadIdsByIndex(tid, 1, &engine_tid, NULL) == S_OK
			&& gDebugSystemObjects->SetCurrentThreadId(engine_tid) == S_OK
			&& gDebugControl->GetStackTrace(0,		// frame offset
											0,		// stack offset
											0,		// instruction offset
											frames,
											MAX_FRAMES,
											&frameFilled) == S_OK )
		{
			if (frameFilled > 0)
			{
				frame_infos->resize(frameFilled);
				for (ULONG fi = 0; fi < frameFilled; fi++)
				{
					struct frame_info* f_info = &frame_infos->at(fi);
					f_info->frame_no = fi;
					f_info->rbp = frames[fi].FrameOffset;
					f_info->rsp = frames[fi].StackOffset;
				}
			}
		}
	}
	return true;
}

/////////////////////////////////////////////////////
// Process segment helper functions
/////////////////////////////////////////////////////
static bool is_process_segment_changed()
{
	address_t start = 0;
	address_t end   = ~start;
	unsigned int seg_index = 0;
	while (start < end)
	{
		MEMORY_BASIC_INFORMATION64 info;
		if (gDebugDataSpaces4->QueryVirtual(start, &info) == S_OK)
		{
			// Free region is inaccessible virtual address
			// Valid address is either MEM_COMMIT or MEM_RESERVE
			if (!(info.State & MEM_FREE))
			{
				if (seg_index >= g_segment_count
					|| g_segments[seg_index].m_vaddr != info.BaseAddress
					|| g_segments[seg_index].m_vsize != info.RegionSize)
					return true;
				seg_index++;
			}
			start = info.BaseAddress + info.RegionSize;
		}
		else
			break;
	}
	if (seg_index != g_segment_count)
		return true;
	return false;
}

static bool fix_segments_with_mapped_file(char* start)
{
	MINIDUMP_HEADER* pdump = (MINIDUMP_HEADER*) start;
	if (MINIDUMP_SIGNATURE != pdump->Signature
		&& MINIDUMP_VERSION != (pdump->Version & 0xffff))
	{
		dprintf("Unrecognizable minidump file format\n");
		return false;
	}
	MINIDUMP_DIRECTORY* pMiniDumpDir = (MINIDUMP_DIRECTORY*) (start + pdump->StreamDirectoryRva);
	for (unsigned int k = 0; k < pdump->NumberOfStreams; k++, pMiniDumpDir++)
	{
		struct ca_segment* seg;
		MINIDUMP_LOCATION_DESCRIPTOR location = pMiniDumpDir->Location;
		// memory regions
		if (pMiniDumpDir->StreamType == Memory64ListStream)
		{
			MINIDUMP_MEMORY64_LIST* mem64_list = (MINIDUMP_MEMORY64_LIST*)(start + location.Rva);
			MINIDUMP_MEMORY_DESCRIPTOR64* region = &mem64_list->MemoryRanges[0];
			char* base = start + mem64_list->BaseRva;
			for (unsigned int i=0; i<mem64_list->NumberOfMemoryRanges; i++, region++)
			{
				seg = get_segment(region->StartOfMemoryRange, 1);
				if (seg && seg->m_vaddr == region->StartOfMemoryRange)
				{
					seg->m_faddr = base;
					if (region->DataSize >= seg->m_vsize)
						seg->m_fsize = seg->m_vsize;
					else
						seg->m_fsize = region->DataSize;
				}
				base += region->DataSize;
			}
		}
	}
	return true;
}

static bool mmap_core_file(const char* fname)
{
	DWORD rc;
	// silently ignores NULL file
	if (!fname)
		return false;

	// file stat
	struct __stat64 lStatBuf;
	if(_stat64(fname, &lStatBuf))
	{
		rc = ::GetLastError();
		dprintf("Failed to stat file %s, errno=%d\n", fname, rc);
		return false;
	}

	if(lStatBuf.st_size == 0)
	{
		dprintf("File %s is empty, ignored\n", fname);
		return false;
	}
	size_t mFileSize = lStatBuf.st_size;

	// Open file for mapping
	HANDLE lFileHandle = ::CreateFile(fname,
									GENERIC_READ,
									FILE_SHARE_READ,
									NULL,
									OPEN_EXISTING,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
	if(INVALID_HANDLE_VALUE == lFileHandle)
	{
		rc = ::GetLastError();
		dprintf("Function CreateFile() Failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Create mapping
	HANDLE mhFile = ::CreateFileMapping(lFileHandle,
										NULL,
										PAGE_READONLY,
										0,
										0,
										NULL);
	if(mhFile == NULL)
	{
		rc = ::GetLastError();
		dprintf("Function CreateFileMapping() failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Get the memory address of mapping
	char* mpStartAddr = (char*) ::MapViewOfFile(mhFile,
												FILE_MAP_READ,
												0,
												0,
												0);
	if(mpStartAddr == NULL)
	{
		rc = ::GetLastError();
		dprintf("Function MapViewOfFile() failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Now that we have mapped the dump file, fix all segments' m_faddr pointers
	if (!fix_segments_with_mapped_file(mpStartAddr))
		return false;

	return true;
}

/////////////////////////////////////////////////////
// Type map helper functions
/////////////////////////////////////////////////////
static void
add_addr_type(ULONG64 addr, struct win_type type)
{
	if (addr_type_map_sz >= addr_type_map_buf_sz)
	{
		if (addr_type_map_buf_sz == 0)
			addr_type_map_buf_sz = 64;
		else
			addr_type_map_buf_sz = addr_type_map_buf_sz * 2;
		addr_type_map = (struct addr_type_pair *) realloc(addr_type_map, addr_type_map_buf_sz * sizeof(struct addr_type_pair));
	}
	addr_type_map[addr_type_map_sz].addr = addr;
	addr_type_map[addr_type_map_sz].type = type;
	addr_type_map_sz++;
}

// The input ref is assumed to be a heap block
static struct addr_type_pair*
lookup_type_by_addr(const struct object_reference* ref)
{
	// pick up the latest first
	for (int i = addr_type_map_sz - 1; i >=0 ; i--)
	{
		if (addr_type_map[i].addr == ref->vaddr
			|| addr_type_map[i].addr == ref->where.heap.addr)
			return &addr_type_map[i];
	}
	return NULL;
}

/*********************************************************************
 * Annotated disassembly instructions
 ********************************************************************/
struct ca_x86_register
{
	const char*  name;			// intel syntax
	unsigned int index:6;		// internal index (see x_type.h)
	unsigned int size:5;		// 1/2/4/8/16 bytes
	unsigned int x64_only:1;	// set if only used by 64bit
	unsigned int param_x64:4;	// nth (1..6) parameter, 0 means not a param reg
	unsigned int preserved_x64:1;	// 64bit - preserved across function call
	unsigned int preserved_x32:1;	// 32bit - preserved across function call
	unsigned int float_reg:1;	// 1=float 0=integer
	int gdb_regnum;				// regnum known to gdb
};

// this name list corresponds to the register index defined in x_type.h
static struct ca_x86_register g_reg_infos[] = {
	//name  index  size x64 par64 prsv64 prev32 float regnum
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
	//name  index  size x64 par64 prsv64 prev32 float regnum
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
	//name  index  size x64 par64 prsv64 prev32 float regnum
	{"di",    RDI,    2,  0,    1,     0,     0,    0,    -1},
	{"si",    RSI,    2,  0,    2,     0,     0,    0,    -1},
	{"dx",    RDX,    2,  0,    3,     0,     0,    0,    -1},
	{"cx",    RCX,    2,  0,    4,     0,     0,    0,    -1},
	{"r8w",   R8,     2,  0,    5,     0,     0,    0,    -1},
	{"r9w",   R9,     2,  0,    6,     0,     0,    0,    -1},
	//  "%r10w", "%r11w", "%r12w", "%r13w", "%r14w", "%r15w",
	//name  index  size x64 par64 prsv64 prev32 float regnum
	{"dil",  RDI,    1,  0,    1,     0,     0,    0,    -1},
	{"sil",  RSI,    1,  0,    2,     0,     0,    0,    -1},
	{"dl",   RDX,    1,  0,    3,     0,     0,    0,    -1},
	{"cl",   RCX,    1,  0,    4,     0,     0,    0,    -1},
	{"r8b",  R8,     1,  0,    5,     0,     0,    0,    -1},
	{"r9b",  R9,     1,  0,    6,     0,     0,    0,    -1},
	// "%r10b", "%r11b", "%r12b", "%r13b", "%r14b", "%r15b" };
	//name    index size x64 par64 prsv64 prev32 float regnum
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
	//name      index size x64 par64 prsv64 prev32 float regnum
	//{"st(0)", RXMM0,   8,  0,    0,     0,     0,    1,    -1}
	//"st(1-7)"
};
#define NUM_KNOWN_REGS (sizeof(g_reg_infos)/sizeof(g_reg_infos[0]))

// return my internal index (g_reg_infos[]::index) by name
// -1 when not found
static int reg_name_to_index(const char* regname)
{
	int i;
	for (i = 0; i < NUM_KNOWN_REGS; i++)
	{
		if (strcmp(regname, g_reg_infos[i].name) == 0)
			return g_reg_infos[i].index;
	}
	return -1;
}

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
				param_regs[index].value = GetExpression ((char*)(cursor + len + 1));
				return true;
			}
		}
	}
	return false;
}

/*
 * A parameter passed thourgh register but has a stack replica
 */
static void
set_parameter_reg(ULONG64 addr, ULONG sz, int reg_index, struct ca_reg_value* param_regs)
{
	size_t val = 0;
	ULONG cb;
	if (!param_regs[reg_index].has_value && ReadMemory(addr, &val, sz, &cb) && cb == sz)
	{
		param_regs[reg_index].has_value = 1;
		param_regs[reg_index].value = val;
	}
}

/*
 * Retrun true if the type name sounds like an integer class
 */
static bool is_integer_class(const char* type_name)
{
	if (strstr(type_name, "bool")
		|| strstr(type_name, "char")
		|| strstr(type_name, "short")
		|| strstr(type_name, "int")
		|| strstr(type_name, "long") )
		return true;
	else
		return false;
}

/*
 * By VS2005's convention of parameter passing of x86_64 architecture,
 *  the first four integer parameters are passed through registers (rcx, rdx, r8, r9)
 *  the first four float parameters are passed through registers (xmm0-3)
 */
static void get_function_parameters(DEBUG_STACK_FRAME* framep, struct ca_reg_value* param_regs)
{
	char name_buf[NAME_BUF_SZ];
	// Set scope to selected frame
	HRESULT hr = gDebugSymbols3->SetScopeFrameByIndex(framep->FrameNumber);
	if (FAILED(hr))
		return;
	// Retrieve COM interface to parameter symbols of this frame/function's scope
	PDEBUG_SYMBOL_GROUP2 symbolGroup2 = NULL;
	if (gDebugSymbols3->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ARGUMENTS, NULL, &symbolGroup2) != S_OK)
		return;
	// Iterate all parameters
	// Since symbols in the group are not always follow the order of parameters, we have to sort it.
	ULONG num_sym;
	if (symbolGroup2->GetNumberSymbols(&num_sym) != S_OK)
		return;
	std::map<ULONG64,ULONG> integer_params_by_addr;
	ULONG i;
	for (i = 0; i < num_sym; i++)
	{
		DEBUG_SYMBOL_ENTRY entry;
		hr = symbolGroup2->GetSymbolEntryInformation(i, &entry);
		if (hr != S_OK)
			break;
		// only integer parameter is considered
		if (entry.Size <= sizeof(size_t))
		{
			bool integer_class = false;
			if (entry.Tag == SymTagPointerType || entry.Tag == SymTagArrayType || entry.Tag == SymTagEnum)
				integer_class = true;
			else
			{
				hr = symbolGroup2->GetSymbolTypeName(i, name_buf, NAME_BUF_SZ, NULL);
				if (SUCCEEDED(hr) && is_integer_class(name_buf))
					integer_class = true;
			}
			if (integer_class)
			{
				// symbol location
				ULONG64 location;
				hr = symbolGroup2->GetSymbolOffset(i, &location);
				if (FAILED(hr))
					break;
				integer_params_by_addr.insert(std::pair<ULONG64,ULONG>(location, entry.Size));
			}
		}
	}
	// Setup registers used for parameter passing
	std::map<ULONG64,ULONG>::iterator itr;
	int param_reg_index[4] = {RCX, RDX, R8, R9};
	for (itr = integer_params_by_addr.begin(), i = 0;
			itr != integer_params_by_addr.end() && i < 4;
			itr++, i++)
	{
		set_parameter_reg((*itr).first, (*itr).second, param_reg_index[i], param_regs);
	}
	// Print out parameters
	dprintf("\nParameters:\n");
	for (i = 0; i < num_sym; i++)
	{
		// type name is included in the vale text (sometimes ??)
		hr = symbolGroup2->GetSymbolTypeName(i, name_buf, NAME_BUF_SZ, NULL);
		if (SUCCEEDED(hr))
			dprintf("\t%s", name_buf);
		// symbol name
		hr = symbolGroup2->GetSymbolName(i, name_buf, NAME_BUF_SZ, NULL);
		if (FAILED(hr))
			break;
		dprintf(" %s", name_buf);
		hr = symbolGroup2->GetSymbolValueText(i, name_buf, NAME_BUF_SZ, NULL);
		if (SUCCEEDED(hr))
			dprintf(" = %s\n", name_buf);
	}
	if (i == 0)
		dprintf(" None");
	dprintf("\n");
}


/*
 * Parse user options and prepare execution context at function entry,
 * then call disassemble function
 * 	Limitation: false report is possible, especially when loop and jump instructions are involved.
 */
void decode_func(char* args)
{
	HRESULT hr;
	unsigned int i;
	ULONG64 intr;
	DEBUG_STACK_FRAME  current_frame;
	DEBUG_STACK_FRAME* framep;
	DEBUG_STACK_FRAME frames[MAX_FRAMES];
	ULONG total_frames = 0;
	ULONG frame_lo, frame_hi;
	bool multi_frame = false;
	bool verbose = false;
	bool user_regs = false;
	CONTEXT context;
	struct ca_reg_value user_input_regs[TOTAL_REGS];
	struct ca_reg_value param_regs[TOTAL_REGS];
	int ptr_bit = g_ptr_bit;
	int ptr_sz  = ptr_bit == 64 ? 8:4;

	// Get selected frame
	if (gDebugSymbols3->GetScope(&intr, &current_frame, &context, sizeof(context)) != S_OK)
	{
		dprintf("Failed to get current debug scope\n");
		return;
	}
	framep = &current_frame;

	// Init registers' state
	memset(param_regs, 0, REG_SET_SZ);
	memset(user_input_regs, 0, REG_SET_SZ);

	ULONG64 dis_start = 0;
	ULONG64 dis_end   = 0;
	// Parse user input options
	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		unsigned int num_options = ca_parse_options(args, options);
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];

			if (strcmp(option, "/v") == 0)
				verbose = true;
			else if (strncmp(option, "from=", 5) == 0)
			{
				// disassemble from this address instead of function start
				dis_start = GetExpression(option+5);
			}
			else if (strncmp(option, "to=", 3) == 0)
			{
				dis_end = GetExpression(option+3);
			}
			else if (strncmp(option, "frame=", 6) == 0)
			{
				// frame=n or frame=n-m
				const char* subexp = option+6;
				const char* hyphen = strchr(subexp, '-');
				if (gDebugControl->GetStackTrace(0,	0, 0, frames, MAX_FRAMES, &total_frames) != S_OK )
					return;
				// retrieve frame number
				if (hyphen && hyphen > subexp)
				{
					const char* cursor = subexp;
#define NUM_BUF_SZ 32
					char numbuf[NUM_BUF_SZ];
					int k;
					for (k = 0; k < NUM_BUF_SZ - 1 && *cursor != '-'; k++)
						numbuf[k] = *cursor++;
					numbuf[k] = '\0';
					frame_lo = atoi(numbuf);
					frame_hi = atoi(hyphen + 1);
					// check the frame number
					if (frame_lo >= total_frames || frame_hi >= total_frames)
					{
						dprintf("Valid frame # for current thread is [0 - %d]\n", total_frames - 1);
						return;
					}
					else if (frame_lo > frame_hi)
					{
						dprintf("Invalid option %s (frame number %d is bigger than %d)\n",
								option, frame_lo, frame_hi);
						return;
					}
				}
				else
				{
					frame_lo = frame_hi = atoi(option+6);
					if (frame_lo >= total_frames)
					{
						dprintf("Valid frame # for current thread is [0 - %d]\n", total_frames - 1);
						return;
					}
				}
				framep = &frames[frame_hi];
				multi_frame = true;
			}
			else if (strchr(option, '='))
			{
				// Take register entry value, such as rdi=0x12345678
				if (!validate_and_set_reg_param(option, user_input_regs))
				{
					dprintf ("Error: unsupported register: %s\n", option);
					return;
				}
				user_regs = true;
			}
			else
				dprintf ("Unknown command argument: %s\n", option);
		}
	}

	// disassemble one frame or multiple frames
	do
	{
		intr = framep->InstructionOffset;
		// Get function name
		char funcname[NAME_BUF_SZ];
		ULONG name_sz;
		ULONG64 displacement = 0;
		hr = gDebugSymbols3->GetNameByOffset(intr, funcname, NAME_BUF_SZ, &name_sz, &displacement);
		if (FAILED(hr))
		{
			dprintf("Failed to get current function name\n");
			return;
		}

		// Get function's symbol entry
		DEBUG_MODULE_AND_ID id;
		ULONG64 displacement2;
		ULONG num_entry;
		DEBUG_SYMBOL_ENTRY sym_entry;
		if (gDebugSymbols3->GetSymbolEntriesByOffset(intr - displacement, 0, &id, &displacement2, 1, &num_entry) != S_OK
				|| gDebugSymbols3->GetSymbolEntryInformation(&id, &sym_entry) != S_OK)
		{
			dprintf("Failed to get the symbol entry of the current function\n");
			return;
		}
		ULONG64 func_start = sym_entry.Offset;
		ULONG64 func_end   = func_start + sym_entry.Size;

		// For single frame, or the 1st frame of multi-frame disassembling
		// validate user-input start/end instruction addresses
		if (!multi_frame || framep->FrameNumber == frame_hi)
		{
			if (dis_start && dis_end && dis_start > dis_end)
			{
				dprintf ("Error: input start address 0x%lx is larger than end address 0x%lx\n", dis_start, dis_end);
				return;
			}
			if (dis_start)
			{
				if (dis_start < func_start || dis_start > func_end)
				{
					dprintf ("Error: input start address 0x%lx is out of the function range\n", dis_start);
					return;
				}
				else if (dis_start == func_start)
					dis_start = 0;
			}
			if (dis_end)
			{
				if (dis_end < func_start || dis_end > func_end)
				{
					dprintf ("Error: input end address 0x%lx is out of the function range\n", dis_end);
					return;
				}
			}
			else
				dis_end = intr;
		}
		else
			dis_end = intr;

		// rsp & rip
		param_regs[RSP].value = framep->FrameOffset + ptr_sz;
		param_regs[RSP].has_value = 1;
		// update context
		g_debug_context.frame_level = framep->FrameNumber;
		g_debug_context.sp = framep->StackOffset;
		g_debug_context.segment = get_segment(g_debug_context.sp, 1);

		if (multi_frame)
			dprintf("\n------------------------------ Frame %d ------------------------------\n", framep->FrameNumber);

		// parameters at function entry
		get_function_parameters(framep, param_regs);

		// display the registers at function entry
		unsigned int count;
		if (verbose)
		{
			dprintf("The following registers are assumed at the beginning: ");
			count = 0;
			for (i=0; i<TOTAL_REGS; i++)
			{
				// saved RIP is the next instruction address when current function returns
				if (param_regs[i].has_value && i != RIP)
				{
					if (count > 0)
						dprintf(", ");
					dprintf("%s=0x%I64x", g_reg_infos[i].name, param_regs[i].value);
					if (param_regs[i].sym_name)
						dprintf("(%s)", param_regs[i].sym_name);
					count++;
				}
			}
			if (count == 0)
				dprintf("none");
			dprintf("\n");
		}

		//dprintf("ip=%p fp=%p sp=%p return_ip=%p\n", intr, frame.FrameOffset, frame.StackOffset, frame.ReturnOffset);
		//dprintf("params[4]={%p %p %p %p}\n", frame.Params[0], frame.Params[1], frame.Params[2], frame.Params[3]);
		dprintf("Dump of assembler code for function %s:\n", funcname);
		{
			int num_displayed = 0;
			struct cleanup *ui_out_chain;
			struct decode_control_block decode_cb;

			decode_cb.gdbarch = NULL;
			decode_cb.uiout   = NULL;
			decode_cb.low     = dis_start;
			decode_cb.high    = dis_end;
			decode_cb.current = intr;
			decode_cb.func_start = func_start;
			decode_cb.func_end   = func_end;
			decode_cb.param_regs = param_regs;
			if (user_regs)
				decode_cb.user_regs = user_input_regs;
			else
				decode_cb.user_regs = NULL;
			decode_cb.verbose    = verbose ? 1:0;
			decode_cb.innermost_frame = framep->FrameNumber == 0 ? 1:0;

			num_displayed = decode_insns(&decode_cb);
		}
		dprintf("End of assembler dump.\n");
		// display registers at the call site if this is not the innermost function
		if (framep->FrameNumber > 0 && dis_end == intr)
		{
			dprintf("\nThe following registers are known at the call: ");
			count = 0;
			for (i=0; i<TOTAL_REGS; i++)
			{
				if (param_regs[i].has_value)
				{
					if (count > 0)
						dprintf(", ");
					dprintf("%s=0x%I64x", g_reg_infos[i].name, param_regs[i].value);
					count++;
				}
			}
			if (count == 0)
				dprintf("none");
			dprintf("\n");
		}

		// next frame
		if (multi_frame && framep->FrameNumber > frame_lo)
			framep--;
		else
			break;
	} while (1);

	return;
}

// Print function address in the form "func+offset"
void print_func_address(address_t addr, char* buf, int buf_sz)
{
	HRESULT hr;
	// Get symbol at the address
	ULONG name_sz = 0;
	ULONG64 displacement = 0;
	hr = gDebugSymbols3->GetNameByOffset(addr, buf, buf_sz, &name_sz, &displacement);
	if (hr == S_OK && displacement)
	{
		sprintf(buf + name_sz - 1, "+"PRINT_FORMAT_SIZE, displacement);
	}
}

/*
 * Display known symbol/type of an instruction's operand value
 */
void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct type* type = NULL;
	struct addr_type_pair* addr_type;
	struct object_reference aref;

	// if op_value is known stack or global symbol
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
			// global symbol
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (aref.storage_type == ENUM_STACK && known_stack_sym(&aref, NULL, NULL))
		{
			// stack symbol
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (aref.storage_type == ENUM_HEAP /*&& known_heap_block(&aref) !FIX! */)
		{
			// heap block with known type
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
	}

	// we are here because we don't know anything about the op_value
	// try if we know anything of its source if any
	if (loc)
	{
		struct object_reference loc_ref;
		memset(&loc_ref, 0, sizeof(loc_ref));
		loc_ref.vaddr = loc + offset;
		loc_ref.value = 0;
		loc_ref.target_index = -1;
		fill_ref_location(&loc_ref);
		if ( (loc_ref.storage_type == ENUM_MODULE_TEXT || loc_ref.storage_type == ENUM_MODULE_DATA)
			&& known_global_sym(&loc_ref, NULL, NULL) )
		{
			// global symbol
			dprintf (" SRC=");
			print_ref(&loc_ref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (loc_ref.storage_type == ENUM_STACK && known_stack_sym(&loc_ref, NULL, NULL))
		{
			// stack symbol
			dprintf (" SRC=");
			print_ref(&loc_ref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (loc_ref.storage_type == ENUM_HEAP && (addr_type = lookup_type_by_addr(&loc_ref)) )
		{
			ULONG name_sz;
			char type_name[NAME_BUF_SZ];
			HRESULT hr = gDebugSymbols3->GetTypeName(addr_type->type.mod_base, addr_type->type.type_id, type_name, NAME_BUF_SZ, &name_sz);
			if (SUCCEEDED(hr) && name_sz < NAME_BUF_SZ)
			{
				dprintf (" SRC=[%s]", type_name);
			}
			return;
		}
	}

	// lastly, we can still provide something useful, like heap/stack info
	if (op_size == ptr_sz && op_value)
	{
		if (aref.storage_type != ENUM_UNKNOWN)
		{
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
	}

	dprintf ("\n");
}

/*
 * A simple progress bar for commands taking long time
 */
#define DEFAULT_WIDTH 40
static unsigned long pb_total = 0;
static int screen_width;
static int scrren_height;
static int pb_cur_pos;
void init_progress_bar(unsigned long total)
{
	pb_total = total;

	scrren_height = 0;
	screen_width = DEFAULT_WIDTH;
	pb_cur_pos = 0;
}

void set_current_progress(unsigned long val)
{
	int pos = val * screen_width / pb_total;
	while (pos > pb_cur_pos)
	{
		CA_PRINT(".");
		pb_cur_pos++;
	}
	fflush (stdout);
}

void end_progress_bar(void)
{
	CA_PRINT("\n");
}

address_t ca_eval_address(const char* expr)
{
	return GetExpression (expr);
}

void calc_heap_usage(char *expr)
{
	size_t var_len = 0;
	size_t ptr_sz = g_ptr_bit >> 3;

	struct object_reference ref;
	ref.vaddr = 0;
	ref.value = 0;

	if (isdigit(*expr))
	{
		var_len = ptr_sz;
		ref.vaddr = GetExpression (expr);
		fill_ref_location(&ref);
		if (ref.storage_type != ENUM_HEAP || !ref.where.heap.inuse)
			return;
	}
	else
	{
		ULONG64 addr, mod_base;
		ULONG type_id, type_sz;

		if (gDebugSymbols3->GetOffsetByName(expr, &addr) == E_FAIL
			|| gDebugSymbols3->GetSymbolTypeId(expr, &type_id, &mod_base) != S_OK
			|| gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) != S_OK)
			return;
		var_len = type_sz;
		ref.vaddr = addr;
		fill_ref_location(&ref);
	}

	if (ref.vaddr)
	{
		struct inuse_block *inuse_blocks = NULL;
		unsigned long num_inuse_blocks;

		// First, create and populate an array of all in-use blocks
		inuse_blocks = build_inuse_heap_blocks(&num_inuse_blocks);
		if (!inuse_blocks || num_inuse_blocks == 0)
		{
			CA_PRINT("Failed: no in-use heap block is found\n");
		}
		else
		{
			unsigned long aggr_count = 0;
			size_t aggr_size = 0;

			CA_PRINT("Heap memory consumed by ");
			print_ref(&ref, 0, CA_FALSE, CA_FALSE);
			// Include all reachable blocks
			if (calc_aggregate_size(&ref, var_len, CA_TRUE, inuse_blocks, num_inuse_blocks, &aggr_size, &aggr_count))
			{
				CA_PRINT("All reachable:\n");
				CA_PRINT("    |--> ");
				print_size(aggr_size);
				CA_PRINT(" (%ld blocks)\n", aggr_count);
			}
			else
				CA_PRINT("Failed to calculate heap usage\n");
			// Directly referenced heap blocks only
			if (calc_aggregate_size(&ref, var_len, CA_FALSE, inuse_blocks, num_inuse_blocks, &aggr_size, &aggr_count))
			{
				CA_PRINT("Directly referenced:\n");
				CA_PRINT("    |--> ");
				print_size(aggr_size);
				CA_PRINT(" (%ld blocks)\n", aggr_count);
			}
			// remember to cleanup
			free_inuse_heap_blocks (inuse_blocks, num_inuse_blocks);
		}
	}
	else
		CA_PRINT("Input expression doesn't reference any heap memory\n");
}
