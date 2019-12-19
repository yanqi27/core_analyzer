/************************************************************************
** FILE NAME..... core_pe_x86.cpp
**
** (c) COPYRIGHT
**
** FUNCTION......... PE core file format (x86 & x86_64)
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
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <map>

#ifndef __in_bcount_opt
 #define __in_bcount_opt(x)
#endif
#ifndef __out_bcount_opt
 #define __out_bcount_opt(x)
#endif
#include <DbgHelp.h>

#include "cmd_impl.h"
#include "util.h"
#include "stl_container.h"

#pragma warning(disable:4996)

typedef std::pair<address_t,ca_segment*> SEG_PAIR;

unsigned int g_ptr_bit = 64;
static const char* g_exec_name = NULL;

static struct ca_segment* NewSegment(address_t vaddr,
				size_t vsize,
				char*  faddr,
				size_t fsize,
				int read,
				int write,
				int exe);

int get_frame_number(const struct ca_segment* segment, address_t vaddr, int* offset)
{
	int frame_num;
	address_t stack_ptr;
	CONTEXT* thread_context = (CONTEXT*)segment->m_thread.context;
#ifdef WIN64
	stack_ptr = thread_context->Rsp;
#else
	stack_ptr = thread_context->Esp;
#endif

	if (vaddr < stack_ptr)
	{
		frame_num = -1;
		*offset = 0;
	}
	else
	{
		frame_num = 0;
		*offset = (int) (vaddr - stack_ptr);
	}
	return frame_num;
}

static const char* MemRegionState(unsigned int state)
{
	const char* rs;
	if (state & MEM_COMMIT)
		rs = "MEM_COMMIT";
	else if (state & MEM_FREE)
		rs = "MEM_FREE";
	else if (state & MEM_RESERVE)
		rs = "MEM_RESERVE";
	else
		rs = "UNKNOWN";
	return rs;
}

static const char* MemRegionType(unsigned int type)
{
	const char* rs;
	if (type & MEM_IMAGE)
		rs = "MEM_IMAGE";
	else if (type & MEM_MAPPED)
		rs = "MEM_MAPPED";
	else if (type & MEM_PRIVATE)
		rs = "MEM_RESERVE";
	else
		rs = "UNKNOWN";
	return rs;
}

bool PrintCoreInfo(MmapFile& irCore)
{
	char* ipCoreFileAddr = irCore.GetStartAddr();
	char* ipCoreEnd   = irCore.GetEndAddr();

	MINIDUMP_HEADER* pdump = (MINIDUMP_HEADER*) ipCoreFileAddr;

	// Minidump header
	printf("\n\n");
	printf("NumberOfStreams: %ld\n", pdump->NumberOfStreams);
	printf("CheckSum: %ld\n", pdump->CheckSum);
	//printf("TimeDateStamp: %s", ctime((time_t*)&pdump->TimeDateStamp));
	printf("Flags: %I64d\n", pdump->Flags);

	// Streams
	printf("Streams:\n");
	MINIDUMP_DIRECTORY* pMiniDumpDir = (MINIDUMP_DIRECTORY*) (ipCoreFileAddr + pdump->StreamDirectoryRva);
	for (unsigned int i=0; i<pdump->NumberOfStreams; i++, pMiniDumpDir++)
	{
		MINIDUMP_LOCATION_DESCRIPTOR location = pMiniDumpDir->Location;
		printf("\t[%d] ", i);
		switch (pMiniDumpDir->StreamType)
		{
		case UnusedStream:
			printf("Unused Stream");
			break;
		case ThreadListStream:
			printf("Thread list: ");
			{
				MINIDUMP_THREAD_LIST* thread_list = (MINIDUMP_THREAD_LIST*) (ipCoreFileAddr + location.Rva);
				printf("%d\n", thread_list->NumberOfThreads);
				/*MINIDUMP_THREAD* p_thread = &thread_list->Threads[0];
				for (unsigned int pseudo_tid=0; pseudo_tid<thread_list->NumberOfThreads; pseudo_tid++, p_thread++)
				{
					MINIDUMP_MEMORY_DESCRIPTOR* p_stack = &p_thread->Stack;
					CONTEXT* thread_context = (CONTEXT*) (ipCoreFileAddr + p_thread->ThreadContext.Rva);
					printf("\t\t[%d] tid=%ld teb=0x%I64x\n",
						pseudo_tid, p_thread->ThreadId, p_thread->Teb);
					printf("\t\t\tstack=[0x%I64x, 0x%I64x]\n",
						p_stack->StartOfMemoryRange, p_stack->StartOfMemoryRange+p_stack->Memory.DataSize);
#ifdef WIN64
					printf("\t\t\trip=0x"ADDR_PRINT_FORMAT", rbp=0x%lx rsp=0x%lx\n",
						thread_context->Rip, thread_context->Rbp, thread_context->Rsp);
#else
					printf("\t\t\teip=0x"ADDR_PRINT_FORMAT", ebp=0x%lx esp=0x%lx\n",
						thread_context->Eip, thread_context->Ebp, thread_context->Esp);
#endif
				}*/
			}
			break;
		case ModuleListStream:
			printf("Module list: ");
			{
				MINIDUMP_MODULE_LIST* module_list = (MINIDUMP_MODULE_LIST*) (ipCoreFileAddr + location.Rva);
				MINIDUMP_MODULE* p_module = &module_list->Modules[0];
				printf("%d\n", module_list->NumberOfModules);
				/*for (unsigned int mod_index=0; mod_index<module_list->NumberOfModules; mod_index++, p_module++)
				{
					MINIDUMP_STRING* name_str = (MINIDUMP_STRING*) (ipCoreFileAddr + p_module->ModuleNameRva);
					wprintf(L"\t\t[%d] %s\n", mod_index, &name_str->Buffer[0]);
					//printf("\t\t0x%I64x\n", p_module->BaseOfImage);
				}*/
			}
			break;
		case MemoryListStream:
			printf("Memory list: ");
			{
				MINIDUMP_MEMORY_LIST* mem_list = (MINIDUMP_MEMORY_LIST*)(ipCoreFileAddr + location.Rva);
				MINIDUMP_MEMORY_DESCRIPTOR* region = &mem_list->MemoryRanges[0];
				printf("%d\n", mem_list->NumberOfMemoryRanges);
				/*for (unsigned int reg_index=0; reg_index<mem_list->NumberOfMemoryRanges; reg_index++, region++)
				{
					printf("\t\t[%d] 0x%I64x - 0x%I64x\n",
						reg_index, region->StartOfMemoryRange, region->StartOfMemoryRange + region->Memory.DataSize);
				}*/
			}
			break;
		case ExceptionStream:
			printf("Exception:\n");
			{
				MINIDUMP_EXCEPTION_STREAM* exception_stream = (MINIDUMP_EXCEPTION_STREAM*)(ipCoreFileAddr + location.Rva);
				printf("\t\tExecption: tid=%d\n", exception_stream->ThreadId);
			}
			break;
		case SystemInfoStream:
			printf("SystemInfo\n");
			{
				MINIDUMP_SYSTEM_INFO* sysinfo = (MINIDUMP_SYSTEM_INFO*)(ipCoreFileAddr + location.Rva);
				printf("\t\tCPU: num=%d arch=%d\n",
					sysinfo->NumberOfProcessors, sysinfo->ProcessorArchitecture);
				printf("\t\tOS: ver=%d.%d build=%d platform=%d\n",
					sysinfo->MajorVersion, sysinfo->MinorVersion, sysinfo->BuildNumber, sysinfo->PlatformId);
			}
			break;
		case ThreadExListStream:
			printf("ThreadEx list");
			break;
		case Memory64ListStream:
			printf("Memory64 list: ");
			{
				MINIDUMP_MEMORY64_LIST* mem64_list =
					(MINIDUMP_MEMORY64_LIST*)(ipCoreFileAddr + location.Rva);
				printf("%I64d\n", mem64_list->NumberOfMemoryRanges);
				MINIDUMP_MEMORY_DESCRIPTOR64* region = &mem64_list->MemoryRanges[0];
				ULONG64 TotalBytes = 0;
				for (unsigned int k=0; k<mem64_list->NumberOfMemoryRanges; k++, region++)
				{
#ifdef CA_DEBUG
					printf("\t\t[%d] 0x"ADDR_PRINT_FORMAT" - 0x"ADDR_PRINT_FORMAT"\n",
						k, region->StartOfMemoryRange, region->StartOfMemoryRange + region->DataSize);
#endif
					TotalBytes += region->DataSize;
				}
				printf("\t\tTotal Bytes = %I64d\n", TotalBytes);
			}
			break;
		case CommentStreamA:
			printf("Comment list");
			break;
		case CommentStreamW:
			printf("Comment list");
			break;
		case HandleDataStream:
			printf("HandleData list");
			{
				MINIDUMP_HANDLE_DATA_STREAM* handle_data =
					(MINIDUMP_HANDLE_DATA_STREAM*)(ipCoreFileAddr + location.Rva);
				printf(" NumberOfDescriptors %d\n", handle_data->NumberOfDescriptors);
				MINIDUMP_HANDLE_DESCRIPTOR* handle = (MINIDUMP_HANDLE_DESCRIPTOR*)(handle_data+1);
				for (unsigned int handle_index=0; handle_index<handle_data->NumberOfDescriptors; handle_index++, handle++)
				{
					MINIDUMP_STRING* type_str = (MINIDUMP_STRING*)(ipCoreFileAddr + handle->TypeNameRva);
					//MINIDUMP_STRING* obj_str = (MINIDUMP_STRING*)(ipCoreFileAddr + handle->ObjectNameRva);
					wprintf(L"\t\t[%d] Handle=0x%I64x type=%s handle_count=%d\n",
						handle_index, handle->Handle, &type_str->Buffer[0], handle->HandleCount);
				}
			}
			break;
		case FunctionTableStream:
			printf("FunctionTable list");
			{
				MINIDUMP_FUNCTION_TABLE_STREAM* func_table =
						(MINIDUMP_FUNCTION_TABLE_STREAM*)(ipCoreFileAddr + location.Rva);
			}
			break;
		case UnloadedModuleListStream:
			printf("UnloadedModule list");
			{
				MINIDUMP_UNLOADED_MODULE_LIST* mod_list =
					(MINIDUMP_UNLOADED_MODULE_LIST*)(ipCoreFileAddr + location.Rva);
			}
			break;
		case MiscInfoStream:
			printf("MiscInfo\n");
			{
				MINIDUMP_MISC_INFO* miscinfo = (MINIDUMP_MISC_INFO*)(ipCoreFileAddr + location.Rva);
				printf("\t\tpid=%d\n", miscinfo->ProcessId);
			}
			break;
		case MemoryInfoListStream:
			printf("MemoryInfo list");
			{
				MINIDUMP_MEMORY_INFO_LIST* meminfo_list =
					(MINIDUMP_MEMORY_INFO_LIST*) (ipCoreFileAddr + location.Rva);
				printf(" number of entries: %I64d\n", meminfo_list->NumberOfEntries);
				MINIDUMP_MEMORY_INFO* region = (MINIDUMP_MEMORY_INFO*)(meminfo_list+1);
				ULONG64 TotalBytes = 0;
				for (unsigned int k=0; k<meminfo_list->NumberOfEntries; k++, region++)
				{
					printf("\t\t[%d] 0x%I64x - 0x%I64x state=%s prot=0x%x type=%s\n",
						k, region->BaseAddress, region->BaseAddress + region->RegionSize,
						MemRegionState(region->State), region->Protect, MemRegionType(region->Type));
					TotalBytes += region->RegionSize;
				}
				printf("\t\tTotal Bytes = %I64d\n", TotalBytes);
			}
			break;
		case ThreadInfoListStream:
			printf("ThreadInfo list");
			{
				MINIDUMP_THREAD_INFO_LIST* threadinfo_list =
					(MINIDUMP_THREAD_INFO_LIST*)(ipCoreFileAddr + location.Rva);
				printf(" NumberOfEntries: %d\n", threadinfo_list->NumberOfEntries);
				MINIDUMP_THREAD_INFO* threadinfo = (MINIDUMP_THREAD_INFO*)(threadinfo_list+1);
				/*for (unsigned int k=0; k<threadinfo_list->NumberOfEntries; k++, threadinfo++)
				{
					printf("\t\t[%d] tid=%d StartAddress=0x%I64x\n",
						k, threadinfo->ThreadId, threadinfo->StartAddress);
				}*/
			}
			break;
		/*case HandleOperationListStream:
			printf("HandleOperation list");
			{
				MINIDUMP_HANDLE_OPERATION_LIST* handle_opt_list =
						(MINIDUMP_HANDLE_OPERATION_LIST*)(ipCoreFileAddr + location.Rva);
				printf("\tNumberOfEntries=%d\n", handle_opt_list->NumberOfEntries);
			}
			break;*/
		default:
			printf("unknown type [%d]", pMiniDumpDir->StreamType);
			break;
		}
		printf("\n");
	}

	printf("Segments:\n");
	PrintSegment();
	return true;
}

#ifdef WIN64
static const char* reg_names[] =
{
	"rax",
	"rcx",
	"rdx",
	"rbx",
	"rsp",
	"rbp",
	"rsi",
	"rdi",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"rip"
};
#else
static const char* reg_names[] =
{
	"edi",
	"esi",
	"ebx",
	"edx",
	"ecx",
	"eax",
	"ebp"
};
#endif

#define NUM_REGS sizeof(reg_names)/sizeof(const char*)

bool VerifyCoreFile(char* ipCoreFileAddr)
{
	MINIDUMP_HEADER* pdump = (MINIDUMP_HEADER*) ipCoreFileAddr;

	if (MINIDUMP_SIGNATURE != pdump->Signature
		&& MINIDUMP_VERSION != (pdump->Version & 0xffff))
	{
		printf("[Error] Not Mini dump file\n");
		return false;
	}

	return true;
}


//////////////////////////////////////////////////////////////
// Sanity check of exec file
//////////////////////////////////////////////////////////////
bool VerifyExecFile(char* ipExecStart)
{
	return true;
}

// deduce target's bit mode by poking its executable
static bool SetPtrBit(const char* modname)
{
	// open module file
	FILE* fp = ::fopen(modname, "rb");
	if(!fp)
	{
		CA_PRINT("Failed to open module %s for read\n", modname);
		const char* execpath = getenv("CA_EXEC");
		if (execpath)
		{
			fp = ::fopen(execpath, "rb");
			if (!fp)
			{
				CA_PRINT("Failed to open module %s for read too\n", execpath);
				return false;
			}
		}
		else
		{
			CA_PRINT("If the module has been removed from this path, please use environment variable CA_EXEC to point to the new location.\n");
			return false;
		}
	}
	// dos header
	IMAGE_DOS_HEADER DOSHeader;
	if(1 != ::fread(&DOSHeader, sizeof(DOSHeader), 1, fp))
	{
		CA_PRINT("Failed to read IMAGE_DOS_HEADER\n");
		fclose(fp);
		return false;
	}
	// seek to nt header
	if(0 != ::fseek(fp, DOSHeader.e_lfanew, SEEK_SET))
	{
		CA_PRINT("Failed to seek to NT Header\n");
		fclose(fp);
		return false;
	}
	// nt header
	IMAGE_NT_HEADERS NTHeader;
	if(1 != ::fread(&NTHeader, sizeof(NTHeader), 1, fp))
	{
		CA_PRINT("Failed to read IMAGE_NT_HEADERS\n");
		fclose(fp);
		return false;
	}
	if (NTHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		g_ptr_bit = 64;
	else if (NTHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		g_ptr_bit = 32;
	else
	{
		CA_PRINT("Unknown platform NTHeader.FileHeader.Machine=%d\n", NTHeader.FileHeader.Machine);
		fclose(fp);
		return false;
	}

	fclose(fp);
	return true;
}

//////////////////////////////////////////////////////////////
// A thread stack is messed up, take a guess
//////////////////////////////////////////////////////////////
bool UnwindThreadCallstack(char* ipCoreStart, unsigned long tid, const char* ipLibPath)
{
	// find the segment of the thread's stack.
	printf("[Error] Not implemented (coming soon)\n");
	return true;
}

address_t get_rsp(const struct ca_segment* segment)
{
	CONTEXT* thread_context = (CONTEXT*)segment->m_thread.context;
#ifdef WIN64
	return thread_context->Rsp;
#else
	return thread_context->Esp;
#endif
}

int get_thread_id (const struct ca_segment* segment)
{
	return segment->m_thread.tid;
}

int read_registers(const struct ca_segment* segment, struct reg_value* regs, int bufsz)
{
	if (regs)
	{
		CONTEXT* thread_context = (CONTEXT*)segment->m_thread.context;
#ifdef WIN64
		DWORD64* registers = &thread_context->Rax;
#else
		DWORD* registers = &thread_context->Edi;
#endif
		if (thread_context->ContextFlags & CONTEXT_INTEGER)
		{
			for (int k=0; k<NUM_REGS; k++)
			{
				regs[k].reg_width = 8;
				regs[k].value = (address_t) registers[k];
			}
			return NUM_REGS;
		}
		else
			return 0;
	}
	return NUM_REGS;
}

bool search_registers(const struct ca_segment* segment,
						struct CA_LIST* targets,
						struct CA_LIST* refs)
{
	if (segment->m_type != ENUM_STACK)
		return false;

	bool lbFound = false;

	// registers
	CONTEXT* thread_context = (CONTEXT*)segment->m_thread.context;
#ifdef WIN64
	DWORD64* regs = &thread_context->Rax;
#else
	DWORD* regs = &thread_context->Edi;
#endif
	if (thread_context->ContextFlags & CONTEXT_INTEGER)
	{
		for (int k=0; k<NUM_REGS; k++)
		{
			struct object_range* target;
			ca_list_traverse_start(targets);
			while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
			{
				if (regs[k] >= target->low && regs[k] < target->high)
				{
					struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
					ref->storage_type  = ENUM_REGISTER;
					ref->where.reg.tid = segment->m_thread.tid;
					ref->where.reg.reg_num = k;
					ref->where.reg.name    = reg_names[k];
					ref->vaddr        = 0;
					ref->value        = regs[k];
					ca_list_push_front(refs, ref);
					lbFound = true;
					break;
				}
			}
			ca_list_traverse_start(targets);
		}
	}
	return lbFound;
}

//////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////
static bool BuildSegments(MmapFile& irCore)
{
	char* lpCoreFileStart = irCore.GetStartAddr();
	char* lpCoreFileEnd   = irCore.GetEndAddr();

	std::map<address_t,struct ca_segment*> segs;
	struct ca_segment* a_seg;

	MINIDUMP_HEADER* pdump = (MINIDUMP_HEADER*) lpCoreFileStart;
	// search memory Streams that have dumped memory bytes in file
	MINIDUMP_DIRECTORY* pMiniDumpDir = (MINIDUMP_DIRECTORY*) (lpCoreFileStart + pdump->StreamDirectoryRva);
	for (unsigned int k=0; k<pdump->NumberOfStreams; k++, pMiniDumpDir++)
	{
		MINIDUMP_LOCATION_DESCRIPTOR location = pMiniDumpDir->Location;
		// memory regions
		if (pMiniDumpDir->StreamType == Memory64ListStream)
		{
			MINIDUMP_MEMORY64_LIST* mem64_list =
					(MINIDUMP_MEMORY64_LIST*)(lpCoreFileStart + location.Rva);
			MINIDUMP_MEMORY_DESCRIPTOR64* region = &mem64_list->MemoryRanges[0];
			char* base = lpCoreFileStart + mem64_list->BaseRva;
			for (unsigned int i=0; i<mem64_list->NumberOfMemoryRanges; i++, region++)
			{
				a_seg = NewSegment (region->StartOfMemoryRange, region->DataSize,
									base, region->DataSize, 1, 1, 1);
				segs.insert(SEG_PAIR(a_seg->m_vaddr, a_seg));
				base += region->DataSize;
			}
		}
		else if (pMiniDumpDir->StreamType == MemoryListStream)
		{
			MINIDUMP_MEMORY_LIST* mem_list = (MINIDUMP_MEMORY_LIST*)(lpCoreFileStart + location.Rva);
			MINIDUMP_MEMORY_DESCRIPTOR* region = &mem_list->MemoryRanges[0];
			for (unsigned int i=0; i<mem_list->NumberOfMemoryRanges; i++, region++)
			{
				a_seg = NewSegment(region->StartOfMemoryRange, region->Memory.DataSize,
								lpCoreFileStart+region->Memory.Rva, region->Memory.DataSize, 1, 1, 1);
				segs.insert(SEG_PAIR(a_seg->m_vaddr, a_seg));
			}
		}
		// modules
		else if (pMiniDumpDir->StreamType == ModuleListStream)
		{
			MINIDUMP_MODULE_LIST* module_list = (MINIDUMP_MODULE_LIST*) (lpCoreFileStart + location.Rva);
			MINIDUMP_MODULE* module = &module_list->Modules[0];
			for (unsigned int index=0; index<module_list->NumberOfModules; index++, module++)
			{
				MINIDUMP_STRING* name_str = (MINIDUMP_STRING*) (lpCoreFileStart + module->ModuleNameRva);
				wchar_t* wname = &name_str->Buffer[0];
				size_t   len   = wcslen(wname);
				char* mod_name = new char[len + 1];
				wcstombs(mod_name, wname, len);
				mod_name[len] = '\0';
				a_seg = NewSegment(module->BaseOfImage, module->SizeOfImage,
								NULL, 0, 1, 1, 1);
				a_seg->m_module_name = mod_name;
				a_seg->m_type = ENUM_MODULE_TEXT;
				segs.insert(SEG_PAIR(a_seg->m_vaddr, a_seg));
				if (!g_exec_name)
				{
					g_exec_name = mod_name;
					if (!SetPtrBit(g_exec_name))
						return false;
				}
			}
		}
		else if (pMiniDumpDir->StreamType == ThreadListStream)
		{
			// threads, deplay thread stacks until all memory streams are processed
		}
	}
	// Minidump has a memory stream for a thread as well, avoid duplication
	pMiniDumpDir = (MINIDUMP_DIRECTORY*) (lpCoreFileStart + pdump->StreamDirectoryRva);
	for (unsigned int k=0; k<pdump->NumberOfStreams; k++, pMiniDumpDir++)
	{
		MINIDUMP_LOCATION_DESCRIPTOR location = pMiniDumpDir->Location;
		if (pMiniDumpDir->StreamType == ThreadListStream)
		{
			MINIDUMP_THREAD_LIST* thread_list = (MINIDUMP_THREAD_LIST*) (lpCoreFileStart + location.Rva);
			MINIDUMP_THREAD* thread = &thread_list->Threads[0];
			for (unsigned int pseudo_tid=0; pseudo_tid<thread_list->NumberOfThreads; pseudo_tid++, thread++)
			{
				MINIDUMP_MEMORY_DESCRIPTOR* stack = &thread->Stack;
				CONTEXT* thread_context = (CONTEXT*) (lpCoreFileStart + thread->ThreadContext.Rva);
				std::map<address_t,ca_segment*>::iterator itr;
				a_seg = NULL;
				for (itr=segs.begin(); itr!=segs.end(); itr++)
				{
					ca_segment* cursor = (*itr).second;
					if (stack->StartOfMemoryRange >= cursor->m_vaddr
						&& stack->StartOfMemoryRange < cursor->m_vaddr + cursor->m_vsize)
					{
						a_seg = cursor;
						break;
					}
				}
				if (!a_seg)
				{
					a_seg = NewSegment(stack->StartOfMemoryRange, stack->Memory.DataSize,
									lpCoreFileStart + stack->Memory.Rva, stack->Memory.DataSize, 1, 1, 0);
					segs.insert(SEG_PAIR(a_seg->m_vaddr, a_seg));
				}
				a_seg->m_thread.tid     = (int)pseudo_tid;
				a_seg->m_thread.context = thread_context;
				a_seg->m_type = ENUM_STACK;
			}
		}
	}

	// now put all segments in the global vector
	std::map<address_t,ca_segment*>::iterator seg_itr;
	for (seg_itr=segs.begin(); seg_itr!=segs.end(); seg_itr++)
	{
		a_seg = (*seg_itr).second;
		// bitwise copy
		struct ca_segment* newseg = add_one_segment (a_seg->m_vaddr, a_seg->m_vsize, true, true, true);
		memcpy(newseg, a_seg, sizeof(struct ca_segment));
	}

	// fixup of dll .data sections
	for (unsigned int i=0; i<g_segment_count; i++)
	{
		ca_segment* segment = &g_segments[i];
		if (segment->m_type == ENUM_MODULE_TEXT)
		{
			unsigned int k = i+1;
			while (k < g_segment_count)
			{
				ca_segment* next_seg = &g_segments[k];
				if (next_seg->m_vaddr >= segment->m_vaddr
					&& next_seg->m_vaddr+next_seg->m_vsize <= segment->m_vaddr + segment->m_vsize)
				{
					next_seg->m_type = ENUM_MODULE_DATA;
					next_seg->m_module_name = segment->m_module_name;
					next_seg->m_read = 1;
					next_seg->m_write = 1;
					next_seg->m_exec = 0;
				}
				else
					break;
				k++;
			}
		}
	}

	return true;
}

extern bool g_dbgheap;

bool InitCoreAnalyzer(MmapFile& irExec, MmapFile& irCore)
{
	bool rc = BuildSegments(irCore) /*&& test_segments(true)*/;

	return rc;
}

static struct ca_segment*
NewSegment(address_t vaddr, size_t vsize, char* faddr, size_t fsize, int read, int write, int exec)
{
	struct ca_segment* segment = (struct ca_segment*) malloc(sizeof(struct ca_segment));
	segment->m_vaddr = vaddr;
	segment->m_vsize = vsize;
	segment->m_faddr = faddr;
	segment->m_fsize = fsize;
	segment->m_type  = ENUM_UNKNOWN;
	segment->m_bitvec_ready = 0;
	segment->m_read = read;
	segment->m_write = write;
	segment->m_exec = exec;
	segment->m_ptr_bitvec = NULL;
	segment->m_module_name = NULL;

	return segment;
}

const char* get_register_name(int tid)
{
	if (tid >= 0 && tid < NUM_REGS)
		return reg_names[tid];
	else
		return NULL;
}
