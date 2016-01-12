/************************************************************************
** FILE NAME..... util.cpp
**
** (c) COPYRIGHT
**
** FUNCTION......... Helper functions.
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
#ifdef WIN32
#ifndef S_ISREG
#define S_ISREG(x) (((x) & S_IFMT) == S_IFREG)
#endif
#else
#include <stdio.h>
#include <ctype.h>
#include <wchar.h>
#endif

#include "cmd_impl.h"
#include "util.h"
#include "stl_container.h"
#include "heap.h"
#include "search.h"

const int min_chars = MIN_CHARS_OF_STRING;

#define LINE_BUFFER_SZ 256
////////////////////////////////////////////////////////////////////
// Helper functions
////////////////////////////////////////////////////////////////////
address_t AskParam(const char* message, const char* env_name, CA_BOOL ask)
{
	if (env_name)
	{
		const char* val_str = getenv(env_name);
		if (val_str)
		{
			printf("%s\n", val_str);
			return String2ULong(val_str);
		}
	}
	else if (!ask)
		return 0;

	printf("%s ? ", message);
	char linebuf[LINE_BUFFER_SZ];
	fgets(linebuf, LINE_BUFFER_SZ, stdin);

	if (strlen(linebuf) <= 0)
		return 0;
	else
	{
		char* cursor = &linebuf[0];
		// remove return character
		for (int i=0; i<LINE_BUFFER_SZ; i++, cursor++)
		{
			if (*cursor == '\n')
			{
				*cursor = '\0';
				break;
			}
		}
	}

	if (0==strcmp(linebuf, "y") )
		return 1;
	else if (0==strcmp(linebuf, "n") )
		return 0;

	return String2ULong(linebuf);
}

#define MAX_PATH_LEN 4096
char* AskPath(const char* pathname)
{
	printf("%s Path ? ", pathname);
	char* lpPath = new char [MAX_PATH_LEN];
	fgets(lpPath, MAX_PATH_LEN, stdin);
	return lpPath;
}

address_t String2ULong(const char* exp)
{
	if (!exp)
		return 0;

	address_t result = 0;
	if (isdigit(exp[0]))
	{
		int base;
		if (exp[0] == '0' && exp[1] == 'x')
			base = 16;
		else
			base = 10;

		char* EndPointer;
#if defined(WIN64) || defined(_WIN64)
		result = ::_strtoui64(exp, &EndPointer, base);
#else
		result = ::strtoul(exp, &EndPointer, base);
#endif
	}
	return result;
}

static void PrintString(char* ipCoreStart, ca_segment* segment, address_t str)
{
	if (!str)
		return;

	char c;
	do
	{
		c = 0;
		if (read_memory_wrapper(segment, str, &c, sizeof(c)))
		{
			if (c)
			{
				printf("%c", c);
				str += sizeof(c);
			}
		}
		else
			break;
	} while (c);
}

static void PrintWString(char* ipCoreStart, ca_segment* segment, address_t str)
{
	if (!str)
		return;

	wchar_t wc;
	do
	{
		wc = 0;
		if (read_memory_wrapper(segment, str, &wc, sizeof(wc)))
		{
			if (wc)
			{
				//wprintf(L"%lc", wc);
				printf("%c", wc);
				str += sizeof(wc);
			}
		}
		else
			break;
	} while (wc);
}

// addr is the place to search string
// return string len in bytes if found
static long IsString(char* ipCoreStart, ca_segment* segment,
					address_t addr, int min_chars, bool& orbWString)
{
	// search char[]
	long len;
	address_t str_addr;
	{
		unsigned char c;
		len = 0;
		for (str_addr = addr; ; str_addr++)
		{
			if (!read_memory_wrapper(segment, str_addr, &c, sizeof(c)))
				break;
			if (isprint(c))
				len++;
			else
				break;
		}
		if (len >= min_chars)
		{
			//if (ptr_addr)
			//	printf(PRINT_FORMAT_POINTER": "PRINT_FORMAT_POINTER" (char*)=> [", ptr_addr, addr);
			//else
			//	printf("0x%llx (char[])=> [", addr);
			//PrintString(ipCoreStart, segment, addr);
			//printf("]\n");
			orbWString = false;
			return len;
		}
	}
	// search wchar_t[]
	if ((addr % sizeof(wchar_t)) == 0)
	{
		wchar_t wc;
		len = 0;
		for (str_addr = addr; ; str_addr += sizeof(wchar_t))
		{
			if (!read_memory_wrapper(segment, str_addr, &wc, sizeof(wc)))
				break;
			wc &= 0xff;
			if (isprint(wc))
				len ++;
			else
				break;
		}
		if (len >= min_chars)
		{
			//if (ptr_addr)
			//	printf("0x%lx: 0x%lx (wchar_t*)=> [", ptr_addr, addr);
			//else
			//	printf("0x%lx (wchar_t[])=> [", addr);
			//PrintWString(ipCoreStart, segment, addr);
			//printf("]\n");
			orbWString = true;
			return len * sizeof(wchar_t);
		}
	}

	return 0;
}

bool FindString(char* ipCoreStart, address_t start, address_t end)
{
	int ptr_bit = g_ptr_bit;
	int ptr_sz = ptr_bit >> 3;
	ca_segment* segment = get_segment(start, end-start);
	if (!segment)
	{
		printf("Error: address and its page is not found in core\n");
		return false;
	}

	address_t cursor;
	bool lbWString;

	// Search String
	printf("String ...\n");
	for (cursor = start; cursor < end; )
	{
		size_t lStrLen = IsString(ipCoreStart, segment, cursor, min_chars, lbWString);
		if (lStrLen)
			cursor += lStrLen;
		else
			cursor++;
	}

	// Search pointer to a string
	printf("Pointer to string ...\n");
	for (cursor = ALIGN(start, ptr_sz); cursor < end; cursor += ptr_sz)
	{
		address_t addr = 0;
		if (!read_memory_wrapper(segment, cursor, &addr, ptr_sz))
			return false;
		if (addr == 0)
			continue;
		// The pointer may point to a new segment
		ca_segment* strsegment = get_segment(addr, min_chars);
		if (!strsegment)
			continue;
		// addr is holding a candidate
		IsString(ipCoreStart, strsegment, addr, min_chars, lbWString);
	}
	return true;
}



const char* GetBaseName(const char* ipPath)
{
	size_t len = strlen(ipPath);
	const char* lpBase = ipPath + len - 1;
	while (lpBase >= ipPath)
	{
		if (*lpBase == '/')
		{
			return lpBase+1;
		}
		lpBase--;
	}
	return ipPath;
}

bool FileReadable(const char* ipFilePath)
{
	struct stat lStat;
	if (0 == stat(ipFilePath, &lStat))
	{
		if (S_ISREG(lStat.st_mode))
			return true;
	}
	return false;
}

const char* RemoveLineReturn(char* ipLineBuf)
{
	size_t len = strlen(ipLineBuf);
	if (len>=1 && ipLineBuf[len-1] == '\n')
		ipLineBuf[len-1] = '\0';
	return ipLineBuf;
}

/////////////////////////////////////////////////////////////////////////
// Whether the object starting at addr has a _vptr embedded
//
// Current implementation checks if the first 8-byte points to a module's
// .data section
/////////////////////////////////////////////////////////////////////////
CA_BOOL is_heap_object_with_vptr(const struct object_reference* ref, char* name_buf, size_t buff_sz)
{
	int ptr_sz = g_ptr_bit >> 3;
	address_t addr = ref->where.heap.addr;
	address_t val = 0;
	if (read_memory_wrapper(NULL, addr, &val, ptr_sz)	&& val)
	{
		ca_segment* segment = get_segment(val, 1);
#ifdef WIN32
		if (segment && (segment->m_type == ENUM_MODULE_DATA || segment->m_type == ENUM_MODULE_TEXT) )
#else
		if (segment && segment->m_type == ENUM_MODULE_DATA)
#endif
			return CA_TRUE;
	}
	return CA_FALSE;
}

//////////////////////////////////////////////////////////////
// List all segments discovered
//////////////////////////////////////////////////////////////
bool PrintSegment()
{
	printf("\n");
	printf("No.                vaddr       memsz      filesz     perm    name\n");
	printf("=================================================================\n");

	// all LOAD segments are already collected in a global vector
	for (int i=0; i<g_segment_count; i++)
	{
		ca_segment* segment = &g_segments[i];
		// segment sequence number
		printf("[%3d]", i);
		// segment info
#ifdef WIN64
		printf(" %#18I64x ", segment->m_vaddr);
		printf(" %10I64d ", segment->m_vsize);
		printf(" %10I64d ", segment->m_fsize);
#else
		printf(" %#18lx ", segment->m_vaddr);
		printf(" %10ld ", segment->m_vsize);
		printf(" %10ld ", segment->m_fsize);
#endif
		// segment permission bits
		char perm[] = "---";
		if (segment->m_exec)
			perm[2] = 'X';
		if (segment->m_write)
			perm[1] = 'W';
		if (segment->m_read)
			perm[0] = 'R';
		printf(" %7s ", perm);

		// What kind of segment is it ?
		if (!segment->m_read && !segment->m_write && !segment->m_exec && segment->m_vsize > 0)
		{
			if (segment->m_vsize == SYS_PAGE_SZ && g_segments[i+1].m_type == ENUM_STACK)
				printf("  [ thread guard page ]");
			else
				printf("  [ inaccessible ]");
		}
		else if (segment->m_type == ENUM_STACK)
		{
			// stack segment
			printf("  [ stack ]  [ tid=%d ]", segment->m_thread.tid);
		}
		else if (segment->m_type == ENUM_MODULE_TEXT)
		{
			if (segment->m_exec)
				printf("  [ .text ]  [ %s ]", segment->m_module_name);
			else
				printf("  [ .rodat]  [ %s ]", segment->m_module_name);
		}
		else if (segment->m_type == ENUM_MODULE_DATA)
		{
			if (segment->m_write)
				printf("  [ .data ]  [ %s ]", segment->m_module_name);
			else if (segment->m_read)
				printf("  [ .rodat]  [ %s ]", segment->m_module_name);
			else
				printf("  [ inaccessible ]");
		}
		else if (segment->m_type == ENUM_HEAP)
			printf("  [ heap ]");
		else
			printf("  [ unknown ]");

		printf("\n");
	}
	return true;
}

void print_heap_ref(const struct object_reference* ref)
{
	int ptr_sz = g_ptr_bit >> 3;
	// special care is taken for heap object w/ _vptr
	if (is_heap_object_with_vptr(ref, NULL, 0))
	{
		address_t vptr = 0;
		if (read_memory_wrapper(NULL, ref->where.heap.addr, &vptr, ptr_sz))
			CA_PRINT(" (_vptr="PRINT_FORMAT_POINTER")", vptr);
	}
}

void print_register_ref(const struct object_reference* ref)
{
	const char* reg_name;
	if (!ref->where.reg.name)
		reg_name = get_register_name (ref->where.reg.reg_num);
	else
		reg_name = ref->where.reg.name;
	CA_PRINT(" thread %d %s="PRINT_FORMAT_POINTER, ref->where.reg.tid, reg_name, ref->value);
}

void print_stack_ref(const struct object_reference* ref)
{
	CA_PRINT(" thread %d rsp%+d @"PRINT_FORMAT_POINTER, ref->where.stack.tid, ref->where.stack.offset, ref->vaddr);
	if (ref->value)
		CA_PRINT(": "PRINT_FORMAT_POINTER, ref->value);
}

void print_global_ref(const struct object_reference* ref)
{
	CA_PRINT (" %s", ref->where.module.name);
	CA_PRINT (" @"PRINT_FORMAT_POINTER, ref->vaddr);
	if (ref->value)
		CA_PRINT (": "PRINT_FORMAT_POINTER, ref->value);
}

void clear_addr_type_map()
{
}

CA_BOOL inferior_memory_read (address_t addr, void* buffer, size_t sz)
{
	return CA_FALSE;
}

address_t get_var_addr_by_name(const char* varname, CA_BOOL ask)
{
	if (ask)
	{
		printf("Please input the address of variable %s\n", varname);
#ifdef __GNUC__
		printf("You can find it by command \"(gdb)print &%s\"\n", varname, varname);
#else
		printf("You can find it by command \"(windbg)? $%s\"\n", varname, varname);
#endif
	}

	char* env_name = strdup(varname);
	char* cursor = env_name;
	while (*cursor)
	{
		if (islower(*cursor))
			*cursor = toupper(*cursor);
		cursor++;
	}
	address_t rs = AskParam(varname, env_name, ask);
	free(env_name);
	return rs;
}

static CA_BOOL g_control_c_pressed = CA_FALSE;

CA_BOOL user_request_break()
{
	if (g_control_c_pressed)
	{
		g_control_c_pressed = CA_FALSE;
		return CA_TRUE;
	}
	return CA_FALSE;
}

CA_BOOL get_vtable_from_exp(const char*, struct CA_LIST*, char*, size_t, size_t*)
{
	return CA_FALSE;
}

CA_BOOL known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	return CA_FALSE;
}

CA_BOOL known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	return CA_FALSE;
}

#define DEFAULT_WIDTH 40
static unsigned long pb_total;
static int screen_width;
static int pb_cur_pos;
void init_progress_bar(unsigned long total)
{
	pb_total = total;
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
	return atol(expr);
}

void calc_heap_usage(char *exp)
{
}
