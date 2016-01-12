/*
 * x_type.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_TYPE_H_
#define X_TYPE_H_

#include <windows.h>
#include <windef.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

//
// Define KDEXT_64BIT to make all wdbgexts APIs recognize 64 bit addresses
// It is recommended for extensions to use 64 bit headers from wdbgexts so
// the extensions could support 64 bit targets.
//
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#pragma warning(disable:4244) // '=' : conversion from 'address_t' to 'ptr_t_32', possible loss of data
#pragma warning(disable:4334) // '<<' : result of 32-bit shift implicitly converted to 64 bits (was 64-bit shift intended?)

#include <extsfns.h>

typedef DWORD ptr_t_32;

#ifdef _WIN64
typedef ULONG64 address_t;
//typedef ULONG64 size_t;
#define BAD_VALUE 0xdeadbeefbadc0ffe
//#define STACK_PTR_NAME "rsp"
#define PRINT_FORMAT_SIZE "%I64d"
#define PRINT_FORMAT_LONG_OFFSET "0x%I64x"
#define PRINT_FORMAT_POINTER "0x%I64x"
#else	//WIN32
typedef DWORD address_t;
typedef ULONG size_t;
#define BAD_VALUE 0xdeadbeef
//#define STACK_PTR_NAME "esp"
#define PRINT_FORMAT_SIZE "%ld"
#define PRINT_FORMAT_LONG_OFFSET "0x%lx"
#define PRINT_FORMAT_POINTER "0x%lx"
#endif

#define MAX_FRAMES  128

#define CA_PRINT(format,...) \
	dprintf(format, __VA_ARGS__)

#define snprintf _snprintf
#define strdup   _strdup

//typedef bool CA_BOOL;
#define CA_BOOL  bool
#define CA_TRUE  true
#define CA_FALSE false

enum SymTagEnum {
   SymTagNull,
   SymTagExe,
   SymTagCompiland,
   SymTagCompilandDetails,
   SymTagCompilandEnv,
   SymTagFunction,
   SymTagBlock,
   SymTagData,
   SymTagAnnotation,
   SymTagLabel,
   SymTagPublicSymbol,
   SymTagUDT,
   SymTagEnum,
   SymTagFunctionType,
   SymTagPointerType,
   SymTagArrayType,
   SymTagBaseType,
   SymTagTypedef,
   SymTagBaseClass,
   SymTagFriend,
   SymTagFunctionArgType,
   SymTagFuncDebugStart,
   SymTagFuncDebugEnd,
   SymTagUsingNamespace,
   SymTagVTableShape,
   SymTagVTable,
   SymTagCustom,
   SymTagThunk,
   SymTagCustomType,
   SymTagManagedType,
   SymTagDimension
};

extern bool g_debug_core;

#ifdef _WIN32
extern IDebugSymbols3* gDebugSymbols3;
extern IDebugControl*  gDebugControl;
extern IDebugAdvanced2* gDebugAdvanced2;
extern IDebugRegisters2* gDebugRegisters2;
extern IDebugDataSpaces4* gDebugDataSpaces4;
extern IDebugClient4* gDebugClient4;
extern IDebugSystemObjects* gDebugSystemObjects;
extern void restore_context();

// For decode function
struct win_type
{
	ULONG   type_id;
	ULONG64 mod_base;
};

extern enum SymTagEnum get_type_code(struct win_type type, ULONG64 addr);
extern void print_type_name(struct win_type type);
extern void print_func_address(address_t addr, char* buf, int buf_sz);
extern void get_stack_sym_and_type(address_t addr, const char** symname, struct win_type* ptype);
extern struct win_type
get_struct_field_type_and_name(struct win_type, ULONG, address_t*, size_t*, char*, size_t);
extern void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea);
#endif

#endif // X_TYPE_H_
