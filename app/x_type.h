/************************************************************************
** FILE NAME..... x_type.h
**
** (c) COPYRIGHT
**
** FUNCTION......... Misc services
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
#ifndef X_TYPE_H_
#define X_TYPE_H_

#ifdef WIN32
#include <windows.h>
#pragma warning(disable: 4267)
#else
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <limits.h>
#endif
#include <stdio.h>
#include <time.h>

#ifdef WIN32

#ifndef address_t
#ifdef WIN64
typedef ULONG64 address_t;
#else
typedef DWORD address_t;
#endif
#endif

typedef DWORD ptr_t_32;

#define CA_PRINT(format,...) \
	printf(format, __VA_ARGS__)

#ifdef WIN64
#define PRINT_FORMAT_POINTER "0x%I64x"
#define PRINT_FORMAT_SIZE    "%I64d"
#else
#define PRINT_FORMAT_POINTER "0x%lx"
#define PRINT_FORMAT_SIZE    "%ld"
#endif

#else

typedef unsigned long address_t;

/*#ifdef sun
#define CA_PRINT(...) \
	printf(__VA_ARGS__ )
#else
#define CA_PRINT(format,args...) \
	printf(format, ##args)
#endif*/
#define CA_PRINT printf

#define PRINT_FORMAT_POINTER "0x%lx"
#define PRINT_FORMAT_SIZE    "%ld"

#endif

#define PERMISSION_X 0x0001
#define PERMISSION_W 0x0002
#define PERMISSION_R 0x0004

#endif // X_TYPE_H_
