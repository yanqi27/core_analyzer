/************************************************************************
** FILE NAME..... cross_platform.h
**
** (c) COPYRIGHT
**
** FUNCTION......... Collection of platform dependant macros/methods
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
#ifndef _CROSS_PLATFORM_H
#define _CROSS_PLATFORM_H

#ifdef WIN32

// Windows
#define UNSIGNED_EIGHT_BYTE_TYPE unsigned __int64
#define	PATHDELIMINATOR '\\'
typedef HANDLE ThreadID_t;
typedef DWORD TLS_key_t;
#define	GET_THREADID()           GetCurrentThreadId()
#define TLS_SET_VALUE(key,value) (0==TlsSetValue((key),(value)))
#define TLS_GET_VALUE(key)       TlsGetValue((key))
#define TLS_CREATE_KEY(key,dtor) (key = TlsAlloc())
#define GET_SYSTEM_PAGE_SIZE(ps) SYSTEM_INFO lSysInfo; \
	GetSystemInfo(&lSysInfo); \
	ps = lSysInfo.dwPageSize
#define AT_STRCMP strcmpi
#define LOCK_MUTEX(alock)	::EnterCriticalSection((alock))
#define UNLOCK_MUTEX(alock)	::LeaveCriticalSection((alock))

#else

// Unix
#include <pthread.h>

#define UNSIGNED_EIGHT_BYTE_TYPE unsigned long long
#define	PATHDELIMINATOR '/'
typedef pthread_t     ThreadID_t;
typedef pthread_key_t TLS_key_t;
#define	GET_THREADID()	          pthread_self()
#define TLS_SET_VALUE(key,value)  (0!=::pthread_setspecific((key),(value)))
#define TLS_GET_VALUE(key)        pthread_getspecific((key))
#define TLS_CREATE_KEY(key,dtor)  pthread_key_create(&(key),(dtor))
#define GET_SYSTEM_PAGE_SIZE(ps) ps=sysconf(_SC_PAGE_SIZE)
#define AT_STRCMP strcmp
#define LOCK_MUTEX(alock)	::pthread_mutex_lock((alock))
#define UNLOCK_MUTEX(alock)	::pthread_mutex_unlock((alock))

#endif

// guessed page size
#ifdef sun
#define SYS_PAGE_SZ 0x2000ul
#else
#define SYS_PAGE_SZ 0x1000ul
#endif

#endif // _CROSS_PLATFORM_H
