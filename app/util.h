/************************************************************************
** FILE NAME..... util.h
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
#ifndef _UTIL_H
#define _UTIL_H

#define MIN_CHARS_OF_STRING 4

// Align number x on multiple of b bytes, b is power of 2
//#define ALIGN(x,b) (((address_t)(x)+((address_t)(b)-1)) & ~((address_t)(b)-1))

//#define ALIGN_FLOOR(x,b) ((x) & ~((address_t)(b)-1))


//#define ALIGN_PTR(p)   ALIGN(p,sizeof(void*))

#define ALIGN_LONG(sz) ALIGN(sz,sizeof(long))

#define ALIGN_FOUR(sz) ((((unsigned int)(sz))+3)&(~3u))

////////////////////////////////////////////////////////////////////
// Helper functions
////////////////////////////////////////////////////////////////////
extern address_t String2ULong(const char* exp);
extern address_t AskParam(const char* message, const char* env_name, CA_BOOL ask);
extern char* AskPath(const char* pathname);
extern const char* GetBaseName(const char* ipPath);
extern bool FileReadable(const char* ipFilePath);
extern const char* RemoveLineReturn(char* ipLineBuf);
extern bool PrintSegment();
extern const char* get_register_name(int tid);

#endif // _UTIL_H
