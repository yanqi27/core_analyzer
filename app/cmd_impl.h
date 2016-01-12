/************************************************************************
** FILE NAME..... cmd_impl.h
**
** (c) COPYRIGHT
**
** FUNCTION......... Functions to Implement Plug-in Commands
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
#ifndef _CMD_IMPL_H
#define _CMD_IMPL_H

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <list>
#include "mmap_file.h"
#include "segment.h"
#include "ref.h"

/////////////////////////////////////////////////////////
// Global vars
/////////////////////////////////////////////////////////
extern const char* gpInputExecName;
extern bool gbBatchMode;
extern bool gbVerbose;

/////////////////////////////////////////////////////////
// Return false ONLY if there is irreparable error.
/////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////
// Basic stuff
/////////////////////////////////////////////////////////

// For the least, the file we are dealing with is indeed a core file
extern bool VerifyCoreFile(char* ipFileStart);
extern bool VerifyExecFile(char* ipFileStart);

// Sanity check, retrieve basic information and cache them
extern bool InitCoreAnalyzer(MmapFile& irExec, MmapFile& irCore);

// Memory manager initializer
extern bool InitMemMgr(char* ipCoreFileAddr);

// The reason core was generated, misc process/threads info
extern bool PrintCoreInfo(MmapFile& irCore);

// A thread stack is messed up, take a guess
extern bool UnwindThreadCallstack(char* ipCoreStart, unsigned long tid, const char* ipLibPath);

// Anything that looks like a string(ascii/unicode)
extern bool FindString(char* ipCoreStart, address_t start, address_t end);

// Anything that points to a heap object
extern bool FindHeapRefs(char* ipCoreStart, address_t start, address_t end);

// Analyze the memory content within a given address range
extern bool PrintMemoryPattern(char* ipCoreStart, address_t start, address_t end);

#endif // _CMD_IMPL_H
