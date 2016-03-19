/************************************************************************
** FILE NAME.....    ca_elf.h
**
** (c) COPYRIGHT
**
** FUNCTION......... helper routines for elf
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
#ifndef _CA_ELF_H
#define _CA_ELF_H
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#ifdef linux
#include <link.h>
#include <sys/procfs.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/ucontext.h>

#elif defined(sun)
#include <link.h>
#include <sys/frame.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/ucontext.h>
#include <sys/auxv.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/utsname.h>

// use the new data structure which is in 2nd NOTE segment.
#define	_STRUCTURED_PROC	1
#include <sys/procfs.h>

#elif defined(__hpux)
#include <elf_em.h>

#else
#pragma error "unsupported platform"
#endif

#include "util.h"

extern struct link_map* GetLinkMap();

extern unsigned long GetULong(void* ipData);

extern bool GetFunctionName(char* opBuf, size_t iBufSz, unsigned long iInstructionOffset, const char* ipModulePath);

extern const char* RemoveLineReturn(char* ipLineBuf);

#ifdef linux
typedef struct elf_prstatus thread_context;
#define GET_RSP(thrd) ((thrd)->pr_reg[CORE_RSP])
#define TOTAL_REGS    ELF_NGREG

#elif defined(sun)
typedef lwpstatus_t  thread_context;
#define GET_RSP(thrd) (GetULong(&(thrd)->pr_reg[R_O6])+0x7ff)
#define TOTAL_REGS    NPRGREG

#elif defined(__hpux)
// temp place holder
typedef long thread_context;
#define GET_RSP(thrd) 0
struct link_map
{
	unsigned long l_addr;
};

#else
#error "unsupported platform"
#endif

extern const char* gExecName;

#ifdef linux
/************************************************************************
** The following macro is defined in kernel core dumper.
** The left side is the elf_gregset_t in core dump file.
************************************************************************/
/*
#define ELF_CORE_COPY_REGS(pr_reg, regs)  do { \
	unsigned v;						\
	(pr_reg)[0] = (regs)->r15;				\
	(pr_reg)[1] = (regs)->r14;				\
	(pr_reg)[2] = (regs)->r13;				\
	(pr_reg)[3] = (regs)->r12;				\
	(pr_reg)[4] = (regs)->rbp;				\
	(pr_reg)[5] = (regs)->rbx;				\
	(pr_reg)[6] = (regs)->r11;				\
	(pr_reg)[7] = (regs)->r10;				\
	(pr_reg)[8] = (regs)->r9;				\
	(pr_reg)[9] = (regs)->r8;				\
	(pr_reg)[10] = (regs)->rax;				\
	(pr_reg)[11] = (regs)->rcx;				\
	(pr_reg)[12] = (regs)->rdx;				\
	(pr_reg)[13] = (regs)->rsi;				\
	(pr_reg)[14] = (regs)->rdi;				\
	(pr_reg)[15] = (regs)->orig_rax;			\
	(pr_reg)[16] = (regs)->rip;				\
	(pr_reg)[17] = (regs)->cs;				\
	(pr_reg)[18] = (regs)->eflags;				\
	(pr_reg)[19] = (regs)->rsp;				\
	(pr_reg)[20] = (regs)->ss;				\
	(pr_reg)[21] = current->thread.fs;			\
	(pr_reg)[22] = current->thread.gs;			\
	asm("movl %%ds,%0" : "=r" (v)); (pr_reg)[23] = v;	\
	asm("movl %%es,%0" : "=r" (v)); (pr_reg)[24] = v;	\
	asm("movl %%fs,%0" : "=r" (v)); (pr_reg)[25] = v;	\
	asm("movl %%gs,%0" : "=r" (v)); (pr_reg)[26] = v;	\
} while(0);
*/
#define CORE_R15 0
#define CORE_R14 1
#define CORE_R13 2
#define CORE_R12 3
#define CORE_RBP 4
#define CORE_RBX 5
#define CORE_R11 6
#define CORE_R10 7
#define CORE_R9  8
#define CORE_R8  9
#define CORE_RAX 10
#define CORE_RCX 11
#define CORE_RDX 12
#define CORE_RSI 13
#define CORE_RDI 14
#define CORE_ORIG_RAX 15
#define CORE_RIP 16
#define CORE_CS  17
#define CORE_EFLAGS 18
#define CORE_RSP 19
#define CORE_SS  20
#define CORE_THREAD_FS 21
#define CORE_THREAD_GS 22
#endif

#endif // _CA_ELF_H
