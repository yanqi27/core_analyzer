/************************************************************************
** FILE NAME..... core_elf_linux_x86_64.cpp
**
** (c) COPYRIGHT
**
** FUNCTION......... core viewer for Linux/x86_64
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
#include <string>
#include "cmd_impl.h"
#include "ca_elf.h"

/////////////////////////////////////////////////////////
// Return false if fail
/////////////////////////////////////////////////////////
bool PrintCoreInfo(MmapFile& irCore)
{
	char* ipCoreFileAddr = irCore.GetStartAddr();
	char* ipCoreEnd   = irCore.GetEndAddr();

	Elf64_Ehdr* elfhdr = (Elf64_Ehdr*)ipCoreFileAddr;
	for(int i=0; i<elfhdr->e_phnum; i++)
	{
		Elf64_Phdr* phdr = (Elf64_Phdr*) (ipCoreFileAddr + elfhdr->e_phoff + i * elfhdr->e_phentsize);
		if (phdr->p_type == PT_NOTE)
		{
			printf("NOTE\n");
			int note_cnt = 0;
			char* lpNextEntry = ipCoreFileAddr + phdr->p_offset;
			while (lpNextEntry - (ipCoreFileAddr + phdr->p_offset) < phdr->p_filesz)
			{
				Elf64_Nhdr* elfnote = (Elf64_Nhdr *)lpNextEntry;
				const char* name = (char*)(elfnote + 1);
				printf ("\t[%d] name: %s", note_cnt, name);
				const char* desc = name + ALIGN_LONG(elfnote->n_namesz);

				// process status is essentially a thread context
				if (elfnote->n_type == NT_PRSTATUS)
				{
					printf(" type: PRSTATUS\n");
					struct elf_prstatus *prstat = (struct elf_prstatus *)desc;

					printf("\t\tpid=%ld signal=%d user_time=%ld.%ldsec sys_time=%ld.%ldsec\n",
						prstat->pr_pid, prstat->pr_cursig, prstat->pr_utime.tv_sec, prstat->pr_utime.tv_usec,
						prstat->pr_stime.tv_sec, prstat->pr_stime.tv_usec);
					printf("\t\t%%rip=0x%lx %%rsp=0x%lx\n",
						prstat->pr_reg[CORE_RIP], prstat->pr_reg[CORE_RSP]);
				}
				// general process info
				else if (elfnote->n_type == NT_PRPSINFO)
				{
					printf(" type: PRPSINFO\n");
					struct elf_prpsinfo *prpsinfo = (struct elf_prpsinfo *)desc;

					printf("\t\tprocess_state=%c\n", prpsinfo->pr_sname);
					printf("\t\tfilename=%s [%s]\n", prpsinfo->pr_fname, prpsinfo->pr_psargs);
				}
				else if (elfnote->n_type == NT_FPREGSET)
				{
					printf(" type: FPREGSET [fpregset struct]\n");
					printf("\t\tfloating point register set\n");
				}
				else if (elfnote->n_type == NT_PRXREG)
				{
					printf(" type: PRXREG [prxregset struct]\n");
				}
				else if (elfnote->n_type == NT_AUXV)
				{
					printf(" type: AUXV\n");
					Elf64_auxv_t* pauxv = (Elf64_auxv_t*)desc;

					while ((char*)pauxv + sizeof(Elf64_auxv_t) < (char*)desc + elfnote->n_descsz)
					{
						printf("\t\ttype=%d\t", pauxv->a_type);
						switch(pauxv->a_type)
						{
						case AT_EXECFD:
							printf("exec_fd=%ld", pauxv->a_un.a_val);
							break;
						case AT_PHDR:
							printf("&phdr[0]=0x%lx", pauxv->a_un.a_val);
							break;
						case AT_PHENT:
							printf("sizeof(phdr[0])=%ld", pauxv->a_un.a_val);
							break;
						case AT_PHNUM:
							printf("#phdr_entries=%ld", pauxv->a_un.a_val);
							break;
						case AT_PAGESZ:
							printf("pagesize=%ld", pauxv->a_un.a_val);
							break;
						case AT_BASE:
							printf("ld.so_base_addr=0x%lx", pauxv->a_un.a_val);
							break;
						case AT_FLAGS:
							printf("proc_flags=0x%lx", pauxv->a_un.a_val);
							break;
						case AT_ENTRY:
							printf("entry_point=0x%lx", pauxv->a_un.a_val);
							break;
						case AT_UID:
							printf("real_uid=%ld", pauxv->a_un.a_val);
							break;
						case AT_EUID:
							printf("effective_uid=%ld", pauxv->a_un.a_val);
							break;
						case AT_GID:
							printf("real_gid=%ld", pauxv->a_un.a_val);
							break;
						case AT_EGID:
							printf("effective_gid=%ld", pauxv->a_un.a_val);
							break;
						case AT_CLKTCK:
							printf("frequency_of_times()=%ld", pauxv->a_un.a_val);
							break;
						case AT_PLATFORM:
							printf("plat_name=0x%lx", pauxv->a_un.a_val);
							break;
						case AT_HWCAP:
							printf("hardware_capability=%ld", pauxv->a_un.a_val);
							break;
						case AT_SECURE:
							printf("was_exec_setuid-like? %s", pauxv->a_un.a_val ? "YES":"NO");
							break;
						default:
							break;
						}
						printf("\n");
						pauxv++;
					}
				}
				else
				{
					printf(" type: %d\n", elfnote->n_type);
				}

				note_cnt++;
				lpNextEntry += sizeof(Elf64_Nhdr) + ALIGN_LONG(elfnote->n_namesz) + ALIGN_LONG(elfnote->n_descsz);
			}
		}
	}
	PrintSegment();
	/*printf("\n");
	printf("No.   type               vaddr       memsz      filesz     perm    name\n");
	printf("=======================================================================\n");

	// all LOAD segments are already collected in a global vector
	for (int i=0; i<g_segments.size(); i++)
	{
		ca_segment* segment = g_segments[i];
		// segment sequence number
		printf("[%2d]  LOAD", i);
		// segment info
		printf("  %#18lx ", segment->m_vaddr);
		printf(" %10ld ", segment->m_vsize);
		printf(" %10ld ", segment->m_fsize);
		// segment permission bits
		char perm[] = "---";
		if (segment->executable())
			perm[2] = 'X';
		if (segment->writable())
			perm[1] = 'W';
		if (segment->readable())
			perm[0] = 'R';
		printf(" %#7s ", perm);

		// What kind of segment is it ?
		if (!segment->readable() && !segment->writable() && !segment->executable() && segment->m_vsize > 0)
		{
			if (segment->m_vsize == 4096)
				printf("  [ thread guard page ]");
			else
				printf("  [      ]");
		}
		else if (segment->m_type == ENUM_STACK)
		{
			// stack segment
			struct elf_prstatus* prstat = (struct elf_prstatus*)segment->m_thread_context;
			printf("  [ stack ]  [pseudo_tid=%d tid=%ld ]", segment->m_pseudo_tid, prstat->pr_pid);
		}
		else if (segment->m_type == ENUM_MODULE_TEXT || segment->m_type == ENUM_MODULE_DATA)
		{
			// module mapping
			const char* module_name = segment->m_module_name;

			if (segment->executable())
				printf("  [ text ]  [ %s ]", module_name);
			else if (segment->writable())
				printf("  [ data ]  [ %s ]", module_name);
			else if (segment->readable())
				printf("  [ rodat]  [ %s ]", module_name);
			else
				printf("  [ dead page ]");
		}
		else if (segment->m_type == ENUM_HEAP)
			printf("  [ heap ]");
		else
			printf("  [ anon ]");

		printf("\n");
	}*/
	return true;
}

bool GetFunctionName(char* opBuf, size_t iBufSz, unsigned long iInstructionOffset, const char* ipModulePath)
{
	*opBuf = '\0';
	std::basic_string<char> cmd("addr2line -e ");
	cmd += ipModulePath;
	cmd += " -f -C ";
	char lAddrBuf[32];
	sprintf(lAddrBuf, "0x%lx", iInstructionOffset);
	cmd += lAddrBuf;
	//printf("[%s]", cmd.c_str());
	FILE *lpFile = popen(cmd.c_str(), "r");
	if (lpFile)
	{
		fgets( opBuf, iBufSz, lpFile );
		// Skip if there is no func info in the binary
		if (opBuf[0] == '?')
		{
			*opBuf = '\0';
		}
		else
		{
			RemoveLineReturn(opBuf);
			//printf("\t%s", RemoveLineReturn(opBuf));
			size_t len = strlen(opBuf);
			// insert delimiters and reserve one for line return
			if (len+1+4 < iBufSz)
			{
				opBuf[len] = ' ';
				opBuf[len+1] = 'a';
				opBuf[len+2] = 't';
				opBuf[len+3] = ' ';
				len += 4;
				fgets(&opBuf[len], iBufSz-len, lpFile );
				RemoveLineReturn(&opBuf[len]);
				//printf("\t%s", RemoveLineReturn(&opBuf[len]));
			}
		}
		pclose(lpFile);
	}
	else
		return false;

	return true;
}
