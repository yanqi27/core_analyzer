/************************************************************************
** FILE NAME..... mmap_file.h
**
** (c) COPYRIGHT
**
** FUNCTION......... mmap a file into process address space.
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
#ifndef _MMAPFILE_H
#define _MMAPFILE_H

#ifdef WIN32
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#endif

#include "cross_platform.h"

// Map a disk file into current process's address space
class MmapFile
{
public:
	// Constructor
	MmapFile(const char* ipFileName, bool ibSync=false)
		: mFileSize(0),	mpOrigin(NULL), mpStartAddr(NULL), mpEndAddr(NULL),
		mpFileName(ipFileName), mbNeedSynch(ibSync)
	{
		// Get system page size, 4K on Win32, 8K on Win64/IA64
		GET_SYSTEM_PAGE_SIZE(mSystemPageSize);
#ifdef WIN32
		mhFile = NULL;
#else
		mFileDescriptor = -1;
#endif
		mInitialized = Open();
	}

	// Destructor
	virtual ~MmapFile()
	{
		Close();
	}

	// The client has read mmaped file up to loaction ipCursor
	// We could shrink the mmaped area to reduce my program's memory footprint
	bool AdjustMmapArea(char* ipCursor)
	{
#ifndef WIN32
		if(ipCursor < mpStartAddr || ipCursor > mpEndAddr)
		{
			::fprintf(stderr, "AdjustMmapArea: Invalid parameters\n");
			::fprintf(stderr, "StartAddr=0x%lx EndAddr=0x%lx CursorAddr=0x%lx\n",
					(long)mpStartAddr, (long)mpEndAddr, (long)ipCursor);
			::abort();
			return false;
		}

		if(ipCursor - (mpStartAddr) >= mSystemPageSize
			&& mpStartAddr + mSystemPageSize < mpEndAddr)
		{
			if(mbNeedSynch)
			{
				if(::msync(mpStartAddr, mSystemPageSize, MS_ASYNC))
				{
					fprintf(stderr, "Failed to msync for file %s\n", mpFileName);
					return false;
				}
			}

			if(::munmap(mpStartAddr, mSystemPageSize) )
			{
				::fprintf(stderr, "AdjustMmapArea: Failed to munmap file\n");
				return false;
			}
			mpStartAddr = mpStartAddr + mSystemPageSize;
		}
#endif
		return true;
	}

	// Open a file and mmap into process virtual address
	bool Open()
	{
		// silently ignores NULL file
		if (!mpFileName)
			return true;

		// file stat
		struct stat lStatBuf;
		if(::stat(mpFileName, &lStatBuf))
		{
			::fprintf(stderr, "Failed to stat file %s, errno=%d\n", mpFileName, errno);
			return false;
		}

		if(lStatBuf.st_size == 0)
		{
			::fprintf(stderr, "File %s is empty, ignored\n", mpFileName);
			return false;
		}
		mFileSize = lStatBuf.st_size;

#ifdef WIN32
		DWORD rc;
		// Open file for mapping
		HANDLE lFileHandle = ::CreateFile(mpFileName,
											GENERIC_READ,
											FILE_SHARE_READ,
											NULL,
											OPEN_EXISTING,
											FILE_ATTRIBUTE_NORMAL,
											NULL);
		if(INVALID_HANDLE_VALUE == lFileHandle)
		{
			rc = ::GetLastError();
			::fprintf(stderr, "Function CreateFile() Failed for %s LastError=%d\r\n", mpFileName, rc);
			return false;
		}
		// Create mapping
		mhFile = ::CreateFileMapping(lFileHandle,
										NULL,
										PAGE_READONLY,
										0,
										0,
										NULL);
		if(mhFile == NULL)
		{
			rc = ::GetLastError();
			::fprintf(stderr, "Function CreateFileMapping() failed for %s LastError=%d\r\n", mpFileName, rc);
			return false;
		}
		// Get the memory address of mapping
		mpStartAddr = (char*) ::MapViewOfFile(mhFile,
												FILE_MAP_READ,
												0,
												0,
												0);
		if(mpStartAddr == NULL)
		{
			rc = ::GetLastError();
			::fprintf(stderr, "Function MapViewOfFile() failed for %s LastError=%d\r\n", mpFileName, rc);
			return false;
		}
#else
		// Open file
		mFileDescriptor = ::open(mpFileName, O_RDONLY);
		if(mFileDescriptor == -1)
		{
			::fprintf(stderr, "Failed to open file %s\n", mpFileName);
			return false;
		}
		// Mmap the file
		// It appears I have to use MAP_SHARED to be able to msync. ?
		mpStartAddr = (char*)
			::mmap(0, mFileSize, PROT_READ, MAP_PRIVATE, mFileDescriptor, 0);
		if(mpStartAddr == MAP_FAILED)
		{
			::fprintf(stderr, "Failed to mmap file %s\n", mpFileName);
			return false;
		}
#endif
		mpEndAddr = mpStartAddr + mFileSize;
		mpOrigin = mpStartAddr;

		return true;
	}

	// Done with the file
	bool Close()
	{
		// silently ignores NULL file
		if (!mpFileName)
			return true;

		if(!mInitialized)
		{
			return false;
		}

#ifdef WIN32
		if(mhFile)
		{
			::CloseHandle(mhFile);
		}
#else
		if(mbNeedSynch)
		{
			if(::msync(mpStartAddr, mpEndAddr - mpStartAddr, MS_ASYNC))
			{
				fprintf(stderr, "Failed to msync for file %s\n", mpFileName);
				return false;
			}
		}

		if(mpEndAddr > mpStartAddr && ::munmap(mpStartAddr, mpEndAddr - mpStartAddr) )
		{
			::fprintf(stderr, "Failed to munmap file %s\n", mpFileName);
			return false;
		}
		mpOrigin = mpStartAddr = mpEndAddr = NULL;

		if(::close(mFileDescriptor))
		{
			::fprintf(stderr, "Failed to close file %s\n", mpFileName);
			return false;
		}
		mFileDescriptor = -1;
#endif
		mpFileName      = NULL;

		return true;
	}

	// Query methods
	char* GetStartAddr() { return mpStartAddr; }

	char* GetEndAddr()   { return mpEndAddr;   }

	size_t GetFileSize() { return mFileSize; }

	bool AddrWithinMmapFile(char* ipAddr)
	{
		return (ipAddr>=mpOrigin && ipAddr<mpEndAddr);
	}

	const char* GetFileName() { return mpFileName; }

	bool InitSucceed() { return mInitialized; }

private:
	// A weak pointer
	const char* mpFileName;
#ifdef WIN32
	HANDLE mhFile;
#else
	int    mFileDescriptor;
#endif
	size_t mSystemPageSize;
	size_t mFileSize;
	char*  mpOrigin;
	char*  mpStartAddr;
	char*  mpEndAddr;
	bool   mbNeedSynch;
	bool   mInitialized;
};

// Specialized mmap file w/ thread id
class MmapPerThreadLogFile : public MmapFile
{
public:
	MmapPerThreadLogFile(long iTID, unsigned int iMappedTID, const char* ipFileName, bool ibSync=false)
		: MmapFile(ipFileName, ibSync), mThreadID(iTID), mMappedTID(iMappedTID)
	{
	}

	virtual ~MmapPerThreadLogFile() {}

	unsigned int GetMappedTID() { return mMappedTID; }

private:
	long   mThreadID;
	 // Map above irregular tid (ulong) to sequential tid(uint)
	unsigned int mMappedTID;
};

#endif // _MMAPFILE_H
