/*
 * heap_mscrt.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 *  Ref: https://systemroot.gitee.io/pages/apiexplorer/d4/d8/heap_8h-source.html
 */
#ifndef HEAP_MSCRT_H
#define HEAP_MSCRT_H

#include "heap.h"

/////////////////////////////////////////////////////
// Allocator heap data structures
/////////////////////////////////////////////////////

/************************************************************************
**  Undocumented kernel/heap data structures
**  BEAWARE they may be changed from version to version
************************************************************************/
typedef PVOID* PPVOID;

/************************************************************************
**  PEB
************************************************************************/
typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;		// +0x000 UChar
  BOOLEAN                 ReadImageFileExecOptions;		// +0x001 UChar
  BOOLEAN                 BeingDebugged;				// +0x002 UChar
  BOOLEAN                 BitField;						// +0x003 UChar
  /*
  unsigned int            ImageUsesLargePages:1;		// win 2008
  unsigned int            IsProtectedProcess:1;			// win 2008
  unsigned int            IsLegacyProcess:1;			// win 2008
  unsigned int            IsImageDynamicallyRelocated:1;	// win 2008
  unsigned int            SkipPatchingUser32Forwarders:1;	// win 2008
  unsigned int            SpareBits:3;
  */
  HANDLE                  Mutant;						// +0x008 Ptr64
  PVOID                   ImageBaseAddress;				// +0x010 Ptr64
  PVOID                   LoaderData;					// +0x018 Ptr64
  PVOID                   ProcessParameters;			// +0x020 Ptr64
  PVOID                   SubSystemData;				// +0x028 Ptr64
  PVOID                   ProcessHeap;					// +0x030 Ptr64
  PVOID                   FastPebLock;					// +0x038 Ptr64
  PVOID                   AtlThunkSListPtr;				// +0x040 Ptr64
  PVOID                   SparePtr2;					// +0x048 Ptr64
  /*
  PVOID                   IFEOKey;		// win 2008
  */
  ULONG                   EnvironmentUpdateCount;		// +0x050 Uint4B
  /*
  unsigned int            CrossProcessFlags;	// win 2008
  unsigned int            ProcessInJob:1;
  unsigned int            ProcessInitializing:1;
  unsigned int            ProcessUsingVEH:1;
  unsigned int            ProcessUsingVCH:1;
  unsigned int            ProcessUsingFTH:1;
  unsigned int            ReservedBits0:27;
  */
  PPVOID                  KernelCallbackTable;			// +0x058 Ptr64
  ULONG                   SystemReserved;				// +0x060 Uint4B
  ULONG                   SpareUlong;					// +0x064 Uint4B
  PVOID                   FreeList;						// +0x068 Ptr64
  /*
  ULONG                   AtlThunkSListPtr32;	// win 2008
  PVOID                   ApiSetMap;			// win 2008
  */
  ULONG                   TlsExpansionCounter;			// +0x070 Uint4B
  PVOID                   TlsBitmap;					// +0x078 Ptr64
  ULONG                   TlsBitmapBits[0x2];			// +0x080 [2] Uint4B
  PVOID                   ReadOnlySharedMemoryBase;		// +0x088 Ptr64
  PVOID                   ReadOnlySharedMemoryHeap;		// +0x090 Ptr64
  /*
  PVOID                   HotpatchInformation;	// win 2008
   */
  PPVOID                  ReadOnlyStaticServerData;		// +0x098 Ptr64
  PVOID                   AnsiCodePageData;				// +0x0a0 Ptr64
  PVOID                   OemCodePageData;				// +0x0a8 Ptr64
  PVOID                   UnicodeCaseTableData;			// +0x0b0 Ptr64
  ULONG                   NumberOfProcessors;			// +0x0b8 Uint4B
  ULONG                   NtGlobalFlag;					// +0x0bc Uint4B
  LARGE_INTEGER           CriticalSectionTimeout;		// +0x0c0 _LARGE_INTEGER
  size_t                  HeapSegmentReserve;			// +0x0c8 Uint8B
  size_t                  HeapSegmentCommit;			// +0x0d0 Uint8B
  size_t                  HeapDeCommitTotalFreeThreshold;	// +0x0d8 Uint8B
  size_t                  HeapDeCommitFreeBlockThreshold;	// +0x0e0 Uint8B
  ULONG                   NumberOfHeaps;				// +0x0e8 Uint4B
  ULONG                   MaximumNumberOfHeaps;			// +0x0ec Uint4B
  PPVOID                  *ProcessHeaps;				// +0x0f0 Ptr64
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  BYTE                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;

} PEB, *PPEB;

/************************************************************************
** Every block is preceded with a _HEAP_ENTRY structure
************************************************************************/
typedef struct _HEAP_ENTRY
{
	PVOID PreviousBlockPrivateData;		// +0x000 Ptr64
	WORD Size;							// +0x008 Uint2B
	UCHAR Flags;						// +0x00a UChar
	UCHAR SmallTagIndex;				// +0x00b UChar
	WORD PreviousSize;					// +0x00c Uint2B
	union								// +0x00e UChar
	{
		UCHAR SegmentOffset;
		UCHAR LFHFlags;
	};
	UCHAR UnusedBytes;					// +0x00f UChar
} HEAP_ENTRY, *PHEAP_ENTRY;

#define HEAP_ENTRY_BUSY 0x01
#define HEAP_ENTRY_EXTRA_PRESENT 0x02
#define HEAP_ENTRY_FILL_PATTERN  0x04
#define HEAP_ENTRY_VIRTUAL_ALLOC 0x08
#define HEAP_ENTRY_LAST_ENTRY    0x10

/************************************************************************
** These are win 2008 only
************************************************************************/
typedef struct _HEAP_COUNTERS
{
	size_t TotalMemoryReserved;
	size_t TotalMemoryCommitted;
	size_t TotalMemoryLargeUCR;
	size_t TotalSizeInVirtualBlocks;
	ULONG TotalSegments;
	ULONG TotalUCRs;
	ULONG CommittOps;
	ULONG DeCommitOps;
	ULONG LockAcquires;
	ULONG LockCollisions;
	ULONG CommitRate;
	ULONG DecommittRate;
	ULONG CommitFailures;
	ULONG InBlockCommitFailures;
	ULONG CompactHeapCalls;
	ULONG CompactedUCRs;
	ULONG AllocAndFreeOps;
	ULONG InBlockDeccommits;
	size_t InBlockDeccomitSize;
	size_t HighWatermarkSize;
	size_t LastPolledSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

typedef struct _HEAP_TUNING_PARAMETERS
{
	ULONG CommittThresholdShift;
	size_t MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;

typedef struct _RTL_HEAP_MEMORY_LIMIT_DATA {
	size_t CommitLimitBytes;
	size_t CommitLimitFailureCode;
	size_t MaxAllocationSizeBytes;
	size_t AllocationLimitFailureCode;
} _RTL_HEAP_MEMORY_LIMIT_DATA;

/************************************************************************
**  PEB::ProcessHeaps points to an array of pointer to _HEAP structure
************************************************************************/
typedef struct _HEAP
{
     HEAP_ENTRY Entry;						// +0x000
     ULONG SegmentSignature;				// +0x010 Uint4B
     ULONG SegmentFlags;					// +0x014 Uint4B
     LIST_ENTRY SegmentListEntry;			// +0x018
     _HEAP* Heap;							// +0x028 Ptr64
     PVOID BaseAddress;						// +0x030 Ptr64
     ULONG NumberOfPages;					// +0x038 Uint4B
     _HEAP_ENTRY* FirstEntry;				// +0x040 Ptr64
     _HEAP_ENTRY* LastValidEntry;			// +0x048 Ptr64
     ULONG NumberOfUnCommittedPages;		// +0x050 Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x054 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x058 Uint2B
     WORD Reserved;							// +0x05a Uint2B
     LIST_ENTRY UCRSegmentList;				// +0x060
	 ULONG Flags;							// +0x070 Uint4B
	 ULONG ForceFlags;						// +0x074 Uint4B
	 ULONG CompatibilityFlags;				// +0x078 Uint4B
	 ULONG EncodeFlagMask;					// +0x07c Uint4B
	 _HEAP_ENTRY Encoding;					// +0x080
	 //size_t PointerKey;					// +0x090 Uint8B
	 ULONG Interceptor;						// +0x090 Uint4B
	 ULONG VirtualMemoryThreshold;			// +0x094 Uint4B
	 ULONG Signature;						// +0x098 Uint4B
	 size_t SegmentReserve;					// +0x0a0 Uint8B
	 size_t SegmentCommit;					// +0x0a8 Uint8B
	 size_t DeCommitFreeBlockThreshold;		// +0x0b0 Uint8B
	 size_t DeCommitTotalFreeThreshold;		// +0x0b8 Uint8B
	 size_t TotalFreeSize;					// +0x0c0 Uint8B
	 size_t MaximumAllocationSize;			// +0x0c8 Uint8B
     WORD ProcessHeapsListIndex;			// +0x0d0 Uint2B
     WORD HeaderValidateLength;				// +0x0d2 Uint2B
     PVOID HeaderValidateCopy;				// +0x0d8 Ptr64
     WORD NextAvailableTagIndex;			// +0x0e0 Uint2B
     WORD MaximumTagIndex;					// +0x0e2 Uint2B
     PVOID /*PHEAP_TAG_ENTRY*/ TagEntries;	// +0x0e8 Ptr64
     LIST_ENTRY UCRList;					// +0x0f0
     size_t AlignRound;						// +0x100 Uint8B
     size_t AlignMask;						// +0x108 Uint8B
     LIST_ENTRY VirtualAllocdBlocks;		// +0x110
     LIST_ENTRY SegmentList;				// +0x120
     WORD AllocatorBackTraceIndex;			// +0x130 Uint2B
     ULONG NonDedicatedListLength;			// +0x134 Uint4B
     PVOID BlocksIndex;						// +0x138 Ptr64
     PVOID UCRIndex;						// +0x140 Ptr64
     PVOID /*PHEAP_PSEUDO_TAG_ENTRY*/ PseudoTagEntries;	// +0x148 Ptr64
     LIST_ENTRY FreeLists;					// +0x150
     PVOID /*PHEAP_LOCK*/ LockVariable;		// +0x160 Ptr64
     LONG * CommitRoutine;					// +0x168 Ptr64
	 PVOID StackTraceInitVar;				// +0x170
	 _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;	// +0x178
     PVOID FrontEndHeap;					// +0x198 Ptr64
     WORD FrontHeapLockCount;				// +0x1a0 Uint2B
     UCHAR FrontEndHeapType;				// +0x1a2 UChar
	 UCHAR RequestedFrontEndHeapType;		// +0x1a3 UChar
	 PVOID FrontEndHeapUsageData;			// +0x1a8
	 WORD FrontEndHeapMaximumIndex;			// +0x1b0
	 UCHAR FrontEndHeapStatusBitmap[129];	// +0x1b2
     HEAP_COUNTERS Counters;				// +0x238
     HEAP_TUNING_PARAMETERS TuningParameters; // +0x2b0
} HEAP, *PHEAP;

typedef struct _HEAP_UNCOMMMTTED_RANGE
{
	struct _HEAP_UNCOMMMTTED_RANGE* next;
	PVOID Address;
	size_t Size;
	ULONG filler;
} HEAP_UNCOMMMTTED_RANGE, *PHEAP_UNCOMMMTTED_RANGE;

typedef struct _HEAP_SEGMENT
{
     HEAP_ENTRY Entry;						// +0x000
     ULONG SegmentSignature;				// +0x010 Uint4B
     ULONG SegmentFlags;					// +0x014 Uint4B
     LIST_ENTRY SegmentListEntry;			// +0x018
     PHEAP Heap;							// +0x028 Ptr64
     PVOID BaseAddress;						// +0x030 Ptr64
     ULONG NumberOfPages;					// +0x038 Uint4B
     PHEAP_ENTRY FirstEntry;				// +0x040 Ptr64
     PHEAP_ENTRY LastValidEntry;			// +0x048 Ptr64
     ULONG NumberOfUnCommittedPages;		// +0x050 Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x054 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x058 Uint2B
     WORD Reserved;							// +0x05a Uint2B
     LIST_ENTRY UCRSegmentList;				// +0x060
} HEAP_SEGMENT, *PHEAP_SEGMENT;

typedef struct _HEAP_UCR_DESCRIPTOR
{
	LIST_ENTRY ListEntry;
	LIST_ENTRY SegmentEntry;
	PVOID Address;
	SIZE_T Size;
} HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR;

/*
 * For diagnostic purpose, blocks are allocated with extra information and
 * stored in a doubly-linked list.  This makes all blocks registered with
 * how big they are, when they were allocated, and what they are used for.
 */

#define nNoMansLandSize 4
typedef struct _CrtMemBlockHeader
{
        struct _CrtMemBlockHeader * pBlockHeaderNext;	//0x00
        struct _CrtMemBlockHeader * pBlockHeaderPrev;	//0x08
        char *                      szFileName;			//0x10
        int                         nLine;				//0x18
#ifdef _WIN64
        /* These items are reversed on Win64 to eliminate gaps in the struct
         * and ensure that sizeof(struct)%16 == 0, so 16-byte alignment is
         * maintained in the debug heap.
         */
        int                         nBlockUse;			//0x1c
        size_t                      nDataSize;			//0x20
#else
        size_t                      nDataSize;
        int                         nBlockUse;
#endif
        long                        lRequest;			//0x28
        unsigned char               gap[nNoMansLandSize];	//0x2c
        /* followed by:
         *  unsigned char           data[nDataSize];
         *  unsigned char           anotherGap[nNoMansLandSize];
         */
} _CrtMemBlockHeader;

typedef struct _HEAP_USERDATA_OFFSETS {
	WORD FirstAllocationOffset;
	WORD BlockStride;
	DWORD StrideAndOffset;
} _HEAP_USERDATA_OFFSETS;

typedef struct _RTL_BITMAP_EX {
	size_t SizeOfBitMap;
	PVOID Buffer;
} _RTL_BITMAP_EX;

typedef struct _HEAP_SUBSEGMENT {
	PVOID LocalInfo;				// +0x000  : Ptr64 _HEAP_LOCAL_SEGMENT_INFO
	PVOID UserBlocks;				// +0x008  : Ptr64 _HEAP_USERDATA_HEADER
	SLIST_HEADER DelayFreeList;		// +0x010  : _SLIST_HEADER
	ULONG AggregateExchg;			// +0x020  : _INTERLOCK_SEQ
	WORD BlockSize;					// +0x024  : Uint2B
	WORD Flags;						// +0x026  : Uint2B
	WORD BlockCount;				// +0x028  : Uint2B
	UCHAR SizeIndex;				// +0x02a  : UChar
	UCHAR AffinityIndex;			// +0x02b  : UChar
	ULONG Alignment[2];				// +0x024  : [2] Uint4B
	ULONG Lock;						// +0x02c  : Uint4B
	SINGLE_LIST_ENTRY SFreeListEntry;	// +0x030  : _SINGLE_LIST_ENTRY
} HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT;

typedef struct _HEAP_USERDATA_HEADER {
	PHEAP_SUBSEGMENT SubSegment;	// +0x00 _HEAP_SUBSEGMENT
	PVOID Reserved;					// +0x08
	UCHAR SizeIndex;				// +0x10
	UCHAR GuardPagePresent;			// +0x11
	WORD PaddingBytes;				// +0x12
	DWORD Signature;				// +0x14
	_HEAP_USERDATA_OFFSETS EncodedOffsets;	// +0x18
	_RTL_BITMAP_EX BusyBitmap;		// +0x20
	PVOID BitmapData[1];			// +0x30
} _HEAP_USERDATA_HEADER;

#endif // HEAP_MSCRT_H
