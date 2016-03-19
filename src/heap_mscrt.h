/*
 * heap_mscrt.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
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
**  PEB in Window XP/2003 and VISTA/2008 are mostly the same,
**  up to data member SystemReserved(+0x60)
************************************************************************/
typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;		// +0x000 UChar
  BOOLEAN                 ReadImageFileExecOptions;		// +0x001 UChar
  BOOLEAN                 BeingDebugged;				// +0x002 UChar
  BOOLEAN                 BitField;						// +0x003 UChar
  /*
  unsigned int            ImageUsesLargePages:1;		// win 2003/2008
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
  PVOID                   SparePtr2;					// +0x048 Ptr64		win 2003
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
  ULONG                   SpareUlong;					// +0x064 Uint4B	win 2003
  PVOID                   FreeList;						// +0x068 Ptr64		win 2003
  /*
  ULONG                   AtlThunkSListPtr32;	// win 2008
  PVOID                   ApiSetMap;			// win 2008
  */
  ULONG                   TlsExpansionCounter;			// +0x070 Uint4B
  PVOID                   TlsBitmap;					// +0x078 Ptr64
  ULONG                   TlsBitmapBits[0x2];			// +0x080 [2] Uint4B
  PVOID                   ReadOnlySharedMemoryBase;		// +0x088 Ptr64
  PVOID                   ReadOnlySharedMemoryHeap;		// +0x090 Ptr64		win 2003
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
typedef struct _HEAP_ENTRY_2003
{
	PVOID PreviousBlockPrivateData;		// +0x000 Ptr64
	WORD Size;							// +0x008 Uint2B
	WORD PreviousSize;					// +0x00a Uint2B
	UCHAR SmallTagIndex;				// +0x00c UChar
	UCHAR Flags;						// +0x00d UChar
	UCHAR UnusedBytes;					// +0x00e UChar
	UCHAR SegmentIndex;					// +0x00f UChar
} HEAP_ENTRY_2003, *PHEAP_ENTRY_2003;

typedef struct _HEAP_ENTRY_2008
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
} HEAP_ENTRY_2008, *PHEAP_ENTRY_2008;

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

/************************************************************************
**  PEB::ProcessHeaps points to an array of pointer to _HEAP structure
************************************************************************/
typedef struct _HEAP_2003
{
     HEAP_ENTRY_2003 Entry;					// +0x000
     ULONG SegmentSignature;			// +0x010 Uint4B
     ULONG SegmentFlags;				// +0x014 Uint4B
	 ULONG ForceFlags;					// +0x018 Uint4B
	 ULONG VirtualMemoryThreshold;		// +0x01c Uint4B
	 size_t SegmentReserve;				// +0x020 Uint8B
	 size_t SegmentCommit;				// +0x028 Uint8B
	 size_t DeCommitFreeBlockThreshold;
	 size_t DeCommitTotalFreeThreshold;
	 size_t TotalFreeSize;
	 size_t MaximumAllocationSize;
     WORD ProcessHeapsListIndex;
     WORD HeaderValidateLength;
     PVOID HeaderValidateCopy;
     WORD NextAvailableTagIndex;
     WORD MaximumTagIndex;
     PVOID /*PHEAP_TAG_ENTRY*/ TagEntries;
	 PVOID /*PHEAP_UCR_SEGMENT*/ UCRSegments;
	 PVOID /*PHEAP_UNCOMMMTTED_RANGE*/ UnusedUnCommittedRanges;
     size_t AlignRound;
     size_t AlignMask;
     LIST_ENTRY VirtualAllocdBlocks;
	 PVOID /*PHEAP_SEGMENT*/ Segments[64];
	 PVOID u;
	 WORD  u2;
	 WORD  AllocatorBackTraceIndex;
     ULONG NonDedicatedListLength;
     PVOID LargeBlocksIndex;
     PVOID /*PHEAP_PSEUDO_TAG_ENTRY*/ PseudoTagEntries;
     LIST_ENTRY FreeLists;
     PVOID /*PHEAP_LOCK*/ LockVariable;
     LONG * CommitRoutine;
     PVOID FrontEndHeap;
     WORD FrontHeapLockCount;
     UCHAR FrontEndHeapType;
	 UCHAR LastSegmentIndex;
} HEAP_2003, *PHEAP_2003;

typedef struct _HEAP_2008
{
     HEAP_ENTRY_2008 Entry;					// +0x000
     ULONG SegmentSignature;				// +0x010 Uint4B
     ULONG SegmentFlags;					// +0x014 Uint4B
     LIST_ENTRY SegmentListEntry;			// +0x018
     _HEAP_2008* Heap;						// +0x028 Ptr64
     PVOID BaseAddress;						// +0x030 Ptr64
     ULONG NumberOfPages;					// +0x038 Uint4B
     _HEAP_ENTRY_2008* FirstEntry;			// +0x040 Ptr64
     _HEAP_ENTRY_2008* LastValidEntry;		// +0x048 Ptr64
     ULONG NumberOfUnCommittedPages;		// +0x050 Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x054 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x058 Uint2B
     WORD Reserved;							// +0x05a Uint2B
     LIST_ENTRY UCRSegmentList;				// +0x060
	 ULONG Flags;							// +0x070 Uint4B
	 ULONG ForceFlags;						// +0x074 Uint4B
	 ULONG CompatibilityFlags;				// +0x078 Uint4B
	 ULONG EncodeFlagMask;					// +0x07c Uint4B
	 _HEAP_ENTRY_2008 Encoding;				// +0x080
	 size_t PointerKey;						// +0x090 Uint8B
	 ULONG Interceptor;						// +0x098 Uint4B
	 ULONG VirtualMemoryThreshold;			// +0x09c Uint4B
	 ULONG Signature;						// +0x0a0 Uint4B
	 size_t SegmentReserve;					// +0x0a8 Uint8B
	 size_t SegmentCommit;					// +0x0b0 Uint8B
	 size_t DeCommitFreeBlockThreshold;		// +0x0b8 Uint8B
	 size_t DeCommitTotalFreeThreshold;		// +0x0c0 Uint8B
	 size_t TotalFreeSize;					// +0x0c8 Uint8B
	 size_t MaximumAllocationSize;			// +0x0d0 Uint8B
     WORD ProcessHeapsListIndex;			// +0x0d8 Uint2B
     WORD HeaderValidateLength;				// +0x0da Uint2B
     PVOID HeaderValidateCopy;				// +0x0e0 Ptr64
     WORD NextAvailableTagIndex;			// +0x0e8 Uint2B
     WORD MaximumTagIndex;					// +0x0ea Uint2B
     PVOID /*PHEAP_TAG_ENTRY*/ TagEntries;	// +0x0f0 Ptr64
     LIST_ENTRY UCRList;					// +0x0f8
     size_t AlignRound;						// +0x108 Uint8B
     size_t AlignMask;						// +0x110 Uint8B
     LIST_ENTRY VirtualAllocdBlocks;		// +0x118
     LIST_ENTRY SegmentList;				// +0x128
     WORD AllocatorBackTraceIndex;			// +0x138 Uint2B
     ULONG NonDedicatedListLength;			// +0x13c Uint4B
     PVOID BlocksIndex;						// +0x140 Ptr64
     PVOID UCRIndex;						// +0x148 Ptr64
     PVOID /*PHEAP_PSEUDO_TAG_ENTRY*/ PseudoTagEntries;	// +0x150 Ptr64
     LIST_ENTRY FreeLists;					// +0x158
     PVOID /*PHEAP_LOCK*/ LockVariable;		// +0x168 Ptr64
     LONG * CommitRoutine;					// +0x170 Ptr64
     PVOID FrontEndHeap;					// +0x178 Ptr64
     WORD FrontHeapLockCount;				// +0x180 Uint2B
     UCHAR FrontEndHeapType;				// +0x182 UChar
     HEAP_COUNTERS Counters;				// +0x188
     HEAP_TUNING_PARAMETERS TuningParameters; // +0x1f8
} HEAP_2008, *PHEAP_2008;

typedef struct _HEAP_UNCOMMMTTED_RANGE
{
	struct _HEAP_UNCOMMMTTED_RANGE* next;
	PVOID Address;
	size_t Size;
	ULONG filler;
} HEAP_UNCOMMMTTED_RANGE, *PHEAP_UNCOMMMTTED_RANGE;

typedef struct _HEAP_SEGMENT_2003
{
     HEAP_ENTRY_2003 Entry;
     ULONG Signature;
     ULONG Flags;
     PHEAP_2003 Heap;
	 size_t LargestUnCommittedRange;
     PVOID BaseAddress;
     ULONG NumberOfPages;
     PHEAP_ENTRY_2003 FirstEntry;
     PHEAP_ENTRY_2003 LastValidEntry;
     ULONG NumberOfUnCommittedPages;
     ULONG NumberOfUnCommittedRanges;
	 PHEAP_UNCOMMMTTED_RANGE UnCommittedRanges;
     WORD AllocatorBackTraceIndex;
     WORD Reserved;
     PHEAP_ENTRY_2003 LastEntryInSegment;
} HEAP_SEGMENT_2003, *PHEAP_SEGMENT_2003;

typedef struct _HEAP_SEGMENT_2008
{
     HEAP_ENTRY_2008 Entry;					// +0x000
     ULONG SegmentSignature;				// +0x010 Uint4B
     ULONG SegmentFlags;					// +0x014 Uint4B
     LIST_ENTRY SegmentListEntry;			// +0x018
     PHEAP_2008 Heap;						// +0x028 Ptr64
     PVOID BaseAddress;						// +0x030 Ptr64
     ULONG NumberOfPages;					// +0x038 Uint4B
     PHEAP_ENTRY_2008 FirstEntry;			// +0x040 Ptr64
     PHEAP_ENTRY_2008 LastValidEntry;		// +0x048 Ptr64
     ULONG NumberOfUnCommittedPages;		// +0x050 Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x054 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x058 Uint2B
     WORD Reserved;							// +0x05a Uint2B
     LIST_ENTRY UCRSegmentList;				// +0x060
} HEAP_SEGMENT_2008, *PHEAP_SEGMENT_2008;

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
        struct _CrtMemBlockHeader * pBlockHeaderNext;
        struct _CrtMemBlockHeader * pBlockHeaderPrev;
        char *                      szFileName;
        int                         nLine;
#ifdef _WIN64
        /* These items are reversed on Win64 to eliminate gaps in the struct
         * and ensure that sizeof(struct)%16 == 0, so 16-byte alignment is
         * maintained in the debug heap.
         */
        int                         nBlockUse;
        size_t                      nDataSize;
#else
        size_t                      nDataSize;
        int                         nBlockUse;
#endif
        long                        lRequest;
        unsigned char               gap[nNoMansLandSize];
        /* followed by:
         *  unsigned char           data[nDataSize];
         *  unsigned char           anotherGap[nNoMansLandSize];
         */
} _CrtMemBlockHeader;

/*=======================================================================
** 32 bit
*======================================================================*/

/************************************************************************
**  PEB
************************************************************************/
typedef struct _PEB_32 {
  BOOLEAN                 InheritedAddressSpace;		// +0x000 UChar
  BOOLEAN                 ReadImageFileExecOptions;		// +0x001 UChar
  BOOLEAN                 BeingDebugged;				// +0x002 UChar
  BOOLEAN                 BitField;						// +0x003 UChar
  /*
  unsigned int            ImageUsesLargePages:1;		// win 2003/2008
  unsigned int            IsProtectedProcess:1;			// win 2008
  unsigned int            IsLegacyProcess:1;			// win 2008
  unsigned int            IsImageDynamicallyRelocated:1;	// win 2008
  unsigned int            SkipPatchingUser32Forwarders:1;	// win 2008
  unsigned int            SpareBits:3;
  */
  ptr_t_32                Mutant;						// +0x004 Ptr32
  ptr_t_32                ImageBaseAddress;				// +0x008 Ptr32
  ptr_t_32                LoaderData;					// +0x00c Ptr32
  ptr_t_32                ProcessParameters;			// +0x010 Ptr32
  ptr_t_32                SubSystemData;				// +0x014 Ptr32
  ptr_t_32                ProcessHeap;					// +0x018 Ptr32
  ptr_t_32                FastPebLock;					// +0x001c Ptr32
  ptr_t_32                AtlThunkSListPtr;				// +0x020 Ptr32
  ptr_t_32                SparePtr2;					// +0x024 Ptr32		win 2003
  /*
  ptr_t_32                IFEOKey;		// win 2008
  */
  ULONG                   EnvironmentUpdateCount;		// +0x028 Uint4B
  /*
  unsigned int            CrossProcessFlags;	// win 2008
  unsigned int            ProcessInJob:1;
  unsigned int            ProcessInitializing:1;
  unsigned int            ProcessUsingVEH:1;
  unsigned int            ProcessUsingVCH:1;
  unsigned int            ProcessUsingFTH:1;
  unsigned int            ReservedBits0:27;
  */
  ptr_t_32                KernelCallbackTable;			// +0x02c Ptr32
  ULONG                   SystemReserved;				// +0x030 Uint4B
  ULONG                   SpareUlong;					// +0x034 Uint4B	win 2003
  ptr_t_32                FreeList;						// +0x038 Ptr32		win 2003
  /*
  ULONG                   AtlThunkSListPtr32;	// win 2008
  ptr_t_32                ApiSetMap;			// win 2008
  */
  ULONG                   TlsExpansionCounter;			// +0x03c Uint4B
  ptr_t_32                TlsBitmap;					// +0x040 Ptr32
  ULONG                   TlsBitmapBits[0x2];			// +0x044 [2] Uint4B
  ptr_t_32                ReadOnlySharedMemoryBase;		// +0x04c Ptr32
  ptr_t_32                ReadOnlySharedMemoryHeap;		// +0x050 Ptr32		win 2003
  /*
  ptr_t_32                HotpatchInformation;	// win 2008
   */
  ptr_t_32                ReadOnlyStaticServerData;		// +0x054 Ptr32
  ptr_t_32                AnsiCodePageData;				// +0x058 Ptr32
  ptr_t_32                OemCodePageData;				// +0x05c Ptr32
  ptr_t_32                UnicodeCaseTableData;			// +0x060 Ptr32
  ULONG                   NumberOfProcessors;			// +0x064 Uint4B
  ULONG                   NtGlobalFlag;					// +0x068 Uint4B
  LARGE_INTEGER           CriticalSectionTimeout;		// +0x070 _LARGE_INTEGER
  ULONG                   HeapSegmentReserve;			// +0x078 Uint4B
  ULONG                   HeapSegmentCommit;			// +0x07c Uint4B
  ULONG                   HeapDeCommitTotalFreeThreshold;	// +0x080 Uint4B
  ULONG                   HeapDeCommitFreeBlockThreshold;	// +0x084 Uint4B
  ULONG                   NumberOfHeaps;				// +0x088 Uint4B
  ULONG                   MaximumNumberOfHeaps;			// +0x08c Uint4B
  ptr_t_32                ProcessHeaps;					// +0x090 Ptr32
  // ...
} PEB_32, *PPEB_32;

/************************************************************************
** Every block is preceded with a _HEAP_ENTRY structure
************************************************************************/
typedef struct _HEAP_ENTRY_2008_32
{
	WORD Size;							// +0x000 Uint2B
	UCHAR Flags;						// +0x002 UChar
	UCHAR SmallTagIndex;				// +0x003 UChar
	//Ptr32 Void SubSegmentCode;		// +0x00
	WORD PreviousSize;					// +0x004 Uint2B
	union
	{
		UCHAR SegmentOffset;				// +0x005 UChar
		UCHAR LFHFlags;						// +0x006 UChar
	};
	UCHAR UnusedBytes;					// +0x007 UChar
} HEAP_ENTRY_2008_32, *PHEAP_ENTRY_2008_32;

/************************************************************************
** These are win 2008 only
************************************************************************/
typedef struct _HEAP_COUNTERS_32
{
	ULONG TotalMemoryReserved;			// 0x000
	ULONG TotalMemoryCommitted;			// 0x004
	ULONG TotalMemoryLargeUCR;			// 0x008
	ULONG TotalSizeInVirtualBlocks;		// 0x00c
	ULONG TotalSegments;				// 0x010
	ULONG TotalUCRs;					// 0x014
	ULONG CommittOps;					// 0x018
	ULONG DeCommitOps;					// 0x01c
	ULONG LockAcquires;					// 0x020
	ULONG LockCollisions;				// 0x024
	ULONG CommitRate;					// 0x028
	ULONG DecommittRate;				// 0x02c
	ULONG CommitFailures;				// 0x030
	ULONG InBlockCommitFailures;		// 0x034
	ULONG CompactHeapCalls;				// 0x038
	ULONG CompactedUCRs;				// 0x03c
	ULONG AllocAndFreeOps;				// 0x040
	ULONG InBlockDeccommits;			// 0x044
	ULONG InBlockDeccomitSize;			// 0x048
	ULONG HighWatermarkSize;			// 0x04c
	ULONG LastPolledSize;				// 0x050
} HEAP_COUNTERS_32, *PHEAP_COUNTERS_32;

typedef struct _HEAP_TUNING_PARAMETERS_32
{
	ULONG CommittThresholdShift;
	ULONG MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS_32, *PHEAP_TUNING_PARAMETERS_32;

typedef struct _LIST_ENTRY_32
{
	ptr_t_32 Flink;
	ptr_t_32 Blink;
} LIST_ENTRY_32;

/************************************************************************
**  PEB::ProcessHeaps points to an array of pointer to _HEAP structure
************************************************************************/
typedef struct _HEAP_2008_32
{
     HEAP_ENTRY_2008_32 Entry;				// +0x000
     ULONG SegmentSignature;				// +0x008 Uint4B
     ULONG SegmentFlags;					// +0x00c Uint4B
     LIST_ENTRY_32 SegmentListEntry;			// +0x010
     ptr_t_32 Heap;							// +0x018 Ptr32  _HEAP_2008_32*
     ptr_t_32 BaseAddress;					// +0x01c Ptr32
     ULONG NumberOfPages;					// +0x020 Uint4B
     ptr_t_32 FirstEntry;					// +0x024 Ptr32  _HEAP_ENTRY_2008_32*
     ptr_t_32 LastValidEntry;				// +0x028 Ptr32  _HEAP_ENTRY_2008_32*
     ULONG NumberOfUnCommittedPages;		// +0x02c Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x030 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x034 Uint2B
     WORD Reserved;							// +0x036 Uint2B
     LIST_ENTRY_32 UCRSegmentList;				// +0x038
	 ULONG Flags;							// +0x040 Uint4B
	 ULONG ForceFlags;						// +0x044 Uint4B
	 ULONG CompatibilityFlags;				// +0x048 Uint4B
	 ULONG EncodeFlagMask;					// +0x04c Uint4B
	 _HEAP_ENTRY_2008_32 Encoding;			// +0x050
	 ULONG PointerKey;						// +0x058 Uint8B
	 ULONG Interceptor;						// +0x05c Uint4B
	 ULONG VirtualMemoryThreshold;			// +0x060 Uint4B
	 ULONG Signature;						// +0x064 Uint4B
	 ULONG SegmentReserve;					// +0x068 Uint8B
	 ULONG SegmentCommit;					// +0x06c Uint8B
	 ULONG DeCommitFreeBlockThreshold;		// +0x070 Uint8B
	 ULONG DeCommitTotalFreeThreshold;		// +0x074 Uint8B
	 ULONG TotalFreeSize;					// +0x078 Uint8B
	 ULONG MaximumAllocationSize;			// +0x07c Uint8B
     WORD ProcessHeapsListIndex;			// +0x080 Uint2B
     WORD HeaderValidateLength;				// +0x082 Uint2B
     ptr_t_32 HeaderValidateCopy;				// +0x084 Ptr32
     WORD NextAvailableTagIndex;			// +0x088 Uint2B
     WORD MaximumTagIndex;					// +0x08a Uint2B
     ptr_t_32 /*PHEAP_TAG_ENTRY*/ TagEntries;	// +0x08c Ptr32
     LIST_ENTRY_32 UCRList;					// +0x090
     ULONG AlignRound;						// +0x098 Uint8B
     ULONG AlignMask;						// +0x09c Uint8B
     LIST_ENTRY_32 VirtualAllocdBlocks;		// +0x0a0
     LIST_ENTRY_32 SegmentList;				// +0x0a8
     WORD AllocatorBackTraceIndex;			// +0x0b0 Uint2B
     ULONG NonDedicatedListLength;			// +0x0b4 Uint4B
     ptr_t_32 BlocksIndex;						// +0x0b8 Ptr32
     ptr_t_32 UCRIndex;						// +0x0bc Ptr32
     ptr_t_32 /*PHEAP_PSEUDO_TAG_ENTRY*/ PseudoTagEntries;	// +0x0c0 Ptr32
     LIST_ENTRY_32 FreeLists;					// +0x0c4
     ptr_t_32 /*PHEAP_LOCK*/ LockVariable;		// +0x0cc Ptr32
     ptr_t_32 CommitRoutine;					// +0x0d0 Ptr32
     ptr_t_32 FrontEndHeap;					// +0x0d4 Ptr32
     WORD FrontHeapLockCount;				// +0x0d8 Uint2B
     UCHAR FrontEndHeapType;				// +0x0da UChar
     HEAP_COUNTERS_32 Counters;				// +0x0dc
     HEAP_TUNING_PARAMETERS_32 TuningParameters; // +0x130
} HEAP_2008_32, *PHEAP_2008_32;

typedef struct _HEAP_UNCOMMMTTED_RANGE_32
{
	ptr_t_32 next;	// struct _HEAP_UNCOMMMTTED_RANGE_32*
	ptr_t_32 Address;
	ULONG Size;
	ULONG filler;
} HEAP_UNCOMMMTTED_RANGE_32, *PHEAP_UNCOMMMTTED_RANGE_32;

typedef struct _HEAP_SEGMENT_2008_32
{
     HEAP_ENTRY_2008_32 Entry;				// +0x000
     ULONG SegmentSignature;				// +0x010 Uint4B
     ULONG SegmentFlags;					// +0x014 Uint4B
     LIST_ENTRY_32 SegmentListEntry;		// +0x018
     ptr_t_32 Heap;							// +0x028 Ptr32  PHEAP_2008_32
     ptr_t_32 BaseAddress;					// +0x030 Ptr32
     ULONG NumberOfPages;					// +0x038 Uint4B
     ptr_t_32 FirstEntry;					// +0x040 Ptr32  PHEAP_ENTRY_2008_32
     ptr_t_32 LastValidEntry;				// +0x048 Ptr32  PHEAP_ENTRY_2008_32
     ULONG NumberOfUnCommittedPages;		// +0x050 Uint4B
     ULONG NumberOfUnCommittedRanges;		// +0x054 Uint4B
     WORD SegmentAllocatorBackTraceIndex;	// +0x058 Uint2B
     WORD Reserved;							// +0x05a Uint2B
     LIST_ENTRY_32 UCRSegmentList;				// +0x060
} HEAP_SEGMENT_2008_32, *PHEAP_SEGMENT_2008_32;

typedef struct _HEAP_UCR_DESCRIPTOR_32
{
	LIST_ENTRY_32 ListEntry;
	LIST_ENTRY_32 SegmentEntry;
	ptr_t_32      Address;		// PHEAP_ENTRY_2008_32
	ULONG Size;
} HEAP_UCR_DESCRIPTOR_32, *PHEAP_UCR_DESCRIPTOR_32;

/*
 * For diagnostic purpose, blocks are allocated with extra information and
 * stored in a doubly-linked list.  This makes all blocks registered with
 * how big they are, when they were allocated, and what they are used for.
 */

#define nNoMansLandSize 4
typedef struct _CrtMemBlockHeader_32
{
        ptr_t_32 pBlockHeaderNext;	// struct _CrtMemBlockHeader *
        ptr_t_32 pBlockHeaderPrev;	// struct _CrtMemBlockHeader *
        ptr_t_32 szFileName;		// char *
        int                         nLine;
        ULONG                       nDataSize;
        int                         nBlockUse;
        long                        lRequest;
        unsigned char               gap[nNoMansLandSize];
        /* followed by:
         *  unsigned char           data[nDataSize];
         *  unsigned char           anotherGap[nNoMansLandSize];
         */
} _CrtMemBlockHeader_32;

#endif // HEAP_MSCRT_H
