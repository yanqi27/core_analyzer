/*
 * heap_ptmalloc.h
 *  Ptmalloc (DL allocator) data structure
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef _MM_PTMALLOC_H
#define _MM_PTMALLOC_H

#include <pthread.h>
#include "heap.h"

#ifndef size_t
typedef long unsigned int size_t;
#endif

/************************************************************************
**  Data types used by Ptmalloc
************************************************************************/
#define INTERNAL_SIZE_T size_t
#define SIZE_SZ                (sizeof(INTERNAL_SIZE_T))
#define MALLOC_ALIGNMENT       (2 * SIZE_SZ)
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
};
typedef struct malloc_chunk* mfastbinptr;
typedef struct malloc_chunk* mchunkptr;

#define MIN_CHUNK_SIZE        (sizeof(struct malloc_chunk))
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

#define NONCONTIGUOUS_BIT (2U)
#define contiguous(M)     (((M)->flags &  NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M)  (((M)->flags &  NONCONTIGUOUS_BIT) != 0)

#define NBINS            128
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define PREV_INUSE 0x1
#define prev_inuse(p)       ((p)->size & PREV_INUSE)
#define IS_MMAPPED 0x2
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
#define NON_MAIN_ARENA 0x4
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)
#define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

/************************************************************************
**  GNU C Library version 2.3.4
************************************************************************/
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE_GLIBC_2_3     80
#define fastbin_index_GLIBC_2_3(sz) ((((unsigned int)(sz)) >> 3) - 2)
#define NFASTBINS_GLIBC_2_3  (fastbin_index_GLIBC_2_3(request2size(MAX_FAST_SIZE_GLIBC_2_3))+1)

struct malloc_state_GLIBC_2_3 {
  int mutex; //mutex_t mutex;

  /* The maximum chunk size to be eligible for fastbin */
  INTERNAL_SIZE_T  max_fast;   /* low 2 bits used as flags */

  /* Fastbins */
  mfastbinptr      fastbins[NFASTBINS_GLIBC_2_3];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr        top;

  /* The remainder from the most recent split of a small request */
  mchunkptr        last_remainder;

  /* Normal bins packed as described above */
  mchunkptr        bins[NBINS * 2];

  /* Bitmap of bins */
  unsigned int     binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state_GLIBC_2_3 *next;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

struct malloc_par_GLIBC_2_3 {
  /* Tunable parameters */
  unsigned long    trim_threshold;
  INTERNAL_SIZE_T  top_pad;
  INTERNAL_SIZE_T  mmap_threshold;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;

  /* Cache malloc_getpagesize */
  unsigned int     pagesize;

  /* Statistics */
  INTERNAL_SIZE_T  mmapped_mem;
  INTERNAL_SIZE_T  max_mmapped_mem;
  INTERNAL_SIZE_T  max_total_mem; /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char*            sbrk_base;
};

struct heap_info_GLIBC_2_3 {
  struct malloc_state_GLIBC_2_3* ar_ptr; /* Arena for this heap. */
  struct heap_info_GLIBC_2_3 *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t pad;    /* Make sure the following data is properly aligned. */
};

#define HEAP_MAX_SIZE_GLIBC_2_3 (1024*1024)
/*
#define heap_for_ptr_GLIBC_2_3(ptr) \
   ((struct heap_info_GLIBC_2_3 *)((unsigned long)(ptr) & ~(HEAP_MAX_SIZE_GLIBC_2_3-1)))
*/

/************************************************************************
**  GNU C Library version 2.4
************************************************************************/
struct malloc_state_GLIBC_2_4 {
  int mutex; //mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr      fastbins[NFASTBINS_GLIBC_2_3];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr        top;

  /* The remainder from the most recent split of a small request */
  mchunkptr        last_remainder;

  /* Normal bins packed as described above */
  mchunkptr        bins[NBINS * 2];

  /* Bitmap of bins */
  unsigned int     binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state_GLIBC_2_4 *next;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

#define malloc_par_GLIBC_2_4 malloc_par_GLIBC_2_3
#define heap_info_GLIBC_2_4  heap_info_GLIBC_2_3

#define HEAP_MAX_SIZE_GLIBC_2_4     (1024*1024)
#define MAX_FAST_SIZE_GLIBC_2_4     MAX_FAST_SIZE_GLIBC_2_3

/************************************************************************
**  GNU C Library version 2.5 and later
************************************************************************/
#define MAX_FAST_SIZE_GLIBC_2_5     MAX_FAST_SIZE_GLIBC_2_3
#define fastbin_index_GLIBC_2_5(sz) fastbin_index_GLIBC_2_3(sz)
#define NFASTBINS_GLIBC_2_5         NFASTBINS_GLIBC_2_3

struct malloc_state_GLIBC_2_5 {
  int mutex; //mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr      fastbins[NFASTBINS_GLIBC_2_5];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr        top;

  /* The remainder from the most recent split of a small request */
  mchunkptr        last_remainder;

  /* Normal bins packed as described above */
  mchunkptr        bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int     binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state_GLIBC_2_5 *next;

  /* Linked list for free arenas.  */
  struct malloc_state_GLIBC_2_5 *next_free;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

struct malloc_par_GLIBC_2_5 {
  /* Tunable parameters */
  unsigned long    trim_threshold;
  INTERNAL_SIZE_T  top_pad;
  INTERNAL_SIZE_T  mmap_threshold;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  int              no_dyn_threshold;

  /* Cache malloc_getpagesize */
  unsigned int     pagesize;

  /* Statistics */
  INTERNAL_SIZE_T  mmapped_mem;
  INTERNAL_SIZE_T  max_mmapped_mem;
  INTERNAL_SIZE_T  max_total_mem; /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char*            sbrk_base;
};

struct heap_info_GLIBC_2_5 {
  struct malloc_state_GLIBC_2_5* ar_ptr; /* Arena for this heap. */
  struct heap_info_GLIBC_2_5*    prev; 	/* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size;
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
};

#define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
#define HEAP_MAX_SIZE_GLIBC_2_5 (2 * DEFAULT_MMAP_THRESHOLD_MAX)
/*
#define heap_for_ptr_GLIBC_2_5(ptr) \
 ((struct heap_info_GLIBC_2_5 *)((unsigned long)(ptr) & ~(HEAP_MAX_SIZE_GLIBC_2_5-1)))
*/

// block types
#define PT_MMAP_BLOCK  0x10
#define PT_MAIN_ARENA  0x20
#define PT_DYNAMIC_ARENA 0x30

/************************************************************************
**  GNU C Library version 2.12.2
************************************************************************/
// MAX_FAST_SIZE is 160; NFASTBINS is 10
// global_max_fast is 128 by default
#define MAX_FAST_SIZE_GLIBC_2_12     (80 * SIZE_SZ / 4)
#define fastbin_index_GLIBC_2_12(sz) ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
#define NFASTBINS_GLIBC_2_12         (fastbin_index_GLIBC_2_12(request2size(MAX_FAST_SIZE_GLIBC_2_12))+1)

struct malloc_state_GLIBC_2_12 {
  int mutex; //mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr      fastbins[NFASTBINS_GLIBC_2_12];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr        top;

  /* The remainder from the most recent split of a small request */
  mchunkptr        last_remainder;

  /* Normal bins packed as described above */
  mchunkptr        bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int     binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state_GLIBC_2_12 *next;

  /* Linked list for free arenas.  */
  struct malloc_state_GLIBC_2_12 *next_free;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

struct malloc_par_GLIBC_2_12 {
  /* Tunable parameters */
  unsigned long    trim_threshold;
  INTERNAL_SIZE_T  top_pad;
  INTERNAL_SIZE_T  mmap_threshold;
  INTERNAL_SIZE_T  arena_test;
  INTERNAL_SIZE_T  arena_max;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  int              no_dyn_threshold;

  /* Cache malloc_getpagesize */
  unsigned int     pagesize;

  /* Statistics */
  INTERNAL_SIZE_T  mmapped_mem;
  INTERNAL_SIZE_T  max_mmapped_mem;
  INTERNAL_SIZE_T  max_total_mem; /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char*            sbrk_base;
};

#define HEAP_MAX_SIZE_GLIBC_2_12    HEAP_MAX_SIZE_GLIBC_2_5

/************************************************************************
**  GNU C Library version 2.17
************************************************************************/
#define malloc_state_GLIBC_2_17 malloc_state_GLIBC_2_12

struct malloc_par_GLIBC_2_17 {
  /* Tunable parameters */
  unsigned long    trim_threshold;
  INTERNAL_SIZE_T  top_pad;
  INTERNAL_SIZE_T  mmap_threshold;
  INTERNAL_SIZE_T  arena_test;
  INTERNAL_SIZE_T  arena_max;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int              no_dyn_threshold;

  /* Cache malloc_getpagesize */
  //unsigned int     pagesize;

  /* Statistics */
  INTERNAL_SIZE_T  mmapped_mem;
  INTERNAL_SIZE_T  max_mmapped_mem;
  INTERNAL_SIZE_T  max_total_mem; /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char*            sbrk_base;
};

#define HEAP_MAX_SIZE_GLIBC_2_17    HEAP_MAX_SIZE_GLIBC_2_5
#define MAX_FAST_SIZE_GLIBC_2_17    MAX_FAST_SIZE_GLIBC_2_12

/************************************************************************
**  GNU C Library version 2.18 and 2.19 are the same as 2.17
************************************************************************/


/************************************************************************
**  32-bit Target
**  Assume the debug host is 64-bit
* 
*   Warning, 32-bit core analyzer is not tested as often as 64-bit
************************************************************************/
#define INTERNAL_SIZE_T_32 unsigned int
#define SIZE_SZ_32                (sizeof(INTERNAL_SIZE_T_32))
#define MALLOC_ALIGNMENT_32       (2 * SIZE_SZ_32)
#define MALLOC_ALIGN_MASK_32      (MALLOC_ALIGNMENT_32 - 1)

#define ptr_t_32  unsigned int

struct malloc_chunk_32 {

  INTERNAL_SIZE_T_32      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T_32      size;       /* Size in bytes, including overhead. */

  ptr_t_32 fd;         /* double links -- used only if free. */
  ptr_t_32 bk;
};
typedef struct malloc_chunk_32* mfastbinptr_32;
typedef struct malloc_chunk_32* mchunkptr_32;

#define MIN_CHUNK_SIZE_32        (sizeof(struct malloc_chunk_32))
#define MINSIZE_32  \
  (unsigned int)(((MIN_CHUNK_SIZE_32+MALLOC_ALIGN_MASK_32) & ~MALLOC_ALIGN_MASK_32))

#define request2size_32(req)                                         \
  (((req) + SIZE_SZ_32 + MALLOC_ALIGN_MASK_32 < MINSIZE_32)  ?             \
   MINSIZE_32 :                                                      \
   ((req) + SIZE_SZ_32 + MALLOC_ALIGN_MASK_32) & ~MALLOC_ALIGN_MASK_32)

// The maximum fastbin request size we support
#define MAX_FAST_SIZE_GLIBC_2_3_32     80
#define fastbin_index_GLIBC_2_3_32(sz) ((((unsigned int)(sz)) >> 3) - 2)
#define NFASTBINS_GLIBC_2_3_32  (fastbin_index_GLIBC_2_3_32(request2size_32(MAX_FAST_SIZE_GLIBC_2_3_32))+1)

#define MAX_FAST_SIZE_GLIBC_2_5_32     MAX_FAST_SIZE_GLIBC_2_3_32
#define fastbin_index_GLIBC_2_5_32(sz) fastbin_index_GLIBC_2_3_32(sz)
#define NFASTBINS_GLIBC_2_5_32         NFASTBINS_GLIBC_2_3_32

#define MAX_FAST_SIZE_GLIBC_2_12_32     80
#define fastbin_index_GLIBC_2_12_32(sz) ((((unsigned int)(sz)) >> 3) - 2)
#define NFASTBINS_GLIBC_2_12_32  (fastbin_index_GLIBC_2_12_32(request2size_32(MAX_FAST_SIZE_GLIBC_2_12_32))+1)

//#define NONCONTIGUOUS_BIT (2U)
//#define contiguous(M)     (((M)->flags &  NONCONTIGUOUS_BIT) == 0)
//#define noncontiguous(M)  (((M)->flags &  NONCONTIGUOUS_BIT) != 0)

//#define NBINS             128
//#define BINMAPSHIFT      5
//#define BITSPERMAP       (1U << BINMAPSHIFT)
//#define BINMAPSIZE       (NBINS / BITSPERMAP)

//#define PREV_INUSE 0x1
//#define prev_inuse(p)       ((p)->size & PREV_INUSE)
//#define IS_MMAPPED 0x2
//#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
//#define NON_MAIN_ARENA 0x4
//#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)
//#define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
//#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

//  GNU C Library version 2.3.4
struct malloc_state_GLIBC_2_3_32 {
  int mutex; //mutex_t mutex;

  // The maximum chunk size to be eligible for fastbin
  INTERNAL_SIZE_T_32  max_fast;   // low 2 bits used as flags

  // Fastbins
  ptr_t_32      fastbins[NFASTBINS_GLIBC_2_3_32];	//mfastbinptr_32

  // Base of the topmost chunk -- not otherwise kept in a bin
  ptr_t_32        top;	//mchunkptr_32

  // The remainder from the most recent split of a small request
  ptr_t_32        last_remainder;	//mchunkptr_32

  // Normal bins packed as described above
  ptr_t_32        bins[NBINS * 2];	//mchunkptr_32

  // Bitmap of bins
  unsigned int     binmap[BINMAPSIZE];

  // Linked list
  ptr_t_32 next;	//struct malloc_state_GLIBC_2_3_32 *

  // Memory allocated from the system in this arena.
  INTERNAL_SIZE_T_32 system_mem;
  INTERNAL_SIZE_T_32 max_system_mem;
};

struct malloc_par_GLIBC_2_3_32 {
  // Tunable parameters
  unsigned int    trim_threshold;
  INTERNAL_SIZE_T_32  top_pad;
  INTERNAL_SIZE_T_32  mmap_threshold;

  // Memory map support
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;

  // Cache malloc_getpagesize
  unsigned int     pagesize;

  // Statistics
  INTERNAL_SIZE_T_32  mmapped_mem;
  INTERNAL_SIZE_T_32  max_mmapped_mem;
  INTERNAL_SIZE_T_32  max_total_mem; // only kept for NO_THREADS

  // First address handed out by MORECORE/sbrk.
  ptr_t_32            sbrk_base;	//char*
};

struct heap_info_GLIBC_2_3_32 {
  ptr_t_32 ar_ptr; // struct malloc_state_GLIBC_2_3_32*
  ptr_t_32 prev; // struct heap_info_GLIBC_2_3_32 *
  INTERNAL_SIZE_T_32 size;   // Current size in bytes.
  INTERNAL_SIZE_T_32 pad;    // Make sure the following data is properly aligned.
};

#define HEAP_MAX_SIZE_GLIBC_2_3_32 (1024*1024)

//  GNU C Library version 2.4
struct malloc_state_GLIBC_2_4_32 {
  int mutex; //mutex_t mutex;

  // Flags (formerly in max_fast).
  int flags;

  // Fastbins
  ptr_t_32      fastbins[NFASTBINS_GLIBC_2_3_32];	//mfastbinptr_32

  // Base of the topmost chunk -- not otherwise kept in a bin
  ptr_t_32        top;	//mchunkptr_32

  // The remainder from the most recent split of a small request
  ptr_t_32        last_remainder;	//mchunkptr_32

  // Normal bins packed as described above
  ptr_t_32        bins[NBINS * 2];	//mchunkptr_32

  // Bitmap of bins
  unsigned int     binmap[BINMAPSIZE];

  // Linked list
  ptr_t_32 next;	//struct malloc_state_GLIBC_2_4_32 *

  // Memory allocated from the system in this arena.
  INTERNAL_SIZE_T_32 system_mem;
  INTERNAL_SIZE_T_32 max_system_mem;
};

#define malloc_par_GLIBC_2_4_32 malloc_par_GLIBC_2_3_32
#define heap_info_GLIBC_2_4_32  heap_info_GLIBC_2_3_32

#define HEAP_MAX_SIZE_GLIBC_2_4_32     (1024*1024)
#define MAX_FAST_SIZE_GLIBC_2_4_32     MAX_FAST_SIZE_GLIBC_2_3_32

//  GNU C Library version 2.5 and later
struct malloc_state_GLIBC_2_5_32 {
  int mutex; //mutex_t mutex;

  // Flags (formerly in max_fast).
  int flags;

  // Fastbins
  ptr_t_32      fastbins[NFASTBINS_GLIBC_2_5_32];	//mfastbinptr_32

  // Base of the topmost chunk -- not otherwise kept in a bin
  ptr_t_32        top;	//mchunkptr_32

  // The remainder from the most recent split of a small request
  ptr_t_32        last_remainder;	//mchunkptr_32

  // Normal bins packed as described above
  ptr_t_32        bins[NBINS * 2 - 2];	//mchunkptr_32

  // Bitmap of bins/
  unsigned int     binmap[BINMAPSIZE];

  // Linked list
  ptr_t_32 next;	//struct malloc_state_GLIBC_2_5_32 *

  // Linked list for free arenas.
  ptr_t_32 next_free;	//struct malloc_state_GLIBC_2_5_32 *

  // Memory allocated from the system in this arena.
  INTERNAL_SIZE_T_32 system_mem;
  INTERNAL_SIZE_T_32 max_system_mem;
};

struct malloc_par_GLIBC_2_5_32 {
  // Tunable parameters
  unsigned int    trim_threshold;
  INTERNAL_SIZE_T_32  top_pad;
  INTERNAL_SIZE_T_32  mmap_threshold;

  // Memory map support
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  int              no_dyn_threshold;

  // Cache malloc_getpagesize
  unsigned int     pagesize;

  // Statistics
  INTERNAL_SIZE_T_32  mmapped_mem;
  INTERNAL_SIZE_T_32  max_mmapped_mem;
  INTERNAL_SIZE_T_32  max_total_mem; // only kept for NO_THREADS

  // First address handed out by MORECORE/sbrk.
  ptr_t_32            sbrk_base;	//char*
};

struct heap_info_GLIBC_2_5_32 {
  ptr_t_32 ar_ptr; // struct malloc_state_GLIBC_2_5_32*
  ptr_t_32    prev; 	// struct heap_info_GLIBC_2_5_32*
  unsigned int size;   // Current size in bytes.
  unsigned int mprotect_size;
  char pad[-6 * SIZE_SZ_32 & MALLOC_ALIGN_MASK_32];
};

#define DEFAULT_MMAP_THRESHOLD_MAX_32 (512 * 1024)
#define HEAP_MAX_SIZE_GLIBC_2_5_32 (2 * DEFAULT_MMAP_THRESHOLD_MAX_32)

struct malloc_state_GLIBC_2_12_32 {
  int mutex; //mutex_t mutex;

  // Flags (formerly in max_fast).
  int flags;

  // Fastbins
  ptr_t_32      fastbins[NFASTBINS_GLIBC_2_12_32];	//mfastbinptr_32

  // Base of the topmost chunk -- not otherwise kept in a bin
  ptr_t_32        top;	//mchunkptr_32

  // The remainder from the most recent split of a small request
  ptr_t_32        last_remainder;	//mchunkptr_32

  // Normal bins packed as described above
  ptr_t_32        bins[NBINS * 2 - 2];	//mchunkptr_32

  // Bitmap of bins/
  unsigned int     binmap[BINMAPSIZE];

  // Linked list
  ptr_t_32 next;	//struct malloc_state_GLIBC_2_12_32 *

  // Linked list for free arenas.
  ptr_t_32 next_free;	//struct malloc_state_GLIBC_2_12_32 *

  // Memory allocated from the system in this arena.
  INTERNAL_SIZE_T_32 system_mem;
  INTERNAL_SIZE_T_32 max_system_mem;
};

struct malloc_par_GLIBC_2_12_32 {
  // Tunable parameters
  unsigned int    trim_threshold;
  INTERNAL_SIZE_T_32  top_pad;
  INTERNAL_SIZE_T_32  mmap_threshold;
  INTERNAL_SIZE_T_32  arena_test;
  INTERNAL_SIZE_T_32  arena_max;

  // Memory map support
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  int              no_dyn_threshold;

  // Cache malloc_getpagesize
  unsigned int     pagesize;

  // Statistics
  INTERNAL_SIZE_T_32  mmapped_mem;
  INTERNAL_SIZE_T_32  max_mmapped_mem;
  INTERNAL_SIZE_T_32  max_total_mem; // only kept for NO_THREADS

  // First address handed out by MORECORE/sbrk.
  ptr_t_32            sbrk_base;	//char*
};

#define HEAP_MAX_SIZE_GLIBC_2_12_32    HEAP_MAX_SIZE_GLIBC_2_5_32

#define malloc_state_GLIBC_2_17_32 malloc_state_GLIBC_2_12_32

struct malloc_par_GLIBC_2_17_32 {
  // Tunable parameters
  unsigned int    trim_threshold;
  INTERNAL_SIZE_T_32  top_pad;
  INTERNAL_SIZE_T_32  mmap_threshold;
  INTERNAL_SIZE_T_32  arena_test;
  INTERNAL_SIZE_T_32  arena_max;

  // Memory map support
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  int              no_dyn_threshold;

  // Cache malloc_getpagesize
  //unsigned int     pagesize;

  // Statistics
  INTERNAL_SIZE_T_32  mmapped_mem;
  INTERNAL_SIZE_T_32  max_mmapped_mem;
  INTERNAL_SIZE_T_32  max_total_mem; // only kept for NO_THREADS

  // First address handed out by MORECORE/sbrk.
  ptr_t_32            sbrk_base;	//char*
};

#define HEAP_MAX_SIZE_GLIBC_2_17_32    HEAP_MAX_SIZE_GLIBC_2_5_32


#endif /* _MM_PTMALLOC_H */
