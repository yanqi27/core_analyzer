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

/*
 * Version history of the memory allocator
 * 
 * 	glibc		ptmalloc		dlmalloc
 * 	------------------------------------------------
 * 	2.3		?
 * 	2.4		?
 * 	2.5		?
 * 	2.12 - 2.23	ptmalloc2-20011215	2.7.0
 */

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

struct malloc_chunk_s {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
};

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
**  GNU C Library version 2.17 - 2.21
**    struct malloc_par removes member "pagesize"
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
**  GNU C Library version 2.22 - 2.23
**    struct malloc_state adds a member "attached_threads"
************************************************************************/
struct malloc_state_GLIBC_2_22 {
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
  struct malloc_state_GLIBC_2_22 *next;

  /* Linked list for free arenas.  */
  struct malloc_state_GLIBC_2_22 *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on the free list. */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

#define malloc_par_GLIBC_2_22 malloc_par_GLIBC_2_17

#define HEAP_MAX_SIZE_GLIBC_2_22    HEAP_MAX_SIZE_GLIBC_2_5
#define MAX_FAST_SIZE_GLIBC_2_22    MAX_FAST_SIZE_GLIBC_2_12

#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))

#endif /* _MM_PTMALLOC_H */
