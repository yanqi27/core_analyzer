/*
 * heap_mimalloc.h
 *  mimalloc data structure
 *
 *  Created on: August 27, 2016
 *      Author: myan
 */
#ifndef _MM_MIMALLOC_H
#define _MM_MIMALLOC_H

#include <stdint.h>
#include <pthread.h>

#include "heap.h"

// In debug mode there is a padding structure at the end of the blocks to check for buffer overflows
#if (MI_PADDING)
typedef struct mi_padding_s {
  uint32_t canary; // encoded block value to check validity of the padding (in case of overflow)
  uint32_t delta;  // padding bytes before the block. (mi_usable_size(p) - delta == exact allocated bytes)
} mi_padding_t;
#define MI_PADDING_SIZE   (sizeof(mi_padding_t))
#define MI_PADDING_WSIZE  ((MI_PADDING_SIZE + MI_INTPTR_SIZE - 1) / MI_INTPTR_SIZE)
#else
#define MI_PADDING_SIZE   0
#define MI_PADDING_WSIZE  0
#endif

#define MI_SMALL_WSIZE_MAX  (128)
#define MI_PAGES_DIRECT     (MI_SMALL_WSIZE_MAX + MI_PADDING_WSIZE + 1)

#define MI_BIN_HUGE  (73U)
#define MI_BIN_FULL  (MI_BIN_HUGE+1)

typedef struct mi_tld_s mi_tld_t;
typedef struct mi_page_s mi_page_t;
typedef struct mi_page_queue_s mi_page_queue_t;
typedef size_t mi_threadid_t;
typedef int mi_arena_id_t;
typedef uintptr_t  mi_encoded_t;

typedef struct mi_block_s {
  mi_encoded_t next;
} mi_block_t;

typedef struct mi_random_cxt_s {
  uint32_t input[16];
  uint32_t output[16];
  int      output_available;
  bool     weak;
} mi_random_ctx_t;

typedef struct mi_page_queue_s {
  mi_page_t* first;
  mi_page_t* last;
  size_t     block_size;
} mi_page_queue_t;

typedef struct mi_heap_s {
  mi_tld_t*             tld;
  mi_block_t*           thread_delayed_free;
  mi_threadid_t         thread_id;
  mi_arena_id_t         arena_id;
  uintptr_t             cookie;
  uintptr_t             keys[2];
  mi_random_ctx_t       random;
  size_t                page_count;
  size_t                page_retired_min;
  size_t                page_retired_max;
  long                  generic_count;
  long                  generic_collect_count;
  struct mi_heap_s*     next;
  bool                  no_reclaim;
  uint8_t               tag;
  /* The followng fields are defined if MI_GUARDED is enabled */
  size_t                guarded_size_min;
  size_t                guarded_size_max;
  size_t                guarded_sample_rate;
  size_t                guarded_sample_count;
  /* End of fields defined if MI_GUARDED is enabled */
  mi_page_t*            pages_free_direct[MI_PAGES_DIRECT];
  mi_page_queue_t       pages[MI_BIN_FULL + 1];
} mi_heap_t;

typedef uintptr_t mi_thread_free_t;

typedef union mi_page_flags_s {
  uint8_t full_aligned;
  struct {
    uint8_t in_full : 1;
    uint8_t has_aligned : 1;
  } x;
} mi_page_flags_t;

typedef struct mi_page_s {
  // "owned" by the segment
  uint32_t              slice_count;
  uint32_t              slice_offset;
  uint8_t               is_committed:1;
  uint8_t               is_zero_init:1;
  uint8_t               is_huge:1;
  // layout like this to optimize access in `mi_malloc` and `mi_free`
  uint16_t              capacity;
  uint16_t              reserved;
  mi_page_flags_t       flags;
  uint8_t               free_is_zero:1;
  uint8_t               retire_expire:7;

  mi_block_t*           free;
  mi_block_t*           local_free;
  uint16_t              used;
  uint8_t               block_size_shift;
  uint8_t               heap_tag;

  size_t                block_size;
  uint8_t*              page_start;

  // The following field is defined if (MI_ENCODE_FREELIST || MI_PADDING)
  uintptr_t             keys[2];
  // end of fields defined if (MI_ENCODE_FREELIST || MI_PADDING)

  mi_thread_free_t xthread_free;
  uintptr_t        xheap;

  struct mi_page_s*     next;
  struct mi_page_s*     prev; 

  // 64-bit 11 words, 32-bit 13 words, (+2 for secure)
  void* padding[1];
} mi_page_t;

struct ca_page {
  address_t addr; // mi_page_t address
  address_t start;
  address_t end;
  size_t block_size;
  int bin_index;
  bool operator<(const ca_page& other) const { return start < other.start; }
};

struct ca_bin {
  size_t block_size = 0;
  size_t page_count = 0;
  size_t inuse_blks = 0;
  size_t free_blks = 0;
  int bin_index = -1;
};

#endif /* _MM_MIMALLOC_H */
