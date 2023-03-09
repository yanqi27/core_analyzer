
## Typical code path
Allocate memory without tcache
```
#0  arena_slab_reg_alloc_batch (slab=0x7ffff5c16480, bin_info=0x7ffff7ee6278 <je_bin_infos+760>, cnt=32, ptrs=0x7ffff6c471e8) at src/arena.c:280
#1  0x00007ffff7ab0d85 in je_arena_cache_bin_fill_small (tsdn=0x7ffff67febf8, arena=0x7ffff5c01040, cache_bin=0x7ffff67ff120, cache_bin_info=0x7ffff6e01066, binind=19, nfill=32) at src/arena.c:985
#2  0x00007ffff7c76543 in je_tcache_alloc_small_hard (tsdn=0x7ffff67febf8, arena=0x7ffff5c01040, tcache=0x7ffff67fef50, cache_bin=0x7ffff67ff120, binind=19, tcache_success=0x7ffff67fdd90) at src/tcache.c:238
#3  0x00007ffff783c901 in tcache_alloc_small (slow_path=false, zero=false, binind=19, size=783, tcache=0x7ffff67fef50, arena=0x7ffff5c01040, tsd=0x7ffff67febf8) at include/jemalloc/internal/tcache_inlines.h:68
#4  arena_malloc (slow_path=false, tcache=0x7ffff67fef50, zero=false, ind=19, size=783, arena=0x0, tsdn=0x7ffff67febf8) at include/jemalloc/internal/arena_inlines_b.h:151
#5  iallocztm (slow_path=false, arena=0x0, is_internal=false, tcache=0x7ffff67fef50, zero=false, ind=19, size=783, tsdn=0x7ffff67febf8) at include/jemalloc/internal/jemalloc_internal_inlines_c.h:66
#6  imalloc_no_sample (ind=19, usize=896, size=783, tsd=0x7ffff67febf8, dopts=0x7ffff67fddc0, sopts=0x7ffff67fdd60) at src/jemalloc.c:2378
#7  imalloc_body (tsd=0x7ffff67febf8, dopts=0x7ffff67fddc0, sopts=0x7ffff67fdd60) at src/jemalloc.c:2553
#8  imalloc (dopts=0x7ffff67fddc0, sopts=0x7ffff67fdd60) at src/jemalloc.c:2667
#9  je_malloc_default (size=783) at src/jemalloc.c:2702
#10 0x00007ffff785b178 in imalloc_fastpath (fallback_alloc=0x7ffff78243f9 <je_malloc_default>, size=783) at include/jemalloc/internal/jemalloc_internal_inlines_c.h:321
#11 malloc (size=783) at src/jemalloc.c:2726
```
