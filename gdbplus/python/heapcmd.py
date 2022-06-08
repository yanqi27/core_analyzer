#!/usr/bin/env python

#
# This script is a collection of some useful heap profiling functions
#     based on core_analyzer
#

import gdb

def topblocks(n=10):
    blocks = {}
    blk=gdb.heap_walk(0)
    while blk:
        if blk.inuse:
            if blk.size in blocks:
                blocks[blk.size] += 1
            else:
                blocks[blk.size] = 1
        blk=gdb.heap_walk(blk)
    #Print stats
    total_inuse_count = 0
    total_inuse_bytes = 0
    for blkSz in blocks:
        total_inuse_count += blocks[blkSz]
        total_inuse_bytes += blkSz * blocks[blkSz]
    print "Total inuse blocks: ", total_inuse_count, " total bytes: ", \
        total_inuse_bytes, " number of size classes: ", len(blocks)
    #Top n blocks by size
    print "Top ", n, " blocks by size"
    pn = n
    for sz in sorted(blocks.keys(), reverse = True):
        count = blocks[sz]
        while count > 0 and pn > 0:
            print "\t", sz
            pn -= 1
            count -= 1
        if pn == 0:
            break
    #Top n size class by count
    print "Top ", n, " block sizes by count"
    pn = n
    for key, value in sorted(blocks.items(), key=lambda kv: kv[1], reverse=True):
        print "\t size ", key, " count: ", value
        pn -= 1
        if pn == 0:
            break
    print ""

def heapwalk(addr=0,n=0xffffffff):
    total=0
    total_inuse=0
    total_free=0
    total_inuse_bytes=0
    total_free_bytes=0
    blk=gdb.heap_walk(addr)

    while blk:
        total=total+1
        if blk.inuse:
            total_inuse=total_inuse+1
            total_inuse_bytes=total_inuse_bytes+blk.size
        else:
            total_free=total_free+1
            total_free_bytes=total_free_bytes+blk.size

        print "[", total, "] ", blk
        if n!=0 and total>=n:
            break

        blk=gdb.heap_walk(blk)

    print "Total ", total_inuse, " inuse blocks of ", total_inuse_bytes, " bytes"
    print "Total ", total_free, " free blocks of ", total_free_bytes, " bytes"
