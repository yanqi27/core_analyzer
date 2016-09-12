/*
 * heap_tcmalloc.h
 *  TCMalloc data structure
 *
 *  Created on: August 27, 2016
 *      Author: myan
 */
#ifndef _MM_TCMALLOC_H
#define _MM_TCMALLOC_H

#include <stdint.h>
#include <pthread.h>

#include "heap.h"

struct ca_span {
	unsigned long start;
	unsigned long length;
	uintptr_t next;
	uintptr_t prev;
	uintptr_t objects;
	unsigned int refcount : 16;
	unsigned int sizeclass : 8;
	unsigned int location : 2;
	unsigned int sample : 1;
	/*
	 * A bit map with set bit indicating free block
	 */
	unsigned int *bitmap;
	unsigned int count;
#define UINT_BITS 32
	bool corrupt;
};

struct ca_config {
	size_t kNumClasses;
	unsigned long kPageShift;
	struct {
		size_t *class_to_size;
		size_t *class_to_pages;
		int *num_objects_to_move;
	} sizemap;
};

enum ca_span_location {
	SPAN_IN_USE,
	SPAN_ON_NORMAL_FREELIST,
	SPAN_ON_RETURNED_FREELIST
};

#endif /* _MM_TCMALLOC_H */
