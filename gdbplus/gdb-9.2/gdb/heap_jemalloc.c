/*
 * heap_jemalloc.c
 *
 *  Created on: March 19, 2023
 *      Author: myan
 *
 * Stubs for jemalloc parser.
 */
#include "heap.h"

void register_je_malloc() {
	return register_heap_manager("je", NULL, false);
}
