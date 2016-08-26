/*
 * mallocTest.cpp
 *
 *  Created on: March 20, 2016
 *      Author: myan
*/
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <list>
#include <iostream>
#include <malloc.h>

struct region {
	void *p;
	size_t size;
	bool inuse;
};

const unsigned num_regions = 4096;
region * regions;

static size_t
rand_size()
{
	return rand() % 1024;
}

static void
fatal_error(const char* e)
{
	std::cerr << e << std::endl;
	exit(-1);
}

static bool
is_lucky(unsigned index)
{
	//half are lucky
	return (index % 2) ^ (rand() % 2);
}

int
main(int argc, char** argv)
{

	//initialize random number generator
	srand (time(NULL));

	//allocate container
	regions = (region *) calloc(num_regions, sizeof *regions);
	if (regions == NULL)
		fatal_error("Out of memory");

	//allocate memory blocks in random sizes
	for (unsigned i = 0; i < num_regions; i++) {
		regions[i].size = rand_size();
		regions[i].inuse = true;
		regions[i].p = malloc(regions[i].size);
		if (regions[i].p == NULL)
			fatal_error("Out of memory");
		regions[i].size = malloc_usable_size(regions[i].p);
	}

	//free part of the memory blocks
	for (unsigned i = 0; i < num_regions; i++) {
		if (is_lucky(i) == true) {
			regions[i].inuse = false;
			free(regions[i].p);
		}
	}

	//create memory image for inspection
	if (::getenv("PAUSE") != NULL)
		::pause();
	else
		::abort();

	return 0;
}

