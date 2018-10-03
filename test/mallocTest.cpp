/*
 * mallocTest.cpp
 *     Allocate/deallocate heap memory randomly and expose these blocks'
 *     information through global variables so that test driver may observe
 *     and compare them with what are detected by core analyzer
 *
 *  Created on: March 20, 2016
 *      Author: myan
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <list>
#include <iostream>

#ifdef TCMALLOC_TEST
#include <gperftools/tcmalloc.h>
#else
#include <malloc.h>
#endif

#include <pthread.h>

/*
 * Since glibc 2.26, ptmalloc introduces per-thread cache.
 * In order for core_analyzer to parse all heap data, the application
 * needs to link with libpthread. This allows gdb to extract thread-local
 * variables of ptmalloc tcache.
 * !TODO! multi-threaded malloc/free
 */
static __thread int myNumber = 5;
static pthread_mutex_t myLock = PTHREAD_MUTEX_INITIALIZER;
static void
IncMyNumberLock(void)
{
	pthread_mutex_lock(&myLock);
	myNumber++;
	pthread_mutex_unlock(&myLock);
}

struct region {
	void *p;
	size_t size;
	bool inuse;
};

class Base
{
public:
	Base() : data(-1) {}
	virtual ~Base() {}
	virtual void doSomething(void) = 0;
private:
	int data;
};

class Derived : public Base
{
public:
	Derived(int _id) : id(_id) {}
	virtual ~Derived() {}
	virtual void doSomething(void)
	{
		std::cout << "Derived::doSomething()\n";
	}
private:
	int id;
};

class Derived2 : public Base
{
public:
	Derived2(float _speed) : speed(_speed) {}
	virtual ~Derived2() {}
	virtual void doSomething(void)
	{
		std::cout << "Derived2::doSomething()\n";
	}
private:
	float speed;
};

const unsigned int num_small_regions = 4096;
const unsigned int num_big_regions = 8;
const unsigned int num_regions = num_small_regions + num_big_regions;
region * regions;

const unsigned int num_derived = 4;
Base *derived_objects[num_derived * 2];
uintptr_t hidden_object;

static size_t
rand_size()
{
	return rand() % 1032;
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

void
last_call(void)
{
	std::cout << "This is the last function call\n";
	IncMyNumberLock();
}

static size_t
region_size(void *p)
{

#ifdef TCMALLOC_TEST
	return tc_malloc_size(p);
#else
	return malloc_usable_size(p);
#endif
}

int
main(int argc, char** argv)
{
	unsigned int index = 0;
	unsigned int i;

	// Initialize random number generator
	srand (time(NULL));

	regions = (region *) calloc(num_regions, sizeof *regions);
	if (regions == NULL)
		fatal_error("Out of memory");

	// Allocate small memory blocks in random sizes
	for (i = 0; i < num_small_regions; i++, index++) {
		regions[index].size = rand_size();
		regions[index].inuse = true;
		regions[index].p = malloc(regions[index].size);
		if (regions[index].p == NULL)
			fatal_error("Out of memory");
		regions[index].size = region_size(regions[index].p);
	}

	// Allocate big memory blocks, i.e. > 128KiB
	const size_t threshold = 128 * 1024;
	const size_t page_size = 4096;
	for (i = 0; i < num_big_regions; i++, index++) {
		regions[index].size = threshold + (rand() % 16) * page_size;
		regions[index].inuse = true;
		regions[index].p = malloc(regions[index].size);
		if (regions[index].p == NULL)
			fatal_error("Out of memory");
		regions[index].size = region_size(regions[index].p);
	}

	// Create a group of Base objects
	for (i = 0; i < num_derived; i++) {
		derived_objects[i] = new Derived(i);
	}
	for (i = 0; i < num_derived; i++) {
		derived_objects[num_derived + i] = new Derived2(i * 0.1);
	}

	// A list of Base Objects
	std::list<Base *> objlist;
	for (i = 0; i < 32; i++) {
		objlist.push_back(new Derived2(num_derived + i));
	}
	hidden_object = (uintptr_t)objlist.front();

	// Free some small memory blocks
	unsigned int num_free_regions = 0;
	for (i = 0; i < num_small_regions; i++) {
		if (is_lucky(i) == true) {
			regions[i].inuse = false;
			free(regions[i].p);
			num_free_regions++;
		}
	}

	// Test driver may break at this function for inspection or create a core dump
	last_call();

	return 0;
}

