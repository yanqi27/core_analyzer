/*
 * mallocTest.cpp
 *     Allocate/deallocate heap memory randomly and expose these blocks'
 *     information through global variables so that test driver may observe
 *     and compare them with what are detected by core analyzer
 *
 *  Created on: March 20, 2016
 *      Author: myan
*/
#ifdef _WIN32
#include "stdafx.h"
#include <Windows.h>
#include <thread>

#elif defined(linux)
#include <unistd.h>
#ifdef TCMALLOC_TEST
#include <gperftools/tcmalloc.h>
#else
#include <malloc.h>
#endif

#include <pthread.h>
#endif // _WIN32

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <list>
#include <iostream>
#include <mutex>

#define NUM_THREADS 2
/*
 * Since glibc 2.26, ptmalloc introduces per-thread cache.
 * In order for core_analyzer to parse all heap data, the application
 * needs to link with libpthread. This allows gdb to extract thread-local
 * variables of ptmalloc tcache.
 * !TODO! multi-threaded malloc/free
 */
//#ifdef linux
//static pthread_mutex_t myLock = PTHREAD_MUTEX_INITIALIZER;
//#endif
static std::mutex myLock;
static int region_index;

static int
get_index(void)
{
	int res;
	std::unique_lock<std::mutex> lock(myLock);
	//pthread_mutex_lock(&myLock);
	res = region_index++;
	//pthread_mutex_unlock(&myLock);
	return res;
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

const unsigned int num_small_regions = 4096 * NUM_THREADS;
const unsigned int num_big_regions = 8 * NUM_THREADS;
const unsigned int num_regions = num_small_regions + num_big_regions + 1;
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
	return ((index % 2) ^ (rand() % 2)) != 0;
}

void
last_call(void)
{
	std::cout << "This is the last function call\n";
}

static size_t
region_size(void *p)
{
#ifdef linux

#ifdef TCMALLOC_TEST
	return tc_malloc_size(p);
#else
	return malloc_usable_size(p);
#endif

#elif _WIN32
	return _msize(p);
#else
	return 0;
#endif // linux
}

static void
mysleep(unsigned long s)
{
#ifdef linux
	sleep(s);
#else
	Sleep(s * 1000);
#endif
}

static void *
thread_func(void *arg)
{
	volatile bool *done = (volatile bool *)arg;
	unsigned int index, i;

	// Allocate small memory blocks in random sizes
	for (i = 0; i < num_small_regions/NUM_THREADS; i++) {
		index = get_index();
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
	for (i = 0; i < num_big_regions/NUM_THREADS; i++) {
		index = get_index();
		regions[index].size = threshold + (rand() % 16) * page_size;
		regions[index].inuse = true;
		regions[index].p = malloc(regions[index].size);
		if (regions[index].p == NULL)
			fatal_error("Out of memory");
		regions[index].size = region_size(regions[index].p);
	}

	// Signal memory allocation has finished, wait for memory release
	*done = true;
	while (*done) {
		mysleep(1);
	}

	// Free some small memory blocks
	for (i = 0; i < (num_regions - 1)/NUM_THREADS; i++) {
		index = get_index();
		if (regions[index].size < threshold && is_lucky(index)) {
			regions[index].inuse = false;
			free(regions[index].p);
		}
	}

	// Don't exit the thread so that per-thread cache is valid
	*done = true;
	while (true) {
		mysleep(1);
	}

	return NULL;
}

int
main(int argc, char** argv)
{
	int i;

	{
		size_t sz = 9;
		const int count = 5;
		char *ptrs[count];
		for (i = 0; i < count; i++) {
			ptrs[i] = new char[sz];
			printf("[%d] %p\n", i, ptrs[i]);
		}
		for (i = 0; i < count; i++) {
			if (i % 2)
				delete[] ptrs[i];
		}
		char c = getchar();
		return 0;
	}

	// Initialize random number generator
#ifdef linux
	srand (time(NULL));
#endif
	regions = (region *) calloc(num_regions, sizeof *regions);
	if (regions == NULL)
		fatal_error("Out of memory");
	// Include the allocated buffer for regions
	regions[num_regions - 1].inuse = true;
	regions[num_regions - 1].p = regions;
	regions[num_regions - 1].size = region_size(regions);

	// Create a group of Base objects
	for (i = 0; i < num_derived; i++) {
		derived_objects[i] = new Derived(i);
	}
	for (i = 0; i < num_derived; i++) {
		derived_objects[num_derived + i] = new Derived2(i * (float)0.1);
	}

	// A list of Base Objects
	std::list<Base *> objlist;
	for (i = 0; i < 32; i++) {
		objlist.push_back(new Derived2((float)(num_derived + i)));
	}
	hidden_object = (uintptr_t)objlist.front();

	bool flags[NUM_THREADS];
	for (i = 0; i < NUM_THREADS; i++)
		flags[i] = false;
#ifdef linux
	pthread_t tids[NUM_THREADS];
	for (i = 0; i < NUM_THREADS; i++) {
		if (pthread_create(&tids[i], NULL, thread_func, &flags[i]) != 0) {
			fatal_error("Failed to create pthread");
		}
	}
#else
	std::list<std::thread *> threads;
	for (i = 0; i < NUM_THREADS; i++) {
		std::thread *thrd = new std::thread(thread_func, &flags[i]);
		threads.push_back(thrd);
	}
#endif // linux

	// Wait for threads to finish memory allocations
	for (i = 0; i < NUM_THREADS; i++) {
		while (flags[i] == false)
			mysleep(1);
	}
	// Signal threads to start releasing memory
	region_index = 0;
	for (i = 0; i < NUM_THREADS; i++)
		flags[i] = false;
	// Wait until memory release is done
	for (i = 0; i < NUM_THREADS; i++) {
		while (flags[i] == false)
			mysleep(1);
	}

	// Test driver may break at this function for inspection or create a core dump
	last_call();

	return 0;
}

