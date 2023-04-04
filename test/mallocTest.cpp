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

#elif defined(__linux__)
#include <unistd.h>
#ifdef TCMALLOC_TEST
#include <gperftools/tcmalloc.h>
#elif defined(JEMALLOC_TEST)
#include <jemalloc/jemalloc.h>
#else
#include <malloc.h>
#endif

#include <pthread.h>
#include <fstream>
#endif // _WIN32

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <list>
#include <iostream>
#include <mutex>

const int NUM_THREADS = 4;

const unsigned int num_small_regions = 4096 * NUM_THREADS;
const unsigned int num_big_regions = 16 * NUM_THREADS;
const unsigned int num_regions = num_small_regions + num_big_regions + 1;

const size_t max_small_sz = 1032;
const size_t threshold = 128 * 1024;
const size_t page_size = 4096;

/*
 * Since glibc 2.26, ptmalloc introduces per-thread cache.
 * In order for core_analyzer to parse all heap data, the application
 * needs to link with libpthread. This allows gdb to extract thread-local
 * variables of ptmalloc tcache.
 */
static std::mutex myLock;
static int region_index;

static int
get_index(void)
{
	int res;
	std::unique_lock<std::mutex> lock(myLock);
	res = region_index++;
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

region * regions;

const unsigned int num_derived = 4;
Base *derived_objects[num_derived * 2];
uintptr_t hidden_object;

static size_t
rand_small_size()
{
	return rand() % max_small_sz;
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
#ifdef _WIN32
	/*
	// output memory stats as the baseline
	std::cout << "{" << std::endl;
	// regions
	std::cout << "\t\"num_regions=\":" << num_regions << "," << std::endl;
	std::cout << "\t" << "\"regions\": [" << std::endl;
	for (unsigned int i = 0; i < num_regions; i++) {
		std::cout << "\t\t{";
		std::cout << "\"address\":" << (size_t)regions[i].p << ",";
		std::cout << "\"size\":" << regions[i].size << ",";
		std::cout << "\"inuse\":" << regions[i].inuse;
		std::cout << "}";
		if (i < num_regions - 1)
			std::cout << ",";
		std::cout << std::endl;
	}
	std::cout << "\t]" << std::endl;
	//
	std::cout << "}" << std::endl;
	*/
	//std::cout << "press return ...";
	char c = getchar();
#endif
}

static size_t
region_size(void *p)
{
#ifdef __linux__

#ifdef TCMALLOC_TEST
	return tc_malloc_size(p);
#elif defined(JEMALLOC_TEST)
	return malloc_usable_size(p);
#else
	return malloc_usable_size(p);
#endif

#elif _WIN32
	return _msize(p);
#else
	return 0;
#endif // __linux__
}

static void
mysleep(unsigned long s)
{
#ifdef __linux__
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
		regions[index].size = rand_small_size();
		regions[index].inuse = true;
		regions[index].p = malloc(regions[index].size);
		if (regions[index].p == NULL)
			fatal_error("Out of memory");
		regions[index].size = region_size(regions[index].p);
	}

	// Allocate big memory blocks, i.e. > 128KiB
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

#ifdef __linux__
	// Force core file include file-backed private/shared mappings
	const char* coredump_filter_path = "/proc/self/coredump_filter";
	unsigned int filter_value = 0x33;
	std::ifstream ifile_stream(coredump_filter_path);
	if (ifile_stream.is_open()) {
		ifile_stream >> std::hex >> filter_value;
		ifile_stream.close();
		// Add bit 2 (file-backed private mapping) and 3 (file-backed shared mapping)
		filter_value |= 0xc;
		std::ofstream ofile_stream(coredump_filter_path);
		if (ofile_stream.is_open()) {
			ofile_stream << filter_value;
			ofile_stream.close();
		}
	}
#endif
	// Initialize random number generator
	srand ((unsigned int)time(NULL));
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

	bool *flags = new bool [NUM_THREADS];
	for (i = 0; i < NUM_THREADS; i++)
		flags[i] = false;

	// Spawn threads
	std::list<std::thread *> threads;
	for (i = 0; i < NUM_THREADS; i++) {
		std::thread *thrd = new std::thread(thread_func, &flags[i]);
		threads.push_back(thrd);
	}

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

	delete[] flags;

	return 0;
}
