/*
 * mallocTest.cpp
 *
 *  Created on: March 20, 2016
 *      Author: myan
*/
#include <stdlib.h>
#include <string.h>
#include <list>
#include <iostream>

int main(int argc, char** argv)
{
    //allocate small blocks
    const int nblks = 10;
    char* pa[nblks];
    for (int i = 0; i < nblks; i++) {
	pa[i] = (char*)malloc(i << 2);
    }

    //allocate bigger blocsk (> threshold 256KB)
    const int nregions = 5;
    void* mpa[nregions];
    const size_t sz = 256 * 1024;
    for (int i = 0; i < nregions; i++) {
	mpa[i] = malloc(sz + i * 4096);
    }

    //check fast bins
    std::list<void*> blklist;
    std::list<int> blksz;
    for (int sz = 1; sz < 160; sz += 16) {
	void *p = malloc(sz);
	memset(p, sz, sz);
	blklist.push_back(p);
	blksz.push_back(sz);
    }
    std::cout << "The following block should be in free state" << std::endl;
    std::list<void*>::iterator itr;
    std::list<int>::iterator itr2;
    for (itr = blklist.begin(), itr2 = blksz.begin(); itr != blklist.end() && itr2 != blksz.end(); itr++, itr2++) {
	void* p = *itr;
	free(p);
	int sz = *itr2;
	std::cout << "0x" << std::hex << p << " size=" << std::dec << sz << std::endl;
    }
    
    
    ::abort();
}
