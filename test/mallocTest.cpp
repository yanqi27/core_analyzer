/*
 * myan
*/
#include <stdlib.h>


int main(int argc, char** argv)
{
  //allocate small blocks
  char* pa[10];
  for (int i = 0; i < 10; i++) {
    pa[i] = malloc(i << 2);
  }
  
  //allocate bigger blocsk (> threshold 256KB)
  void* mpa[5];
  const size_t sz = 256 * 1024;
  for (int i = 0; i < 5; i++) {
    mpa[i] = malloc(sz + i * 4096);
  }
  
  ::abort();
}
