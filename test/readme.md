### Unit Test
This test verifies core_analyzer's following functions:

-  small heap region's size and status
- gdb python extension

It has following limitations:

- ptmalloc only. The test calls malloc_usable_size() to get heap allocation size
- gdb and python

To run the test, simply

```
make check
```
