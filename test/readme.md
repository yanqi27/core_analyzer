### Unit Test
This test verifies core_analyzer's functions through its gdb python extension.
A python script is invoked by gdb, which loads and runs a C++ program. The
program allocates numerous heap memory and creates C++ objects. The python
script extracts variables from the program which identifies heap blocks and
their status. It then calls core_analyzer APIs and compares the result with
what the variables reveal.

The test is first run against a live process. The python script then creates
a core dump file and loads it and verifies core_analyzer APIs again.


To run the test, simply

```
make check
```

By default, ptmalloc is tested. For tcmalloc
```
make check_tcmalloc
```
