
CXX = g++

COMP_OPT = -g -m64 -fpermissive

LIBS = 

TARGETS = mallocTest

GDB    = ../bin/Linux/ptmalloc/gdb-7.11.1/gdb
GDB_TC = ../bin/Linux/tcmalloc/gdb-7.11.1/gdb

all: ${TARGETS}

mallocTest: mallocTest.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(COMP_OPT) -c $<

check: all
	$(GDB) mallocTest -q -x verify.py | grep ca_test

check_verbose: all
	$(GDB) -q -x verify.py

mallocTest_tcmalloc.o: mallocTest.cpp
	$(CXX) $(COMP_OPT) -DTCMALLOC_TEST -c -o $@ $^

mallocTest_tcmalloc: mallocTest_tcmalloc.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS) -ltcmalloc

check_tcmalloc: mallocTest_tcmalloc
	$(GDB_TC) mallocTest_tcmalloc -q -x verify.py | grep ca_test

clean:
	rm *.o ${TARGETS}
