
CXX = g++

COMP_OPT = -g -m64 -fpermissive

LIBS = -lpthread 

TARGETS = mallocTest

GDB    = ../bin/Linux/ptmalloc/gdb-9.2/gdb --data-directory=/usr/local/share/gdb
GDB_TC = ../bin/Linux/tcmalloc/gdb-8.1/gdb --data-directory=/usr/local/share/gdb

all: ${TARGETS}

mallocTest: mallocTest.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(COMP_OPT) -c $<

check: all
	$(GDB) mallocTest -q -x verify.py

check_verbose: all
	$(GDB) -q -x verify.py

mallocTest_tcmalloc.o: mallocTest.cpp
	$(CXX) $(COMP_OPT) -DTCMALLOC_TEST -c -o $@ $^

mallocTest_tcmalloc: mallocTest_tcmalloc.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS) -ltcmalloc

check-tcmalloc: mallocTest_tcmalloc
	$(GDB_TC) mallocTest_tcmalloc -q -x verify.py

clean:
	rm *.o ${TARGETS}
