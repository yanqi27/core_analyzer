
CXX = g++

COMP_OPT = -g -m64

LIBS = -lpthread 

TARGETS = mallocTest

GDB    = /workspaces/core_analyzer/build/gdb-12.1/build/gdb/gdb --data-directory=/usr/share/gdb

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
	$(GDB) mallocTest_tcmalloc -q -ex 'switch_heap tc' -x verify.py

clean:
	rm *.o ${TARGETS}
