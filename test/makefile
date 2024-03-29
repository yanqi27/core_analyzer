
CXX = g++

COMP_OPT = -g -m64 -std=c++11

LIBS = -lpthread 

TARGETS = mallocTest

GDB    = gdb --data-directory=/usr/share/gdb

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
	export LD_LIBRARY_PATH=/usr/local/lib; $(GDB) mallocTest_tcmalloc -q -x verify.py

mallocTest_jemalloc.o: mallocTest.cpp
	$(CXX) $(COMP_OPT) -DJEMALLOC_TEST -c -o $@ $^

mallocTest_jemalloc: mallocTest_jemalloc.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS) -ljemalloc

check-jemalloc: mallocTest_jemalloc
	export LD_LIBRARY_PATH=/usr/local/lib; $(GDB) mallocTest_jemalloc -q -x verify.py

clean:
	rm *.o ${TARGETS}
