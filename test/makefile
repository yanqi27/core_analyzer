
CXX = g++

COMP_OPT = -g -m64 -fpermissive

LIBS = 

TARGETS = mallocTest

all: ${TARGETS}

mallocTest: mallocTest.o
	$(CXX) $(COMP_OPT) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(COMP_OPT) -c $<

run:
	./mallocTest

clean:
	rm *.o core.* ${TARGETS}
