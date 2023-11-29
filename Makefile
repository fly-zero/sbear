.PHONY: all
all: sbear

sbear: main.o
	$(CXX) -o $@ $^

main.o: main.cpp
	$(CXX) -g3 -c -std=c++20 -o $@ $^

.PHONY: clean
clean:
	rm -f sbear *.o