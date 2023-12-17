CC=gcc

all: a.out

a.out: test.o
	$(CC) -o a.out test.o

test.o: test.c
	$(CC) -c -o $@ $<

.PHONY: clean
clean:
	rm -f test.o a.out
