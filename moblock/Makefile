
CFLAGS=-O3 -march=i586 -ffast-math -D_GNU_SOURCE
CC=gcc

all: MoBlock


MoBlock: MoBlock.o rbt.o
	gcc -o $@ MoBlock.o rbt.o -lipq
	strip $@
	
clean:
	rm -f *.o *~ *# MoBlock

.PHONY: clean

