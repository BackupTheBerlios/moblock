
CFLAGS=-Wall -O2 -march=i586 -mcpu=i686 -fomit-frame-pointer -ffast-math -D_GNU_SOURCE -L/usr/include/libipq
CC=gcc

all: MoBlock


MoBlock: MoBlock.o rbt.o
	gcc -o $@ MoBlock.o rbt.o -lipq
	strip $@
	
clean:
	rm -f *.o *~ *# MoBlock

.PHONY: clean
