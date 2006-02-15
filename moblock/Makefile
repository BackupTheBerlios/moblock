
# To use the old-soon-to-be-deprecated libipq interface
# uncomment the following line and comment the NFQUEUE one,
# then comment the gcc line with netfilter_queue and
# uncomment the following one.

#QUEUE_LIB=LIBIPQ
QUEUE_LIB=NFQUEUE

CFLAGS=-Wall -O2 -march=i586 -mtune=i686 -fomit-frame-pointer -ffast-math \
	-D_GNU_SOURCE -D$(QUEUE_LIB)
CC=gcc

all: MoBlock


MoBlock: MoBlock.o rbt.o
	gcc -o $@ MoBlock.o rbt.o -lnetfilter_queue
	#gcc -o $@ MoBlock.o rbt.o -lipq
	strip $@
	
clean:
	rm -f *.o *~ *# MoBlock

.PHONY: clean
