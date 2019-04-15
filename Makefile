## Makefile for objectfs

PROGRAM = objectfs

OBJECTS = objectfs.o

INCLUDES= -I.
CFLAGS = -O2 -Wall -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26 -g
LDFLAGS = $(CFLAGS) -lfuse

CC=gcc
LD=gcc

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(LD) -o $(PROGRAM) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(PROGRAM)
	rm -f *.o

