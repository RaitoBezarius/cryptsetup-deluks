TARGET=keyslot_test
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE -I ../../lib/
LDLIBS=-ljson-c -luuid -lgcrypt -ldevmapper -lpthread -lssh
CC=gcc

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS) ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ core $(TARGET)

.PHONY: clean
