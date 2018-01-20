CC=g++
CFLAGS=-std=c++11
LDFLAGS=-L/usr/lib
LDLIBS=-lssl -lcrypto

all: set1 set2

set1:
	$(CC) $(CFLAGS) crypto1.cpp crypto_utils.cpp -o crypto1 $(LDFLAGS) $(LDLIBS)

set2:
	$(CC) $(CFLAGS) crypto2.cpp crypto_utils.cpp -o crypto2 $(LDFLAGS) $(LDLIBS)
