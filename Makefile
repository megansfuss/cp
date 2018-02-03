CC=g++
CFLAGS=-std=c++11
LDFLAGS=-L/usr/lib
LDLIBS=-lssl -lcrypto

all:
	$(CC) $(CFLAGS) crypto.cpp crypto_utils.cpp -o crypto $(LDFLAGS) $(LDLIBS)
