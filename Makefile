all:
	g++ crypto.cpp crypto_utils.cpp -o crypto -std=c++11 -L/usr/lib -lssl -lcrypto
