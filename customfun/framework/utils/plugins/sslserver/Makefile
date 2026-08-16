CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -pedantic -I/usr/local/include -L/usr/local/lib
LDFLAGS = -lssl -lcrypto

all: ssl_server

ssl_server: ssl_server.c ssl_server.h
	$(CC) $(CFLAGS) -o ssl_server.exe ssl_server.c $(LDFLAGS)

clean:
	rm -f ssl_server