CC=gcc
CFLAGS=-Wall
OBJ=client-dtls.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: client-udp client-dtls

client-dtls: client-dtls.c
	$(CC) -DCYASSL_DTLS -DDEBUG_CYASSL -o client-dtls client-dtls.c -lcyassl

client-udp: client-udp.c
	$(CC) -o client-udp client-udp.c

.PHONY: clean

clean:
	-rm -f *.0 client-udp
	-rm -f *.o client-dtls

