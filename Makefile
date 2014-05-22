CC=gcc
CFLAGS=-Wall
OBJ=client-dtls.o client-dtls-resume.o client-dtls-nonblocking.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: client-udp client-dtls client-dtls-resume client-dtls-nonblocking

client-dtls-nonblocking: client-dtls-nonblocking.c
	$(CC) -DCYASSL_DTLS -DDEBUG_CYASSL -o client-dtls-nonblocking client-dtls-nonblocking.c -lcyassl

client-dtls-resume: client-dtls-resume.c
	$(CC) -DCYASSL_DTLS -DDEBUG_CYASSL -o client-dtls-resume client-dtls-resume.c -lcyassl

client-dtls: client-dtls.c
	$(CC) -DCYASSL_DTLS -DDEBUG_CYASSL -o client-dtls client-dtls.c -lcyassl

client-udp: client-udp.c
	$(CC) -o client-udp client-udp.c

.PHONY: clean

clean:
	-rm -f *.o client-dtls-nonblocking
	-rm -f *.o client-dtls-resume
	-rm -f *.o client-udp
	-rm -f *.o client-dtls

