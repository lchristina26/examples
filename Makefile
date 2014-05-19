%.o: %.c 
	$(CC) $(CFLAGS) -c $< -o $@

UDPclient: UDPclient.c
	$(CC) -Wall -o UDPclient UDPclient.c -I ../include -lm -lcyassl
	
.PHONY: clean

clean:
	-rm -f *.o UDPclient
