CC=gcc
LIBSOCKET=-lnsl
CCFLAGS=-Wall -g
DNS_SRV=server
DNS_CLT=dnsclient

all: $(DNS_CLT)

run: $(DNS_CLT)
	./$(DNS_CLT) www.google.com A
$(DNS_CLT):	$(DNS_CLT).c
	$(CC) -o $(DNS_CLT) $(LIBSOCKET) $(DNS_CLT).c

clean:
	rm -f *.o *~
	rm -f $(DNS_CLT)