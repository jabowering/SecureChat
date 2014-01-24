CC = gcc

CFLAGS = -std=c99 -g -Wall -pedantic 

all: sc

sc: md5.o sc.o lib.o
	$(CC) -o sc sc.o md5.o lib.o

md5.o: md5.c md5.h common.h
	$(CC) $(CFLAGS) -c md5.c 

lib.o: lib.c lib.h
	$(CC) $(CFLAGS) -c lib.c

sc.o: sc.c md5.h lib.h
	$(CC) $(CFLAGS) -c sc.c

clean:
	$(RM) sc md5.o lib.o sc.o


