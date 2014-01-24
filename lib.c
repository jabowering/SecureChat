/*-----------------------------------------------------------------------------

  # Student's Name: Jakob Bowering
  # CMPUT 361
  # Student's Unix Login: boweringj
  # Assignment #1
  # Program Name: sc
  # File Name: lib.c
  # Instructor's Name: Nicholas Boers
  # Acknowledgements: The function readline and its associated helper functions 
  and types were provided. I did not modify them. The 
  functions connect_server and connect_client are based on 
  the provided server.c. I modified parts of them to work 
  with my application. The functions bigendian64, bigendian16, 
  littleendian64 and littleendian16 were borrowed from the 
  following website: 
  http://sourceforge.net/p/predef/wiki/Endianness/ 
  I modified only the type. The md5 libraries md5.h md5.c and 
  md5.common were provided. I did not modify them. The header 
  file is based on the one provided for the assignment. The 
  changes and additions I made are indicated.
  *----------------------------------------------------------------------------*/



/* ============================================================================
   Course: CMPT 361
   Author: Nicholas Boers
   Date: Sept. 2013

   Version: 1.01

   Functions that may prove useful for non-blocking I/O.

   Acknowledgements:
   Parts of 'buffered_read' and 'readline' copied/inspired by readline.c and
   readn.c in UNIX Network Programming.
   http://www.kohala.com/start/unpv12e.html
   ============================================================================ */

#define _POSIX_C_SOURCE 1

/* Import the following external libraries.*/
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <strings.h>

/* Import these local headers.*/
#include "md5.h"
#include "common.h"
#include "lib.h"

/* Define the external variable md5 from lib.h*/
byte_t md5[16];

/* Sets up a single packet using the packet type. Each field is initialized before
   the packet is sent for encryption.*/
void createpacket(int mo, packet *p, byte_t* md5, int f, byte_t *data, uint16_t len){
	
  for(int i = 0; i < 16; i++)
    p->md[i] = md5[i];
   		
  p->version = (byte_t) 1;

  p->length = len; 
	
  /* Data is length bytes long.*/
  for(int i = 0; i < p->length; i++)
    p->data[i] = data[i];

  /* If defined as client*/
  if(mo == CLIENT)
    encryptfront(f, p);
	
  /* If defined as server*/
  if(mo == SERVER)
    encryptback(f, p);
}

/* Loads the write buffer buf by calculating the size of each packet p and moving 
   it into buff.*/
unsigned int loadbuf(byte_t* buf, packet* p, unsigned int count){

  /* i is the actual size of the packet including data.*/
  unsigned int i = p->length + (((unsigned char*)&p->data) - ((unsigned char*)p));
  memmove(&buf[count], p, i);
	
  /* Returns the number of bytes in a packet.*/
  return (i);
}

/* Calculate the MD5 checksum of the file descriptor f and store it in buffer c.*/
void calc_md5(int f, byte_t c[]){

  /* Create the provided structs, start md5 calculation and add 64 bytes at a 
     time.*/
  struct md5CTX m;
  struct md5CTX* md5 = &m;
     	
  md5Start(md5);
 	
  size_t count = 1;
  while(count){
        
    byte_t* buf = calloc(64, 1);
    if(buf == NULL){
      fprintf(stdout, "Memory error\n");
      exit(1);
    }	
    count = read(f, buf, 64);  	
    md5Add(md5, buf, count);
    free(buf);
  }
 	
  /* End the md5 calculation and store each byte in c.*/
  md5End(md5, c);
}

/* If the current session is a client, read chunks of the pad p->length bytes 
   at a time starting at 0 and xor them for encryption. Each piece of the pad 
   is used only once providing unbreakable encryption.*/
void encryptfront(int f, packet* p){

  byte_t *newpad = calloc(p->length, 1);
  if(newpad == NULL){
    fprintf(stdout, "Memory error\n");
    exit(1);
  }
		
  /* Set the file descriptor to the beginning of the pad.*/
  p->offset = lseek(f, 0, SEEK_CUR);
  size_t count = read(f, newpad, p->length);

  int j;
  for(j = 0; j < count; j++)
    p->data[j] = p->data[j] ^ newpad[j];

  printf("\n");
  free(newpad);

  /* The offset and length fields of a packet must be converted to big endian
     before being sent over the network.*/
  p->offset = bigendian64(p->offset);
  p->length = bigendian16(p->length);	
}

/* If the current session is a server, read chunks of the pad p->length bytes 
   at a time starting at the end and xor them for encryption. Each piece of the 
   pad is used only once providing unbreakable encryption.*/
void encryptback(int f, packet* p){

  byte_t *newpad = calloc(p->length, 1);
  if(newpad == NULL)
    exit(1);
	
  /* Set the file descriptor to p->length bytes from the end of the pad.*/
  int cur = lseek(f, p->length*(-1), SEEK_CUR);
  int end = lseek(f, 0, SEEK_END);
	
  /* The offset is now a negative number that will be interpreted as 
     required.*/
  p->offset = cur - end;

  lseek(f, p->offset, SEEK_END);
  size_t count = read(f, newpad, p->length);

  int j;
  for(j = 0; j < count; j++) 	
    p->data[j] = p->data[j] ^ newpad[j];

  printf("\n");
  lseek(f, (-1)*p->length, SEEK_CUR);
  free(newpad);

  /* The offset and length fields of a packet must be converted to big endian
     before being sent over the network.*/
  p->offset = bigendian64(p->offset);
  p->length = bigendian16(p->length);

}


/* Code taken from http://sourceforge.net/p/predef/wiki/Endianness/
   modified only the type from int to uint64_t.*/
uint64_t bigendian64(uint64_t net_number){
  uint64_t result = 0;
  int i;

  for (i = 0; i < (int)sizeof(result); i++) {
    result <<= CHAR_BIT;
    result += (((unsigned char *)&net_number)[i] & UCHAR_MAX);
  }
  return result;
}


/* Code taken from http://sourceforge.net/p/predef/wiki/Endianness/
   modified only the type from int to uint16_t.*/
uint16_t bigendian16(uint16_t net_number){
  uint16_t result = 0;
  int i;

  for (i = 0; i < (int)sizeof(result); i++) {
    result <<= CHAR_BIT;
    result += (((unsigned char *)&net_number)[i] & UCHAR_MAX);
  }
  return result;
}

// Code taken from http://sourceforge.net/p/predef/wiki/Endianness/
// modified only the type from int to uint64_t.
uint64_t littleendian64(uint64_t native_number)
{
  uint64_t result = 0;
  int i;

  for (i = (int)sizeof(result) -1; i >= 0; i--) {
    ((unsigned char *)&result)[i] = native_number & UCHAR_MAX;
    native_number >>= CHAR_BIT;
  }
  return result;
}

/* Code taken from http://sourceforge.net/p/predef/wiki/Endianness/
   modified only the type from int to uint16_t.*/
uint16_t littleendian16(uint16_t native_number){
  uint16_t result = 0;
  int i;

  for (i = (int)sizeof(result) -1; i >= 0; i--) {
    ((unsigned char *)&result)[i] = native_number & UCHAR_MAX;
    native_number >>= CHAR_BIT;
  }
  return result;
}

/* Build a packet from received bytes and pass it to a function to decrypt the
   data.*/
void decrypt(int fd, int pad){

  /* Position the file descriptor at the start of the pad.*/
  lseek(fd, 0, SEEK_SET);	
  packet p;
  read(fd, &p.version, 1); 		
  read(fd, &p.md, 16);  			
  read(fd, &p.offset, 8);		
  read(fd, &p.length, 2);  			
  read(fd, &p.data, p.length);

  /* Pass the created packet to d for decryption.*/
  d(pad, &p);	
}

/* Decrypt the encrypted data and print to standard out.*/
void d(int pad, packet* p){

  /* Check remote md5 sum and ensure it matches the local value stored in 
     external variable md5. If not the application exits.*/
  for(int i = 0; i < 16; i++){
    if(md5[i] != p->md[i]){
      fprintf(stderr, "The MD5 sums do not match. Terminating.\n");
      exit(1);
    }
  }

  /* Convert the length and offset fields back to little endian.*/
  p->offset = littleendian64(p->offset);
  p->length = littleendian16(p->length);

  byte_t *newpad = calloc(p->length, 1);
  if(newpad == NULL){
    fprintf(stdout, "Memory error\n");
    exit(1);
  }
		
  /* Depending on weather the offset it positive or negative, read from the 
     beginning or end of the pad. Read a chunk length bytes long and xor it
     against the data for decryption.*/
  if(p->offset < 0)
    lseek(pad, p->offset, SEEK_END);
			
  else
    lseek(pad, p->offset, SEEK_SET);
		
  size_t count = read(pad, newpad, p->length);
  for(int j = 0; j < count; j++){
   	
    p->data[j] = p->data[j] ^ newpad[j];
    printf("%c", p->data[j]);
  }
   	
  printf("\n");
  free(newpad);
}






/* Code borrowed and modified from Nicks server.c It creates, binds, and 
   listens to as many sockets as possible. Once a connection is made it accepts 
   and returns the file descriptor of the connected socket so the client and 
   server can use it for "peer to peer" communication.*/
int connect_server(char* p){

  struct addrinfo hints, *results, *iter;
  char *port = p;

  /* when creating a server, we may end up listening on multiple
     sockets at the same time; let's create an array where we can store
     each socket that we create */
  int sock[MAXSOCK];
  /* counter to keep track of how many we've created */
  int nsock;

  /* prepare the hints structure for getaddrinfo; this structure provides
     hints about the type of socket that we'd like to use */
  bzero (&hints, sizeof (struct addrinfo));
  /* accept any protocol family supported by the operating system */
  hints.ai_family = PF_UNSPEC;
  /* accept only connection-oriented, e.g., TCP, socket types */
  hints.ai_socktype = SOCK_STREAM;
  /* indicate that we'll use the returned structure in calls to bind
     for creating a listening socket */
  hints.ai_flags = AI_PASSIVE;

  /* using the prepared hints, call getaddrinfo to obtain a linked list
     of "struct addrinfo" elements; we will use these elements to
     create and configure each socket:
     hostname: NULL because we're creating a server
     servname: the user-specified port
     hints:    pointer to the prepared hints structure
     res:      pointer to a pointer to an addrinfo struct */
  if (getaddrinfo (NULL, port, &hints, &results) != 0) {
    fprintf (stderr, "getaddrinfo failed\n");
    exit (1);
  }

  /* walk the returned linked list element-by-element */
  nsock = 0;
  for (iter = results; iter != NULL && nsock < MAXSOCK; iter = iter->ai_next) {
    int sd;

    /* create a new unnamed (unbound) socket */
    if ((sd = socket (iter->ai_family,
		      iter->ai_socktype,
		      iter->ai_protocol)) == -1){
      /* failed; we didn't create anything, so let's simply try
	 the next element */

      fprintf(stderr, "Socket create failure\n");

      continue;
    }
    int val = 1;

    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if(iter->ai_family == AF_INET6)
      setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

    /* bind the unnamed socket to an address/port;
       for the address and its length, we can use values obtained
       through getaddrinfo */
    if (bind (sd, iter->ai_addr, iter->ai_addrlen) == -1) {
      /* failed; clean up the socket and try the next element */
      close (sd);
      continue;
    }
    /* listen for connections on our just-bound socket */
    if (listen (sd, BACKLOG) == -1){ 

      /* failed; clean up the socket and try the next element */
      close (sd);
      continue;
    }

    /* success; let's copy the temporary (sock) variable to our
       array of socket descriptors */
    sock[nsock] = sd;
	
    nsock++;
  }

  /* check whether all calls failed... */
  if (nsock == 0) {
    fprintf (stderr, "%s: unable to create socket\n", p);
    exit (1);
  }

  /* once we've created all of the sockets, free the memory
     associated with the linked list */
  freeaddrinfo (results);

  /* now we can accept connections and then read/write data...
     calls to accept block if there are no incoming connections; for
     that reason, you should use select on all of the server's
     sockets and only call accept on a socket once you can read
     from the socket */      
       
  /* Set up an array of bits for file descriptors. Zeroize and listen on 
     each socket that was created.*/
  fd_set rfds;
  FD_ZERO(&rfds);
  int fdmax = 0;
  int newfd;	  
	  
  /* Loop until a connection is made.*/
  while (1) {
   
  Retry:
       	
    /* Set each created socket.*/
    for(int i = 0; i < nsock; i++){
      FD_SET (sock[i], &rfds);
      if(sock[i] > fdmax)
	fdmax = sock[i];
    }

    /* Block until there is I/O. In this case a connection request.*/
    if ((select (fdmax + 1, &rfds, NULL, NULL, NULL)) == -1) {
      if (errno == EINTR)
	goto Retry;
      perror ("select");
      exit (1);
    }
		
    /* Accept all connections requested.*/
    for(int i = 0; i <= nsock; i++){		 
      if (FD_ISSET(sock[i], &rfds)){ 
	newfd = accept(sock[i], NULL, NULL);
 				
	if (newfd == -1) 
	  perror("accept");
	else{
	  for(int i = 0; i < nsock; i++)
	    close(sock[i]);
                		
	  /* Return the connected file descriptor.*/
	  return newfd;            	
	}   	 		
      }    	  			
    }
  }
  return -1;
}

/* Code borrowed and modified from Nicks server.c It creates a socket and 
   connects to a server. Once the connection is made it returns the file 
   descriptor of the connected socket so the client and server can use it for 
   "peer to peer" communication.*/
int connect_client(char* p){

  struct addrinfo hints, *results, *iter;
  char *port = p;

  /* when creating a server, we may end up listening on multiple
     sockets at the same time; let's create an array where we can store
     the socket that we create */
  int nsock; 

  /* prepare the hints structure for getaddrinfo; this structure provides
     hints about the type of socket that we'd like to use */
  bzero (&hints, sizeof (struct addrinfo));
  /* accept any protocol family supported by the operating system */
  hints.ai_family = PF_UNSPEC;
  /* accept only connection-oriented, e.g., TCP, socket types */
  hints.ai_socktype = SOCK_STREAM;
  /* the socket will be used to connect to a server.*/
  hints.ai_flags = 0;

  /* using the prepared hints, call getaddrinfo to obtain a linked list
     of "struct addrinfo" elements; we will use these elements to
     create and configure each socket:
     hostname: NULL because we're creating a server
     servname: the user-specified port
     hints:    pointer to the prepared hints structure
     res:      pointer to a pointer to an addrinfo struct */
  if (getaddrinfo (NULL, port, &hints, &results) != 0) {
    fprintf (stderr, "getaddrinfo failed\n");
    exit (1);
  }

  /* walk the returned linked list element-by-element */
  nsock = 0;
  for (iter = results; iter != NULL && nsock < MAXSOCK; iter = iter->ai_next) {
    int sd;

    /* create a new socket */
    if ((sd = socket (iter->ai_family,
		      iter->ai_socktype,
		      iter->ai_protocol)) == -1)
      /* failed; we didn't create anything, so let's simply try
	 the next element */
      continue;

    /* Attempt to connect the socket to a server.*/
    if (connect (sd, iter->ai_addr, iter->ai_addrlen) == -1) {
      /* failed; clean up the socket and try the next element */
      close (sd);
      continue;
    }

    nsock = sd;
  }

  /* check whether all calls failed... */
  if (nsock == 0) {
    fprintf (stderr, "%s: unable to connect.\n", p);
    exit (1);
  }
	 

  /* once we've created all of the sockets, free the memory
     associated with the linked list */
  freeaddrinfo (results);
   
  /* Return the connected socket.*/
  return nsock;
}


/*****************************************************************************/
/* type used internally for calls to is_ready */
typedef enum _io_type_t { 
  TEST_READ,
  TEST_WRITE,
  TEST_EXCEPTION
} io_type_t;

/* ----------------------------------------------------------------------------
   is_ready:
   Determine whether a file descriptor is ready for the indicated operation,
   i.e., it won't block for the operation.
   Arguments:
   int	file descriptor to check
   io_type_t	type of test: TEST_READ, TEST_WRITE, or TEST_EXCEPTION
   Return values:
   -1		error (see errno)
   0		file descriptor is not ready for reading
   1		file descriptor is ready for reading
   ---------------------------------------------------------------------------- */
static int is_ready (int fd, io_type_t type)
{
  struct timeval tv = { 0, 0 };	/* use a timeout of 0 */
  fd_set fds;
  int rdy;

 Retry:
  FD_ZERO (&fds);
  FD_SET (fd, &fds);
  rdy = select (fd + 1,
		type == TEST_READ      ? &fds : NULL,
		type == TEST_WRITE     ? &fds : NULL,
		type == TEST_EXCEPTION ? &fds : NULL,
		&tv);
  if (rdy == -1) {
    if (errno == EINTR)
      goto Retry;
    return -1;
  }

  return rdy;
}

/* ----------------------------------------------------------------------------
   buffered_read:
   Obtain the next byte from a file descriptor, using a buffer to improve
   the performance.
   Arguments:
   fd		file descriptor to read
   ptr	location to save single character
   st		state used with this file descriptor
   Return values:
   -2		would have blocked
   -1		error (see errno)
   0		EOF
   1		byte saved at ptr
   ---------------------------------------------------------------------------- */
static ssize_t buffered_read(int fd, char *ptr, fdstat *st)
{
  /* if we do not have buffered data... */
  if (st->read_cnt <= 0) {
    /* check whether the descriptor will block for a read */
    switch (is_ready (fd, TEST_READ)) {
    case -1:
      return -1; /* error */
    case 0:
      return -2; /* try later */
    }

    /* read the data (will *not* block) */
  Retry:
    if ((st->read_cnt = read (fd, st->read_buf,
			      sizeof (st->read_buf))) < 0) {
      if (errno == EINTR)
	goto Retry;
      /* error */
      return -1;
    } else if (st->read_cnt == 0) {
      /* EOF */
      return 0;
    }

    /* update our pointer */
    st->read_ptr = st->read_buf;
  }

  /* provide a byte of buffered data */
  st->read_cnt--;
  *ptr = *(st->read_ptr)++;

  return 1;
}

/* ----------------------------------------------------------------------------
   readline
   ---------------------------------------------------------------------------- */
ssize_t readline (int fd, void *vptr, size_t maxlen, fdstat *st)
{
  int rc, n;
  char c;

  if (st->ptr == NULL) {
    /* set the pointer, which we'll iterate through the string, only
       on the first call */
    st->ptr = vptr;
    st->maxlen = maxlen;
    st->n = 1;
  }
  for (; st->n < st->maxlen; (st->n)++) {
    if ((rc = buffered_read (fd, &c, st)) == 1) {
      /* obtained one byte */
      *(st->ptr)++ = c;
      if (c == '\n')
	break; /* newline is stored, like fgets() */
    } else if (rc == 0) {
      /* EOF */
      return 0;
    } else if (rc == -2) {
      /* would block */
      return -2;
    } else
      /* error, errno set by read() */
      return -1;
  }

  /* null terminate like fgets() */
  *(st->ptr) = '\0';

  n = st->ptr - (char *)vptr;

  /* setting st->ptr to NULL will cause next call to reset
     the necessary state variables */
  st->ptr = NULL;

  return (n);
}


 
