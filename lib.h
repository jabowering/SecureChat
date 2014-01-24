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
  functions bigendian64, bigendian16, littleendian64 and 
  littleendian16 were borrowed from the following website:
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
#ifndef _LIB_H
#define _LIB_H


/****************** Jakes additions*******************************************/
#define _POSIX_C_SOURCE 1

/* Macros for server and client modes.*/
#define SERVER 0
#define CLIENT 1

#include <stdint.h>
#include "common.h"
#include <string.h>
/*****************************************************************************/

#define MAXSOCK		100	/* let's (arbitrarily) support up to 100
				   sockets */
#define BACKLOG		10	/* let's allow 10 connections in the queue */


#define READ_BUF_SZ	65537	/* internal buffer size; use 16 bits + 1 (for
				   the NUL terminator) */

/* This structure maintains state between calls to readline/readn.  For each
   file descriptor that you use with this library, you must create one of
   these structures.  Before using this structure, you must pass it to
   FDSTAT_RESET. */
typedef struct _fdstat {
  /* used by buffered_read */
  int read_cnt;
  char *read_ptr;
  char read_buf[READ_BUF_SZ];
  /* used by readline */
  int n;
  size_t maxlen;
  /* used by readn */
  size_t nleft;
  size_t nread;
  /* used by readn and readline */
  char *ptr;
} fdstat;



/***************************Jakes additions***********************************/

/* External variable md5 is defined in lib.c.*/
extern byte_t md5[];

/* Structure for a packet. Includes fields for all of the required information.
   The length field can by a maximum of 2 bytes, hence the max size of the data
   field.*/
typedef struct packet{
  byte_t version;
  byte_t md[16];
  int64_t offset;
  uint16_t length; 
  byte_t data[65536];
} __attribute__((packed)) packet;
	
/* Functions as defined in lib.c*/	
void decrypt(int readfile, int pad);
void calc_md5(int f, byte_t c[]);
void encryptfront(int f, packet* p);
void encryptback(int f, packet* p);
void createpacket(int mo, packet *p, byte_t *md5, int f, byte_t *data, 
		  uint16_t len);
void d(int f, packet *p);
unsigned int loadbuf(byte_t* buf, packet* p, unsigned int count);
int connect_server(char* p);
int connect_client(char* p);

uint64_t bigendian64(uint64_t net_number);
uint16_t bigendian16(uint16_t net_number);
uint16_t littleendian16(uint16_t native_number);
uint64_t littleendian64(uint64_t native_number);
/*****************************************************************************/


/* This macro prepares a new fdstat structure for use with readline/readn. */
#define FDSTAT_RESET(st)	do {		\
    st.read_cnt = 0;				\
    st.read_ptr = NULL;				\
    st.read_buf[0] = '\0';			\
    st.n = 0;					\
    st.maxlen = 0;				\
    st.nleft = 0;				\
    st.nread = 0;				\
    st.ptr = NULL;				\
  } while (0)

/* ----------------------------------------------------------------------------
   readline:
   Read a single line from the file descriptor, up to the maximum length.
   The buffer must be allocated in advance, and it won't be NUL terminated.
   Arguments:
   int	file descriptor
   void *	buffer for storing the bytes
   size_t	maximum length
   fdstat *	state to maintain between calls
   Return values:
   -2		incomplete; would have blocked
   -1		error (see errno)
   0		EOF
   >0		bytes read (does not return partial lines)
   ---------------------------------------------------------------------------- */
ssize_t readline (int, void *, size_t, fdstat *);

#endif /* _LIB_H */
 
