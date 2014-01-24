/*-----------------------------------------------------------------------------

  # Student's Name: Jakob Bowering
  # CMPT 361
  # Student's Unix Login: boweringj
  # Assignment #1
  # Program Name: sc
  # File Name: sc.c
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

#define _POSIX_C_SOURCE 1

/* Import the following external libraries.*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

/* Include the lib.h header.*/
#include "lib.h"

int main(int argc, char* argv[]){

  /* Mode defines if the program will run as a server or client. One of the 
     macros defined in lib.h is used. It will be either SERVER or CLIENT.*/
  int mode;
	
  /* Rover is a file desriptor for for the pad. It is called rover because it 
     is not confined to reading in a linear fashion from front to back or 
     back to front. It goes all over the place.*/
  int rover;
  if((argc != 3 || (rover = open(argv[1], O_RDONLY)   ) == -1) ){	
    fprintf(stderr, "Invalid arguments. Try again.\n");
    exit(1);
  }
   	
  /*fd for reading from the front or back of the pad depending on mode. It 
    reads only in a linear way.*/
  int read_data = open(argv[1], O_RDONLY);
   	
  /* Get the md5 sum.*/
  calc_md5(rover, md5);
   	
  /* Attempt to get 2 tokens from args[]. If there are two -> client, if there 
     is 1 ->server.*/
  char *t1;
  char *t2;
  t1 = strtok(argv[2], ":");
  if((t2 = strtok(NULL, " ")) == NULL){
    printf("THIS IS A SERVER\nport: %s\n", t1);
    mode = SERVER;
  }
  else {
    printf("THIS IS A CLIENT\nhost: %s\nport: %s\n", t1, t2);
    mode = CLIENT;
  }	

  /* If CLIENT read from the front of the pad.*/
  if(mode == CLIENT)
    lseek(read_data, 0, SEEK_SET);
  /* If server read from the back of the pad.*/
  else
    lseek(read_data, 0, SEEK_END);
    		
  /* J holds the connected file descriptor for reading and writing to.*/
  int j;		

  /* Set j if a server.*/
  if(mode == SERVER)
    j = connect_server(t1);
    	
  /* Set j if a client.*/
  if(mode == CLIENT)
    j = connect_client(t2);
    	  	
  /* Create a large buffer to store multiple packets in the event that data 
     is entered faster than it can be written to the socket.*/
  byte_t hugebuf[sizeof(packet) * 20] = {0};
    
  /* buf_count controls where bytes are entered into hugebuf. It also 
     determines weather or not the write fd is set.*/
  unsigned int buf_count = 0;
   	
  /* Linebuffer to store a line returned from readline.*/
  byte_t linebuf[65536];
   	  	
  /* Test packet is pre loaded into the buffer and is sent on start up.*/
  packet test_packet;
  createpacket(mode, &test_packet, md5, read_data, linebuf, 0);  
  buf_count += loadbuf(hugebuf, &test_packet, buf_count);

  /* create read and write fd sets.*/
  fd_set r;
  fd_set w;
    
  /* Loop until program termination.*/
  while(1){
    
  Retry:

    /* Zero the sets.*/
    FD_ZERO(&w);
    FD_ZERO(&r);

    /* Set standard in and the connected fd j for reading. Set j for writing
       only if there is data in hugebuf.*/
    FD_SET(j, &r);
    FD_SET(0, &r);
    if(buf_count != 0)
      FD_SET(j, &w);
    
    /* Block until an fd is ready for I/O.*/
    if ((select (j + 1, &r, &w, NULL, NULL)) == -1) {
      if (errno == EINTR)
	goto Retry;
      perror ("select");
      exit (1);
    }
 				 
    /* If there is data on the connected socket send them to decrypt for 
       packet formulation and decryption.*/
    if (FD_ISSET(j, &r))  		
      decrypt(j, rover);
     		
    /* If there is input at standard in, read it, create packets and load 
       them into the buffer.*/
    if (FD_ISSET(0, &r)){ 
   	
      fdstat fd;
      FDSTAT_RESET (fd);
      packet p;
      int len = readline(0, linebuf, sizeof(linebuf), &fd);
      if(len == 0)
	exit(0);
      createpacket(mode, &p, md5, read_data, linebuf, len);  
      buf_count += loadbuf(hugebuf, &p, buf_count);
    }
  			
    /* If there is data in the buffer attempt to empty the buffer to j. If 
       the buffer is not emptied move remaining bytes in the buffer to the 
       beginning of the buffer.*/
    if(FD_ISSET(j, &w)){
  			
      int n = write(j, hugebuf, buf_count);
      if(n == buf_count)
	buf_count = 0;
      else if(n != buf_count){
	buf_count -= n;
	memmove(hugebuf, &hugebuf[n], buf_count);
      }
    }
  } 
  return 0;
}  
 
