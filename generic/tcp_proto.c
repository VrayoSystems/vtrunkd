/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016  Vrayo Systems Ltd. team,

   Vtrunkd has been derived from VTUN package by Maxim Krasnyansky. 
   vtun Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */

/*
 * tcp_proto.c,v 1.4.2.3.2.1 2006/11/16 04:04:35 mtbishop Exp
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "log.h"

int tcp_write(int fd, char *buf, int len)
{
     char *ptr;
     int bad_frame = len & ~VTUN_FSIZE_MASK;
#ifdef BAD_LOCAL_SEQ_LOG_TCP
     if (bad_frame == 0) {
         vlog(LOG_INFO, "tcp local_seqnum %lu regular packet", ntohl(*((uint32_t *) (&buf[len - 3 * sizeof(uint32_t) - sizeof(uint16_t)]))));
     } else if(bad_frame == VTUN_BAD_FRAME) {
         int flag_var = 0;
         memcpy(&flag_var, buf + sizeof(uint32_t), sizeof(uint16_t));
         if (ntohs(flag_var) == FRAME_REDUNDANCY_CODE) {
             vlog(LOG_INFO, "tcp local_seqnum %lu sum packet", ntohl(*((uint32_t *) (&buf[len - 4 * sizeof(uint32_t)]))));
         }
     } else  {
         vlog(LOG_INFO, "tcp local_seqnum other");
     }
#endif
     ptr = buf - sizeof(uint16_t);

     *((uint16_t *)ptr) = htons(len);
     len  = (len & VTUN_FSIZE_MASK) + sizeof(uint16_t);

     return write_n(fd, ptr, len);
}

int tcp_read(int fd, char *buf)
{
     uint16_t len, flen;
     int rlen;

     /* Rad frame size */
     if( (rlen = read_n(fd, (char *)&len, sizeof(uint16_t)) ) <= 0) {
#ifdef DEBUGG
        vlog(LOG_ERR, "Null-size or -1 frame length received len %d", rlen); // TODO: remove! OK on client connect error
#endif
          return rlen;
     }

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ){
     	/* Oversized frame, drop it. */ 
        while( flen ){
	   len = min(flen, VTUN_FRAME_SIZE);
           if( (rlen = read_n(fd, buf, len)) <= 0 )
	      break;
           flen -= rlen;
        }
        vlog(LOG_ERR, "Oversized frame received %hd", flen); // TODO: remove!
	return VTUN_BAD_FRAME;
     }	

     if( len & ~VTUN_FSIZE_MASK ){
	/* Return flags */
        read_n(fd, buf, flen);
	return len;
     }

     /* Read frame */
     return read_n(fd, buf, flen);
}
