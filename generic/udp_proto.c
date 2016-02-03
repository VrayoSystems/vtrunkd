/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016  Vrayo Systems Ltd. team

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
 * udp_proto.c,v 1.5.2.3.2.1 2006/11/16 04:04:43 mtbishop Exp
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
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
#include <netinet/udp.h>
#endif

#include "vtun.h"
#include "lib.h"

//#define BAD_LOCAL_SEQ_LOG 1

uint32_t previous_local_seq_num = 0;

/* Functions to read/write UDP frames. */
int udp_write(int fd, char *buf, int len)
{
     register char *ptr;
     register int wlen;
    int bad_frame = len & ~VTUN_FSIZE_MASK;
#ifdef BAD_LOCAL_SEQ_LOG
    if (bad_frame == 0) {
        uint32_t local_seq_num = ntohl(*((uint32_t *) (&buf[len - 3 * sizeof(uint32_t) - sizeof(uint16_t)])));
        if ((previous_local_seq_num) && ((previous_local_seq_num + 1) != local_seq_num)) {
            vtun_syslog(LOG_INFO, "udp local_seqnum %lu prev %lu regular packet", local_seq_num, previous_local_seq_num);
        }
        if (local_seq_num)
            previous_local_seq_num = local_seq_num;
    } else if (bad_frame == VTUN_BAD_FRAME) {
        int flag_var = 0;
        memcpy(&flag_var, buf + sizeof(uint32_t), sizeof(uint16_t));
        flag_var = ntohs(flag_var);
        if (flag_var == FRAME_REDUNDANCY_CODE) {
            uint32_t local_seq_num = ntohl(*((uint32_t *) (&buf[len - 4 * sizeof(uint32_t)])));
            if ((previous_local_seq_num) && ((previous_local_seq_num + 1) != local_seq_num)) {
                vtun_syslog(LOG_INFO, "udp local_seqnum %lu prev %lu sum packet", local_seq_num, previous_local_seq_num);
            }
            if (local_seq_num)
                previous_local_seq_num = local_seq_num;
        }
        if (flag_var == FRAME_CHANNEL_INFO) {
            uint32_t local_seq_num = ntohl(*((uint32_t *) (&buf[4 * sizeof(uint16_t) + sizeof(uint32_t)])));
            if ((previous_local_seq_num) && ((previous_local_seq_num + 1) != local_seq_num)) {
                vtun_syslog(LOG_INFO, "udp local_seqnum %lu prev %lu FCI", local_seq_num, previous_local_seq_num);
            }
            if (local_seq_num)
                previous_local_seq_num = local_seq_num;
        }
    } else {
//        vtun_syslog(LOG_INFO, "udp local_seqnum other");
    }
#endif

     ptr = buf - sizeof(uint16_t);

     *((uint16_t *)ptr) = htons(len);
     len  = (len & VTUN_FSIZE_MASK) + sizeof(uint16_t);

     while( 1 ){
	if( (wlen = write(fd, ptr, len)) < 0 ){ 
	   if( errno == EAGAIN || errno == EINTR )
	      continue;
	   if( errno == ENOBUFS )
	      return 0;
	}
	/* Even if we wrote only part of the frame
         * we can't use second write since it will produce 
         * another UDP frame */  
        return wlen;
     }
}

int udp_read(int fd, char *buf)
{
     uint16_t hdr, flen;
     struct iovec iv[2];
     register int rlen;

     /* Read frame */
     iv[0].iov_len  = sizeof(uint16_t);
     iv[0].iov_base = (char *) &hdr;
     iv[1].iov_len  = VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
     iv[1].iov_base = buf;

     while( 1 ){
        if( (rlen = readv(fd, iv, 2)) < 0 ){ 
	   if( errno == EAGAIN || errno == EINTR )
	      continue;
	   else
     	      return rlen;
	}
        hdr = ntohs(hdr);
        flen = hdr & VTUN_FSIZE_MASK;

        if( rlen < 2 || (rlen-2) != flen )
	   return VTUN_BAD_FRAME;

	return hdr;
     }
}		
