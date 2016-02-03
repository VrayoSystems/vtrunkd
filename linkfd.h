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
 * linkfd.h,v 1.1.1.2.2.2.2.3 2006/11/16 04:03:26 mtbishop Exp
 */ 

#ifndef _LINKFD_H
#define _LINKFD_H

#define BREAK_ERROR -2
#define CONTINUE_ERROR -1
#define TRYWAIT_NOTIFY -3
#define LASTPACKETMY_NOTIFY -4
#define RESENDLIMIT_NOTIFY -5
#define NET_WRITE_BUSY_NOTIFY -5
#define SEND_Q_NOTIFY -6
#define HAVE_FAST_RESEND_FRAME -7

#define LINKFD_PID_DIR "/var/run/vtrunkd"
/* Priority of the process in the link_fd function */
/* Never set the priority to -19 without stating a good reason.
 *#define LINKFD_PRIO -19
 * Since the likely intent was just to give vtun an edge,
 * -1 will do nicely.
 */
#define LINKFD_PRIO -1
/* Frame alloc/free */
//                              len value
#define LINKFD_FRAME_RESERV sizeof(short)
//                              seq_num                        flag
#define LINKFD_FRAME_APPEND sizeof(unsigned long) + sizeof(unsigned short)

static inline void * lfd_alloc(size_t size)
{
     register char * buf;

     size += LINKFD_FRAME_RESERV + LINKFD_FRAME_APPEND;

     if( !(buf = malloc(size)) )
        return NULL;

     return buf+LINKFD_FRAME_RESERV; 
}

static inline void * lfd_realloc(void *buf, size_t size)
{
     unsigned char *ptr = buf;

     ptr  -= LINKFD_FRAME_RESERV;
     size += LINKFD_FRAME_RESERV;

     if( !(ptr = realloc(ptr, size)) )
        return NULL;

     return ptr+LINKFD_FRAME_RESERV; 
}

static inline void lfd_free(void *buf)
{
     unsigned char *ptr = buf;

     free(ptr-LINKFD_FRAME_RESERV);
}


static inline int check_force_rtt_max_wait_time(int chan_num, int *next_token_ms);

int linkfd(struct vtun_host *host, struct conn_info *ci, int ss, int conn_num);
/* Module */
struct lfd_mod {
   char *name;
   int (*alloc)(struct vtun_host *host);
   int (*encode)(int len, char *in, char **out);
   int (*avail_encode)(void);
   int (*decode)(int len, char *in, char **out);
   int (*avail_decode)(void);
   int (*free)(void);

   struct lfd_mod *next;
   struct lfd_mod *prev;
};

/* External LINKFD modules */

extern struct lfd_mod lfd_zlib;
extern struct lfd_mod lfd_lzo;
extern struct lfd_mod lfd_encrypt;
extern struct lfd_mod lfd_shaper;


unsigned int get_tcp_hash(char *buf, unsigned int *tcp_seq);

#endif
