
/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016  Andrew Gryaznov <realgrandrew@gmail.com>
   This file is dual-licensed to be compatible with 
   Vrayo Systems vtrunkd_helper, part of Vrayo Internet Combiner package

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
 * llist.h,v 1.1.1.2.6.1 2006/11/16 04:03:32 mtbishop Exp
 */ 

#ifndef _VTUN_FRAME_LLIST_H
#define _VTUN_FRAME_LLIST_H

#include <sys/time.h>
#include <stdint.h>
#include "const.h"

#define VTUN_FRAME_SIZE2 1536 // 3*512

struct frame_seq {
    char out[VTUN_FRAME_SIZE2];
    int len;
    unsigned long seq_num;
    unsigned long local_seq_num[MAX_TCP_PHYSICAL_CHANNELS];
    int rel_next; // relative pointer [TODO: make it short or even char!]
    int sender_pid; // okay as short?
    int chan_num;
    int physical_channel_num;
    struct timeval time_stamp;
    struct timeval flush_time;
    int current_rtt;
    uint32_t marker;
    int stub_counter; // amount of stub packets before this one to skip
    unsigned int shash; // stream hash (max W_STREAMS_AMT)
    int unconditional_write_flag;
};

struct frame_llist{
	int rel_head;
	int rel_tail;
    int length;
    int stub_total; // not controlled by standard methods; total stub packets in buffer 
};

void frame_llist_fill(struct frame_llist *l, struct frame_seq flist[], int len);
void frame_llist_init(struct frame_llist *l);
int frame_llist_empty(struct frame_llist *l);
int frame_llist_free(struct frame_llist *l, struct frame_llist *lfree, struct frame_seq flist[], int f);
int frame_llist_pull(struct frame_llist *lfree, struct frame_seq flist[], int *f);
void frame_llist_append(struct frame_llist *l, int f, struct frame_seq buf[]);
void frame_llist_prepend(struct frame_llist *l, int f, struct frame_seq buf[]);


#endif /* _VTUN_FRAME_LLIST_H */
