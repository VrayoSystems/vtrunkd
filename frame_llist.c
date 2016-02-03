
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
 * llist.c,v 1.1.1.2.6.1 2006/11/16 04:03:29 mtbishop Exp
 */ 

#include <stdlib.h>
#include <string.h>
#include "frame_llist.h"

/* Function to work with the Linked Lists */



void frame_llist_init(struct frame_llist *l) {
    l->rel_head = l->rel_tail = -1;
    l->length = 0;
    l->stub_total = 0;
} 

void frame_llist_fill(struct frame_llist *l, struct frame_seq flist[], int len)
{
    int i;
    l->rel_head = 0;
    l->length = 0;
    for (i = 0; i < (len - 1); i++) {
        flist[i].rel_next = i + 1;
    }
    flist[len - 1].rel_next = -1;
    l->rel_tail = len - 1;
    l->length = len;
} 


int frame_llist_empty(struct frame_llist *l)
{
	return l->rel_tail == -1;
}


int frame_llist_pull(struct frame_llist *lfree, struct frame_seq flist[], int *f)
{
	if(lfree->rel_head == -1) { // no more chunks available
		return -1; 
	}
    lfree->length--;
	*f = lfree->rel_head;
	lfree->rel_head = flist[lfree->rel_head].rel_next;
    if (lfree->rel_head == -1)
        lfree->rel_tail = -1;
    flist[(*f)].rel_next = -1; // make sure to set it!
    return 0;
}

void frame_llist_append(struct frame_llist *l, int f, struct frame_seq buf[]) {
    if(l->rel_tail > -1) {
          buf[l->rel_tail].rel_next = f;
          l->rel_tail = f;
    } else {
          l->rel_tail = l->rel_head = f;
    }
    buf[f].rel_next = -1;
    l->length++;
}


void frame_llist_prepend(struct frame_llist *l, int f, struct frame_seq buf[]) {
    if(l->rel_head > -1) {
          buf[f].rel_next = l->rel_head;
          l->rel_head = f;
    } else {
          l->rel_tail = l->rel_head = f;
          buf[f].rel_next = -1;
    }
    l->length++;
}


/* free a frame into free list */
int frame_llist_free(struct frame_llist *l, struct frame_llist *lfree, struct frame_seq flist[], int f)
{	
	int i = l->rel_head, n, prev=-1;
	int icbt = 0;
	if(i<0) return i;

	while( i > -1 ){
	   n = flist[i].rel_next; 	
	   if( f == i ) {
		if(f == l->rel_head) {
			l->rel_head = n;
		} else {
			flist[prev].rel_next = n;
		}
		if(lfree->rel_head == -1)
			lfree->rel_head = lfree->rel_tail = f;
		else
			flist[lfree->rel_tail].rel_next = f;
		lfree->rel_tail = f;
		flist[f].rel_next = -1;
		break;
	   }
	   prev = i;
	   i = n;
	   if( (icbt++) > 2000) break; // TODO: logging???
	}
	return 0;
} 

