
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
 * llist.h,v 1.1.1.2.6.1 2006/11/16 04:03:32 mtbishop Exp
 */ 

#ifndef _VTUN_LLIST_H
#define _VTUN_LLIST_H

struct llist_element {
	struct llist_element * next;
	void * data;
};
typedef struct llist_element llist_elm;

typedef struct {
	llist_elm * head;
	llist_elm * tail;
} llist;


void llist_init(llist *l);
int  llist_add(llist *l, void *d);
int  llist_empty(llist *l);
void * llist_trav(llist *l, int (*f)(void *d, void *u), void *u);
int llist_copy(llist *l, llist *t, void* (*f)(void *d, void *u), void *u);
void * llist_free(llist *l, int (*f)(void *d, void *u), void *u);


#endif /* _VTUN_LLIST_H */
