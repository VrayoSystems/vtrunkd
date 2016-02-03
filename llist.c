
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
#include "llist.h"

/* Function to work with the Linked Lists */

void llist_init(llist *l)
{
	l->head = l->tail = NULL;
} 

int llist_empty(llist *l)
{
	return l->tail == NULL;
}

int llist_add(llist *l, void * d)
{
	llist_elm *e;

	if( !(e=malloc(sizeof(llist_elm))) )
	   return -1; 	

	if( !l->head )
	   l->head = l->tail = e; 
	else
	   l->tail->next = e;
	l->tail = e;

	e->next = NULL;
	e->data = d;

	return 0;
} 

/* Travel list from head to tail */
void * llist_trav(llist *l, int (*f)(void *d, void *u), void *u)
{
	llist_elm *i = l->head;

	while( i ){
	   if( f(i->data,u) ) return i->data;
	   i = i->next;
	}
	return NULL;
}

/* Copy list from (l) to (t) */
int llist_copy(llist *l, llist *t, void* (*f)(void *d, void *u), void *u)
{
	llist_elm *i = l->head;

	llist_init(t);
	
	while( i ){
	   llist_add(t,f(i->data,u));
	   i = i->next;
	}
	return 0;
}

/* Travel list from head to tail, deallocate each element */
void * llist_free(llist *l, int (*f)(void *d, void *u), void *u)
{
	llist_elm *i = l->head, *n;
        void *ff = NULL; 

	while( i ){
	   n = i->next; 	
	   if( f(i->data,u) ) 
 	      ff = i->data;
	   else
	      free(i); 
	   i = n;
	}
	l->head = l->tail = NULL;
	return ff;
}


