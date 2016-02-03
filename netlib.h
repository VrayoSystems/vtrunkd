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
 * netlib.h,v 1.2.2.1.2.2 2006/11/16 04:03:50 mtbishop Exp
 */ 

#ifndef _VTUN_NETDEV_H
#define _VTUN_NETDEV_H

#include "config.h"
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

unsigned long getifaddr(char * ifname);
int connect_t(int s, struct sockaddr *svr, time_t timeout); 
int udp_session(struct vtun_host *host); 

int local_addr(struct sockaddr_in *addr, struct vtun_host *host, int con);
int server_addr(struct sockaddr_in *addr, struct vtun_host *host);
int generic_addr(struct sockaddr_in *addr, struct vtun_addr *vaddr);

#endif /* _VTUN_NETDEV_H */
