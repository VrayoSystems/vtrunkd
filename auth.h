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
 * auth.h,v 1.1.1.2.6.1 2006/11/16 04:02:36 mtbishop Exp
 */ 

#define VTUN_CHAL_SIZE	 16	

#define ST_INIT  0
#define ST_HOST  1
#define ST_CHAL  2

struct vtun_host * auth_server(int fd, int * reason);
int auth_client(int fd, struct vtun_host *host, int * reason);

