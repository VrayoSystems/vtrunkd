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
 * vtun_socks.h,v 1.1.1.1.6.1 2006/11/16 04:04:20 mtbishop Exp
 */ 

#ifndef _VTUN_SOCKS_H
#define _VTUN_SOCKS_H

#if defined(VTUN_SOCKS)
   /* Syscalls to SOCKS calls */
   #if VTUN_SOCKS == 1
      #define connect 		SOCKSconnect
      #define bind 		SOCKSbind
      #define select		SOCKSselect
      #define getsockname 	SOCKSgetsockname
      #define getpeername 	SOCKSgetpeername
      #define gethostbyname 	SOCKSgethostbyname
   #else
      #define connect 		Rconnect
      #define bind 		Rbind
      #define select		Rselect
      #define getsockname 	Rgetsockname
      #define getpeername 	Rgetpeername
      #define gethostbyname 	Rgethostbyname
   #endif
#endif


#endif /* _VTUN_SOCKS_H */
