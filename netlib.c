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
 * netlib.c,v 1.7.2.4.2.2 2006/11/16 04:03:47 mtbishop Exp
 */ 

#include "config.h"
#include "vtun_socks.h"

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
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

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

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "log.h"
#include "netlib.h"

/* Connect with timeout */
int connect_t(int s, struct sockaddr *svr, time_t timeout) 
{
#if defined(VTUN_SOCKS) && VTUN_SOCKS == 2
     /* Some SOCKS implementations don't support
      * non blocking connect */
     return connect(s,svr,sizeof(struct sockaddr));
#else
     int sock_flags;
     fd_set fdset;
     struct timeval tv;

     tv.tv_usec=0; tv.tv_sec=timeout;

     sock_flags=fcntl(s,F_GETFL);
     if( fcntl(s,F_SETFL,O_NONBLOCK) < 0 )
        return -1;

     if( connect(s,svr,sizeof(struct sockaddr)) < 0 && errno != EINPROGRESS)
        return -1;

     FD_ZERO(&fdset);
     FD_SET(s,&fdset);
     if( select(s+1,NULL,&fdset,NULL,timeout?&tv:NULL) > 0 ){
        int l=sizeof(errno);	 
        errno=0;
        getsockopt(s,SOL_SOCKET,SO_ERROR,&errno,&l);
     } else
        errno=ETIMEDOUT;  	

     fcntl(s,F_SETFL,sock_flags); 

     if( errno )
        return -1;

     return 0;
#endif
}

/* Get interface address */
unsigned long getifaddr(char * ifname) 
{
     struct sockaddr_in addr;
     struct ifreq ifr;
     int s;

     if( (s = socket(AF_INET, SOCK_DGRAM, 0)) == -1 )
        return -1;

     strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)-1);
     ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';

     if( ioctl(s, SIOCGIFADDR, &ifr) < 0 ){
        close(s);
        return -1;
     }
     close(s);

     addr = *((struct sockaddr_in *) &ifr.ifr_addr);

     return addr.sin_addr.s_addr;
}

/* 
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error.
 */
int udp_session(struct vtun_host *host) 
{
     struct sockaddr_in saddr; 
     short port;
     int s,opt;

     if( (s=socket(AF_INET,SOCK_DGRAM,0))== -1 ){
        vlog(LOG_ERR,"Can't create socket");
        return -1;
     }

     opt=1;
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 
    
     /* Set local address and port */
     local_addr(&saddr, host, 1);
     if( bind(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vlog(LOG_ERR,"Can't bind to the socket");
        return -1;
     }

     opt = sizeof(saddr);
     if( getsockname(s,(struct sockaddr *)&saddr,&opt) ){
        vlog(LOG_ERR,"Can't get socket name");
        return -1;
     }

     /* Write port of the new UDP socket */
     port = saddr.sin_port;
     if( write_n(host->rmt_fd,(char *)&port,sizeof(short)) < 0 ){
        vlog(LOG_ERR,"Can't write port number");
        return -1;
     }
     host->sopt.lport = htons(port);

     /* Read port of the other's end UDP socket */
     if( readn_t(host->rmt_fd,&port,sizeof(short),host->timeout) < 0 ){
        vlog(LOG_ERR,"Can't read port number %s", strerror(errno));
        return -1;
     }

     opt = sizeof(saddr);
     if( getpeername(host->rmt_fd,(struct sockaddr *)&saddr,&opt) ){
        vlog(LOG_ERR,"Can't get peer name");
        return -1;
     }

     saddr.sin_port = port;
     if( connect(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vlog(LOG_ERR,"Can't connect socket");
        return -1;
     }
     host->sopt.rport = htons(port);

     /* Close TCP socket and replace with UDP socket */	
     close(host->rmt_fd); 
     host->rmt_fd = s;	

     vlog(LOG_INFO,"UDP connection initialized");
     return s;
}

/* Set local address */
int local_addr(struct sockaddr_in *addr, struct vtun_host *host, int con)
{
     int opt;

     if( con ){
        /* Use address of the already connected socket. */
        opt = sizeof(struct sockaddr_in);
        if( getsockname(host->rmt_fd, (struct sockaddr *)addr, &opt) < 0 ){
           vlog(LOG_ERR,"Can't get local socket address");
           return -1; 
        }
     } else {
        if (generic_addr(addr, &host->src_addr) < 0)
                 return -1;
              }

     host->sopt.laddr = strdup(inet_ntoa(addr->sin_addr));

     return 0;
}

int server_addr(struct sockaddr_in *addr, struct vtun_host *host)
{
     struct hostent * hent;

     memset(addr,0,sizeof(struct sockaddr_in));
     addr->sin_family = AF_INET;
     addr->sin_port = htons(vtun.bind_addr.port);

     /* Lookup server's IP address.
      * We do it on every reconnect because server's IP 
      * address can be dynamic.
      */
     if( !(hent = gethostbyname(vtun.svr_name)) ){
        vlog(LOG_ERR, "Can't resolv server address: %s", vtun.svr_name);
        return -1;
     }
     addr->sin_addr.s_addr = *(unsigned long *)hent->h_addr; 

     host->sopt.raddr = strdup(inet_ntoa(addr->sin_addr));
     host->sopt.rport = vtun.bind_addr.port;

     return 0; 
}

/* Set address by interface name, ip address or hostname */
int generic_addr(struct sockaddr_in *addr, struct vtun_addr *vaddr)
{
     struct hostent *hent;
     memset(addr, 0, sizeof(struct sockaddr_in));
  
     addr->sin_family = AF_INET;
  
     switch (vaddr->type) {
        case VTUN_ADDR_IFACE:
	 if (!(addr->sin_addr.s_addr =
	       getifaddr(vaddr->name))) {
	    vlog(LOG_ERR,
	                "Can't get address of interface %s",
	                vaddr->name);
	    return -1;
	 }
           break;
        case VTUN_ADDR_NAME:
	 if (!(hent = gethostbyname(vaddr->name))) {
	    vlog(LOG_ERR,
	                "Can't resolv local address %s",
	                vaddr->name);
	    return -1;
           }
	 addr->sin_addr.s_addr = *(unsigned long *) hent->h_addr;
           break;
        default:
           addr->sin_addr.s_addr = INADDR_ANY;
           break;
     }
  
     if (vaddr->port)
        addr->sin_port = htons(vaddr->port);

     return 0; 
}
