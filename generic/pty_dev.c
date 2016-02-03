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
 * pty_dev.c,v 1.1.1.1.2.3.2.1 2006/11/16 04:04:29 mtbishop Exp
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "vtun.h"
#include "lib.h"

/* 
 * Allocate pseudo tty, returns master side fd. 
 * Stores slave name in the first arg(must be large enough).
 */  
int pty_open(char *sl_name)
{
    int  mr_fd;
#if defined (HAVE_GETPT) && defined (HAVE_GRANTPT) && defined (HAVE_UNLOCKPT) && defined (HAVE_PTSNAME)
    char *ptyname;

    if((mr_fd=getpt()) < 0)
 	return -1;
    if(grantpt(mr_fd) != 0)
	return -1;
    if(unlockpt(mr_fd) != 0)
	return -1;
    if ((ptyname = (char*)ptsname(mr_fd)) == NULL)
	return -1;
    strcpy(sl_name, ptyname);
    return mr_fd;

#else

    char ptyname[] = "/dev/ptyXY";
    char ch[] = "pqrstuvwxyz";
    char digit[] = "0123456789abcdefghijklmnopqrstuv";
    int  l, m;

    /* This algorithm should work for almost all standard Unices */	
    for(l=0; ch[l]; l++ ) {
        for(m=0; digit[m]; m++ ) {
	 	ptyname[8] = ch[l];
		ptyname[9] = digit[m];
		/* Open the master */
		if( (mr_fd=open(ptyname, O_RDWR)) < 0 )
	 	   continue;
		/* Check the slave */
		ptyname[5] = 't';
		if( (access(ptyname, R_OK | W_OK)) < 0 ){
		   close(mr_fd);
		   ptyname[5] = 'p';
		   continue;
		}
		strcpy(sl_name,ptyname);
		return mr_fd;
	    }
	}
	return -1;
#endif
}

/* Write frames to PTY device */
int pty_write(int fd, char *buf, int len)
{
    return write_n(fd, buf, len);
}

/* Read frames from PTY device */
int pty_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}
