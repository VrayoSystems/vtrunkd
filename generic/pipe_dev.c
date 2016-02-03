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
 * pipe_dev.c,v 1.1.1.1.2.1.2.1 2006/11/16 04:04:26 mtbishop Exp
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>

#include "vtun.h"
#include "lib.h"

/* 
 * Create pipe. Return open fd. 
 */  
int pipe_open(int *fd)
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
}

/* Write frames to pipe */
int pipe_write(int fd, char *buf, int len)
{
    return write_n(fd, buf, len);
}

/* Read frames from pipe */
int pipe_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}
