/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

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
 * tap_dev.c,v 1.2.2.1.2.1 2006/11/16 04:04:32 mtbishop Exp
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
 * Allocate Ether TAP device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */ 
int tap_open(char *dev)
{
    char tapname[14];
    int i, fd;

    if( *dev ) {
       sprintf(tapname, "/dev/%s", dev);
       return open(tapname, O_RDWR);
    }

    for(i=0; i < 255; i++) {
       sprintf(tapname, "/dev/tap%d", i);
       /* Open device */
       if( (fd=open(tapname, O_RDWR)) > 0 ) {
          sprintf(dev, "tap%d",i);
          return fd;
       }
    }
    return -1;
}

int tap_close(int fd, char *dev)
{
    return close(fd);
}

/* Write frames to TAP device */
int tap_write(int fd, char *buf, int len)
{
    return write(fd, buf, len);
}

/* Read frames from TAP device */
int tap_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}
