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
 * lib.h,v 1.2.2.5.2.1 2006/11/16 04:03:20 mtbishop Exp
 */ 
#ifndef _VTUN_LIB_H
#define _VTUN_LIB_H

#include "config.h"
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifndef HAVE_SETPROC_TITLE
  void init_title(int argc,char *argv[],char *env[], char *name);
  void set_title(const char *ftm, ...);
#else
  #define init_title( a... ) 
  #define set_title setproctitle
#endif /* HAVE_SETPROC_TITLE */

#ifndef min
  #define min(a,b)    ( (a)<(b) ? (a):(b) )
#endif

int readn_t(int fd, void *buf, size_t count, time_t timeout);
int print_p(int f, const char *ftm, ...);

int  run_cmd(void *d, void *opt);
void free_sopt(struct vtun_sopt *opt);

int std_dev(int nums[], int len);

/* IO cancelation */
extern volatile sig_atomic_t __io_canceled;

static inline void io_init(void)
{
	__io_canceled = 0;
}

static inline void io_cancel(void)
{
	__io_canceled = 1;
}

/* signal safe syslog function */
void vtun_syslog (int priority, char *format, ...);

/* Read exactly len bytes (Signal safe)*/
static inline int read_n(int fd, char *buf, int len)
{
    register int t = 0, w, ecount = 0;

	while (!__io_canceled && len > 0) {
	  if( (w = read(fd, buf, len)) < 0 ){
            if (errno == EAGAIN) {
                continue;
            } else if (errno == EINTR) {
                ecount++;
                if (ecount >= 2) {
                    return -1;
                }
                continue;
            }
	     return -1;
	  }
	  if( !w )
	     return 0;
	  len -= w; buf += w; t += w;
	}

	return t;
}   

/* Write exactly len bytes (Signal safe)*/
static inline int write_n(int fd, char *buf, int len)
{
	register int t=0, w;

	while (!__io_canceled && len > 0) {
 	  if( (w = write(fd, buf, len)) < 0 ){
	     if( errno == EINTR || errno == EAGAIN )
  	         continue;
	     return -1;
	  }
	  if( !w )
	     return 0;
	  len -= w; buf += w; t += w;
	}

	return t;
}
#endif /* _VTUN_LIB_H */
