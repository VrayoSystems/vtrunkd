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
 * lfd_shaper.c,v 1.1.1.2.2.4.2.1 2006/11/16 04:03:09 mtbishop Exp
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <syslog.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "log.h"

/*
 * Shaper module.
 */

#ifdef HAVE_SHAPER

unsigned long bytes, max_speed;
struct timeval curr_time, last_time;

/*
 * Initialization function.
 */
int shaper_init(struct vtun_host *host)
{
    /* Calculate max speed bytes/sec */
    max_speed = host->spd_out / 8 * 1024;

    /* Compensation for delays, nanosleep and so on */
    max_speed += 400;

    bytes = 0;

    vlog(LOG_INFO, "Traffic shaping(speed %dK) initialized.", host->spd_out);
    return 0;
}

/* Shaper counter */
int shaper_counter(int len, char *in, char **out)
{
    /* Just count incoming bytes */
    bytes += len;

    *out = in;
    return len;
}

#ifndef timersub
/* Some includes doesn't contain this macro */
#define timersub(a, b, result)                          \
  do {                                                  \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;       \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;    \
    if ((result)->tv_usec < 0) {                        \
        --(result)->tv_sec;                             \
        (result)->tv_usec += 1000000;                   \
    }                                                   \
  } while (0)
#endif

/*
 * Main shaper function.
 * Compute current speed in bytes/sec and if it is
 * higher than maximal speed stop accepting input
 * until the speed become lower or equal to maximal.
 */
int shaper_avail(void)
{
    static struct timeval tv;
    register unsigned long speed;

    /* Let me know if you have faster and better time source. */
    gettimeofday(&curr_time, NULL);

    timersub(&curr_time, &last_time, &tv);

    /* Calculate current speed bytes/sec.
     * (tv2ms never returns 0) */
    speed = bytes * 1000 / tv2ms(tv);

    if ( speed > max_speed ) {
        /*
         * Sleep about 1 microsec(actual sleep might be longer).
         * This is actually the hack to reduce CPU usage.
         * Without this delay we will consume 100% CPU.
             */
        static struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);

        /* Don't accept input */
        return 0;
    }

    if ( curr_time.tv_sec > last_time.tv_sec ) {
        last_time = curr_time;
        bytes = 0;
    }

    /* Accept input */
    return  1;
}

struct lfd_mod lfd_shaper = {
    "Shaper",
    shaper_init,
    shaper_counter,
    shaper_avail,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

#else  /* HAVE_SHAPER */

int no_shaper(struct vtun_host *host)
{
    vlog(LOG_INFO, "Traffic shaping is not supported");
    return -1;
}

struct lfd_mod lfd_shaper = {
    "Shaper",
    no_shaper, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_SHAPER */
