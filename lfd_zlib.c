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
 * lfd_zlib.c,v 1.1.1.2.2.6.2.1 2006/11/16 04:03:14 mtbishop Exp
 */ 

/* ZLIB compression module */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "log.h"

#ifdef HAVE_ZLIB

#include <zlib.h>

static z_stream zi, zd; 
static unsigned char *zbuf;
static int zbuf_size = VTUN_FRAME_SIZE + 200;

/* 
 * Initialize compressor/decompressor.
 * Allocate the buffer.
 */  
int zlib_alloc(struct vtun_host *host)
{
     int zlevel = host->zlevel ? host->zlevel : 1;

     zd.zalloc = (alloc_func)0;
     zd.zfree  = (free_func)0;
     zd.opaque = (voidpf)0;
     zi.zalloc = (alloc_func)0;
     zi.zfree  = (free_func)0;
     zi.opaque = (voidpf)0;
    
     if( deflateInit(&zd, zlevel ) != Z_OK ){
	vlog(LOG_ERR,"Can't initialize compressor");
	return 1;
     }	
     if( inflateInit(&zi) != Z_OK ){
	vlog(LOG_ERR,"Can't initialize decompressor");
	return 1;
     }	
     if( !(zbuf = (void *) lfd_alloc(zbuf_size)) ){
	vlog(LOG_ERR,"Can't allocate buffer for the compressor");
	return 1;
     }
   
     vlog(LOG_INFO,"ZLIB compression[level %d] initialized.", zlevel);
     return 0;
}

/* 
 * Deinitialize compressor/decompressor.
 * Free the buffer.
 */  

int zlib_free()
{
     deflateEnd(&zd);
     inflateEnd(&zi);

     lfd_free(zbuf); zbuf = NULL;

     return 0;
}

static int expand_zbuf(z_stream *zs, int len)
{
     if( !(zbuf = lfd_realloc(zbuf,zbuf_size+len)) )
         return -1;
     zs->next_out = zbuf + zbuf_size;
     zs->avail_out = len;
     zbuf_size += len;     

     return 0;
}

/* 
 * This functions _MUST_ consume all incoming bytes in one pass,
 * That's why we expand buffer dynamically.
 * Practice shows that buffer will not grow larger that 16K.
 */  
int zlib_comp(int len, char *in, char **out)
{ 
     int oavail, olen = 0;    
     int err;
 
     zd.next_in = (void *) in;
     zd.avail_in = len;
     zd.next_out = (void *) zbuf;
     zd.avail_out = zbuf_size;
    
     while(1) {
        oavail = zd.avail_out;
        if( (err=deflate(&zd, Z_SYNC_FLUSH)) != Z_OK ){
           vlog(LOG_ERR,"Deflate error %d",err);
           return -1;
        }
        olen += oavail - zd.avail_out;
        if(!zd.avail_in)
	   break;

        if( expand_zbuf(&zd,100) ) {
	   vlog( LOG_ERR, "Can't expand compression buffer");
           return -1;
	}
     }
     *out = (void *) zbuf;
     return olen;
}

int zlib_decomp(int len, char *in, char **out)
{
     int oavail = 0, olen = 0;     
     int err;

     zi.next_in = (void *) in;
     zi.avail_in = len;
     zi.next_out = (void *) zbuf;
     zi.avail_out = zbuf_size;

     while(1) {
        oavail = zi.avail_out;
        if( (err=inflate(&zi, Z_SYNC_FLUSH)) != Z_OK ) {
           vlog(LOG_ERR,"Inflate error %d len %d", err, len);
           return -1;
        }
        olen += oavail - zi.avail_out;
        if(!zi.avail_in)
	   break;
        if( expand_zbuf(&zi,100) ) {
	   vlog( LOG_ERR, "Can't expand compression buffer");
           return -1;
	}
     }
     *out = (void *) zbuf;
     return olen;
}

struct lfd_mod lfd_zlib = {
     "ZLIB",
     zlib_alloc,
     zlib_comp,
     NULL,
     zlib_decomp,
     NULL,
     zlib_free,
     NULL,
     NULL
};

#else  /* HAVE_ZLIB */

int no_zlib(struct vtun_host *host)
{
     vlog(LOG_INFO, "ZLIB compression is not supported");
     return -1;
}

struct lfd_mod lfd_zlib = {
     "ZLIB",
     no_zlib, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_ZLIB */
