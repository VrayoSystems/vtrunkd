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
 * client.c,v 1.5.2.8.2.1 2006/11/16 04:02:48 mtbishop Exp
 */ 

#include "config.h"
#include "vtun_socks.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <time.h>        /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>   /* inet(3) functions */
#include <errno.h>
#include <fcntl.h>       /* for nonblocking */
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>    /* for S_xxx file mode constants */
#include <sys/uio.h>     /* for iovec{} and readv/writev */
#include <unistd.h>
#include <sys/wait.h>
#include <sys/un.h>      /* for Unix domain sockets */


#include "vtun.h"
#include "lib.h"
#include "log.h"
#include "llist.h"
#include "auth.h"
#include "compat.h"
#include "netlib.h"

static volatile sig_atomic_t client_term;
static void sig_term(int sig)
{
    vlog(LOG_INFO, "Terminated");
    client_term = VTUN_SIG_TERM;
}
/*
int cshit3(struct conn_info * sci, int fx) {
     int cnt = 0, cnt2=0;
     int nnl = sci->resend_buf.frames.rel_head;
     int nnf = sci->resend_buf.free_frames.rel_head;
     
     while(nnl > -1) {
          cnt++;
          nnl = sci->resend_buf.frames_buf[nnl].rel_next;
     }
     
     while(nnf > -1) {
          cnt++;
          nnf = sci->resend_buf.frames_buf[nnf].rel_next;
     }
     vlog(LOG_INFO, "%d count l: %d f: %d", fx, cnt, cnt2);
     return 0;
}
*/

void client(struct vtun_host *host)
{
    struct sockaddr_in my_addr, svr_addr;
    struct sigaction sa;
    int s, opt, reconnect, sss, len;
    int shm_new = 0;
    struct sockaddr_un remote;

    vlog_close();
    vlog_open(host->host, LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

#ifdef CLIENTONLY
    vlog(LOG_INFO, "vtrunkd client only ver %s %s started", VTUN_VER, BUILD_DATE);
#else
    vlog(LOG_INFO, "vtrunkd client ver %s %s started", VTUN_VER, BUILD_DATE);
#endif
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_term;
    sigaction(SIGTERM, &sa, NULL);
    // sigaction(SIGINT, &sa, NULL);


    // now init everything...
    int shmid;
    int reason = 0; // connection denial reason
    key_t key;
    struct conn_info *shm_conn_info;
    struct timeval cur_time;
    /*
    * We'll name our shared memory segment
    * "5678".
    */
    key = vtun.shm_key;


    /*
    * First, try to open shm
    */

    if ((shmid = shmget(key, sizeof(struct conn_info), 0666)) < 0) {
        /*
        * Create the segment.
        */
        vlog(LOG_INFO, "client: init new shm...");
        if ((shmid = shmget(key, sizeof(struct conn_info), IPC_CREAT | 0666)) < 0) {
            vlog(LOG_ERR, "shmget 2 size %d", sizeof(struct conn_info));
            exit(1);
        }
        shm_new = 1;
    } else {
        vlog(LOG_INFO, "client: reusing shm...");
        shm_new = 0;
    }
    /*
    * Now we attach the segment to our data space.
    */
    if ((shm_conn_info = shmat(shmid, NULL, 0)) == (struct conn_info *) - 1) {
        vlog(LOG_ERR, "shmat 2");
        exit(1);
    }
    //cshit3(&shm_conn_info[0], 36);
    // now try to connect to socket if shm_new ==0
    if (!shm_new) {
        if ((sss = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            vlog(LOG_ERR, "socket 44");
            exit(1);
        }
        remote.sun_family = AF_UNIX;
        sprintf(remote.sun_path, "/tmp/vtrunkd_%s.socket", shm_conn_info[0].devname);
        len = strlen(remote.sun_path) + sizeof(remote.sun_family);
        if ( (shm_conn_info->rdy) && (connect(sss, (struct sockaddr *)&remote, len) == -1)) {
            vlog(LOG_INFO, "SHM ready but socket not open! Assuming we're only process running;");
            shm_new = 1; // could not connect; assume we're new!
        } else {
            vlog(LOG_INFO, "Socket connected OK seems all OK");
        }
        close(sss);
    }
    if (shm_new) {
        vlog(LOG_INFO, "client doing memset");
        memset(shm_conn_info, 0, sizeof(struct conn_info));
    }
    //cshit3(&shm_conn_info[0], 37);

    client_term = 0; reconnect = 0;
    while ( (!client_term) || (client_term == VTUN_SIG_HUP) ) {
        if ( reconnect && (client_term != VTUN_SIG_HUP) ) {
            if ( vtun.persist || host->persist ) {
                /* Persist mode. Sleep and reconnect. */
                sleep(5);
            } else {
                /* Exit */
                break;
            }
        } else {
            reconnect = 1;
        }

        set_title("%s init initializing", host->host);

        /* Set server address */
        if ( server_addr(&svr_addr, host) < 0 )
            continue;

        /* Set local address */
        if ( local_addr(&my_addr, host, 0) < 0 )
            continue;

        /* We have to create socket again every time
         * we want to connect, since STREAM sockets
         * can be successfully connected only once.
         */
        if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
            vlog(LOG_ERR, "Can't create socket. %s(%d)",
                        strerror(errno), errno);
            continue;
        }
        //cshit3(&shm_conn_info[0], 38);

        /* Required when client is forced to bind to specific port */
        opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

//        #ifndef W_O_SO_MARK
        if (host->RT_MARK != -1) {
            if (setsockopt(s, SOL_SOCKET, SO_MARK, &host->RT_MARK, sizeof(host->RT_MARK))) {
                vlog(LOG_ERR, "client socket rt mark error %s(%d)",
                            strerror(errno), errno);
                break;
            }
        }
//        #endif


        if ( bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr)) ) {
            vlog(LOG_ERR, "Can't bind socket. %s(%d)",
                        strerror(errno), errno);
            continue;
        }

        /*
         * Clear speed and flags which will be supplied by server.
         */
        host->spd_in = host->spd_out = 0;
        host->flags &= VTUN_CLNT_MASK;

        io_init();

        set_title("%s connecting to %s", host->host, vtun.svr_name);
        vlog(LOG_INFO, "Connecting to %s", vtun.svr_name);

        if ( connect_t(s, (struct sockaddr *) &svr_addr, host->timeout) ) {
            vlog(LOG_ERR, "Connect to %s failed. %s(%d)", vtun.svr_name,
                        strerror(errno), errno);
        } else {
            if ( auth_client(s, host, &reason) ) {
                vlog(LOG_ERR, "Session %s[%s] opened (build %s)", host->host, vtun.svr_name, BUILD_DATE);



                host->rmt_fd = s;
                //cshit3(&shm_conn_info[0], 39);

                /* Start the tunnel */
                client_term = tunnel(host, 0, NULL);
                gettimeofday(&cur_time, NULL);
                shm_conn_info->alive = cur_time.tv_sec; // show we are alive and trying to reconnect still.. (or fd_server will quit)

                vlog(LOG_ERR, "Session %s[%s] closed", host->host, vtun.svr_name);
            } else {
                vlog(LOG_ERR, "Connection denied by %s, reason: %d", vtun.svr_name, reason);
            }
        }
        close(s);
        free_sopt(&host->sopt);
    }

    vlog(LOG_INFO, "Exit");
    return;
}
