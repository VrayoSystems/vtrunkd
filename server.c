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
 * server.c,v 1.4.2.5.2.4 2006/11/16 04:03:53 mtbishop Exp
 */ 

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef DEBUGG
#include <sys/types.h>
#include <sys/gmon.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "log.h"
#include "lock.h"
#include "auth.h"
#include "netlib.h"

#include "compat.h"

char process_string[100] = { 0 };
struct conn_info* shm_conn_info = NULL;
int shmid = 0;

static volatile sig_atomic_t server_term;
static void sig_term(int sig) {
    if (shmid != 0) {
        if (shmctl(shmid, IPC_RMID, NULL ) == -1) {
            vlog(LOG_INFO, "shm destroy fail; reason %s (%d)", strerror(errno), errno);
        } else {
            vlog(LOG_INFO, "shm destroy mark");
        }
    } else {
        if ((shmid = shmget(vtun.shm_key, sizeof(struct conn_info) * vtun.MAX_TUNNELS_NUM, 0666)) < 0) {
            vlog(LOG_ERR, "SHM buffer for key %d not found", vtun.shm_key);
        } else {
            if (shmctl(shmid, IPC_RMID, NULL ) == -1) {
                vlog(LOG_INFO, "shm destroy fail; reason %s (%d)", strerror(errno), errno);
            }
        }
    }
    if (shm_conn_info != NULL ) {

        if (shmdt(shm_conn_info) == -1) {
            vlog(LOG_INFO, "Detach shm fail; reason %s (%d)", strerror(errno), errno);
        } else {
            vlog(LOG_INFO, "shm detached");
        }

    }
    vlog(LOG_INFO, "Terminated");
    server_term = VTUN_SIG_TERM;
}

void connection(int sock, sem_t *shm_sem)
{
#ifndef CLIENTONLY
    struct sockaddr_in my_addr, cl_addr;
    struct vtun_host *host;
    struct sigaction sa;
    char *ip;
    int opt;
    int reason = 0;

    opt = sizeof(struct sockaddr_in);
    if ( getpeername(sock, (struct sockaddr *) &cl_addr, &opt) ) {
        vlog(LOG_ERR, "Can't get peer name");
        exit(1);
    }
    opt = sizeof(struct sockaddr_in);
    if ( getsockname(sock, (struct sockaddr *) &my_addr, &opt) < 0 ) {
        vlog(LOG_ERR, "Can't get local socket address");
        exit(1);
    }

    ip = strdup(inet_ntoa(cl_addr.sin_addr));

    io_init();

    if ( (host = auth_server(sock, &reason)) ) {
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_NOCLDWAIT;;
        sigaction(SIGHUP, &sa, NULL);

        sprintf(process_string, "vtrunkd %s", host->host);
        vlog(LOG_INFO, "Change title with: %s", process_string);
        vlog_close();

        vlog_open(host->host, LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
        vlog(LOG_ERR, "Session %s[%s:%d] opened (build %s)", host->host, ip, ntohs(cl_addr.sin_port), BUILD_DATE);

        host->rmt_fd = sock;

        host->sopt.laddr = strdup(inet_ntoa(my_addr.sin_addr));
        host->sopt.lport = vtun.bind_addr.port;
        host->sopt.raddr = strdup(ip);
        host->sopt.rport = ntohs(cl_addr.sin_port);
        host->start_port = vtun.start_port;
        host->end_port = vtun.end_port;
        /* Start tunnel */
        tunnel(host, 1, shm_sem);

        vlog(LOG_ERR, "Session %s closed", host->host);

        /* Unlock host. (locked in auth_server) */
        unlock_host(host);
    } else {
        vlog(LOG_INFO, "Denied connection from %s:%d, reason: %d", ip,
                    ntohs(cl_addr.sin_port), reason );
    }
    close(sock);
#endif
    exit(0);
}

void listener(void)
{
    struct sigaction sa;
    struct sockaddr_in my_addr, cl_addr;
    int s, s1, opt;

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;

    /* Set listen address */
    if ( generic_addr(&my_addr, &vtun.bind_addr) < 0)
    {
        vlog(LOG_ERR, "Can't fill in listen socket");
        exit(1);
    }

    if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
        vlog(LOG_ERR, "Can't create socket");
        exit(1);
    }

    opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if ( bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr)) ) {
        vlog(LOG_ERR, "Can't bind to the socket");
        exit(1);
    }

    if ( listen(s, 10) ) {
        vlog(LOG_ERR, "Can't listen on the socket");
        exit(1);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDWAIT;
    sa.sa_handler = sig_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    // WARNING: signals should be re-checked before using!
    server_term = 0;

    set_title("waiting for connections on port %d", vtun.bind_addr.port);

    // now init everything...
    key_t key;
    /*
    * We'll name our shared memory segment
    * defaul is 567888
    */
    key = vtun.shm_key;

    /*
    * Create the segment.
    */
    // TODO: do not allocate all memory at once!!!!
    if ((shmid = shmget(key, sizeof(struct conn_info) * vtun.MAX_TUNNELS_NUM, IPC_CREAT | 0666)) < 0) {
        vlog(LOG_ERR, "Can not allocate SHM buffer of size %d. Please check your system shmmax or use 'ipcrm' to remove stale SHMs", sizeof(struct conn_info) * vtun.MAX_TUNNELS_NUM);
        exit(1);
    }

    /*
    * Now we attach the segment to our data space.
    */
    if ((shm_conn_info = shmat(shmid, NULL, 0)) == (struct conn_info *) - 1) {
        vlog(LOG_ERR, "shmat 1");
        exit(1);
    }

    memset(shm_conn_info, 0, sizeof(struct conn_info) * vtun.MAX_TUNNELS_NUM);
    
    char semname[255];
    sprintf(semname, "/vtrunkd_%d", vtun.shm_key);
    sem_t *shm_sem;
    if ((shm_sem = sem_open(semname, O_CREAT, 0644, 1)) == SEM_FAILED) {
        perror("shm semaphore initilization");
        exit(1);
    }
    sem_init(&shm_sem, 1, 1);

    while ( (!server_term) || (server_term == VTUN_SIG_HUP) ) {
        opt = sizeof(cl_addr);
        if ( (s1 = accept(s, (struct sockaddr *)&cl_addr, &opt)) < 0 )
            continue;

        switch ( fork() ) {
        case 0:
            close(s);
#ifdef DEBUGG
            // now init the profiler; don;t forget to set GMON_OUT_PREFIX
            extern void _start (void), etext (void);
            monstartup ((u_long) &_start, (u_long) &etext);
#endif
            struct rlimit core_limit;
            core_limit.rlim_cur = RLIM_INFINITY;
            core_limit.rlim_max = RLIM_INFINITY;

            if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
                vlog(LOG_ERR, "setrlimit: Warning: core dumps may be truncated or non-existant reason %s (%d)", strerror(errno), errno);
            }
            connection(s1, shm_sem);
            break;
        case -1:
            vlog(LOG_ERR, "Couldn't fork()");
        default:
            close(s1);
            // normal cont
            break;
        }
    }

    shmctl(key, IPC_RMID, NULL);

    vlog(LOG_INFO, "SERVER QUIT %d", server_term);
}

void server(int sock)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    vlog(LOG_INFO, "vtrunkd server ver %s %s (%s)", VTUN_VER, BUILD_DATE,
                vtun.svr_type == VTUN_INETD ? "inetd" : "stand" );

    switch ( vtun.svr_type ) {
    case VTUN_STAND_ALONE:
        listener();
        break;
    case VTUN_INETD:
        connection(sock, NULL);
        break;
    }
}
