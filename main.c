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
 * main.c,v 1.1.1.2.2.8.2.4 2006/11/16 04:03:41 mtbishop Exp
 */

#include "config.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef DEBUGG
#include <sys/types.h>
#include <sys/gmon.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "log.h"
#include "compat.h"

/* Global options for the server and client */
struct vtun_opts vtun;
struct vtun_host default_host;
int debug_trace = 0;

void write_pid(void);
void reread_config(int sig);
void usage(void);
void version();

extern int optind, opterr, optopt;
extern char *optarg;

int main(int argc, char *argv[], char *env[])
{
    int svr, daemon, sock, dofork, fd, opt;
    struct vtun_host *host = NULL;
    struct sigaction sa;
    char *hst;

    /* Configure default settings */
    svr = 0; daemon = 1; sock = 0; dofork = 1;

    vtun.cfg_file = VTUN_CONFIG_FILE;
    vtun.persist = -1;
    vtun.timeout = -1;

    vtun.MAX_TUNNELS_NUM = -1; // todo: defaults?

    /* Dup strings because parser will try to free them */
    vtun.ppp   = strdup("/usr/sbin/pppd");
    vtun.ifcfg = strdup("/sbin/ifconfig");
    vtun.route = strdup("/sbin/route");
    vtun.fwall = strdup("/sbin/ipchains");
    vtun.iproute = strdup("/sbin/ip");

    vtun.svr_name = NULL;
    vtun.svr_addr = NULL;
    vtun.bind_addr.port = -1;
    vtun.start_port = 0;
    vtun.end_port = 0;
    vtun.svr_type = -1;
    vtun.quiet = 1;
    vtun.syslog   = LOG_DAEMON;
    vtun.shm_key = SHM_TUN_KEY;

    /* Initialize default host options */
    memset(&default_host, 0, sizeof(default_host));
    default_host.flags   = VTUN_TTY | VTUN_TCP;
    default_host.multi   = VTUN_MULTI_ALLOW;
    default_host.timeout = VTUN_CONNECT_TIMEOUT;
    default_host.ka_interval = 30;
    default_host.ka_failure  = 4;
    default_host.loc_fd = default_host.rmt_fd = -1;

    default_host.TICK_SECS = P_TICK_SECS;
    default_host.RXMIT_CNT_DROP_PERIOD = P_RXMIT_CNT_DROP_PERIOD;
    default_host.MAX_WEIGHT_NORM = P_MAX_WEIGHT_NORM;
    default_host.WEIGHT_SCALE = P_WEIGHT_SCALE;
    default_host.WEIGHT_SMOOTH_DIV = P_WEIGHT_SMOOTH_DIV;
    default_host.WEIGHT_START_STICKINESS = P_WEIGHT_START_STICKINESS;
    default_host.WEIGHT_SAW_STEP_UP_DIV = P_WEIGHT_SAW_STEP_UP_DIV;
    default_host.WEIGHT_SAW_STEP_UP_MIN_STEP = P_WEIGHT_SAW_STEP_UP_MIN_STEP;
    default_host.WEIGHT_SAW_STEP_DN_DIV = P_WEIGHT_SAW_STEP_DN_DIV;
    default_host.WEIGHT_MSEC_DELAY = P_WEIGHT_MSEC_DELAY;
    default_host.MAX_WINDOW = RSR_TOP;
    default_host.MAX_LATENCY = P_MAX_LATENCY;
    default_host.MAX_LATENCY_DROP = P_MAX_LATENCY_DROP;
    default_host.MAX_ALLOWED_BUF_LEN = P_MAX_ALLOWED_BUF_LEN;
    default_host.MAX_REORDER = P_MAX_REORDER;
    default_host.MAX_IDLE_TIMEOUT = P_MAX_IDLE_TIMEOUT;
    default_host.FRAME_COUNT_SEND_LWS = P_FRAME_COUNT_SEND_LWS;
    default_host.PING_INTERVAL = P_PING_INTERVAL;
    default_host.TUN_TXQUEUE_LEN = P_TUN_TXQUEUE_LEN;
    default_host.TCP_CONN_AMOUNT = P_TCP_CONN_AMOUNT;
    default_host.START_WEIGHT = 0;
    default_host.RT_MARK = -1;
    //default_host.MAX_TUNNELS_NUM = P_MAX_TUNNELS_NUM;

    /* Start logging to syslog and stderr */
    vlog_open("vtrunkd", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

    while ((opt = getopt(argc, argv, "S:R:mDisf:P:L:t:M:nQpvh?")) != EOF) {
        switch (opt) {
        case 'S':
            vtun.shm_key = atoi(optarg);
            break;
        case 'R':
            vtun.start_port = 0;
            char *start_port = optarg;
            char *end_port = strchr(start_port, '-');
            *end_port = '\0';
            end_port++;
            vtun.start_port = atoi(start_port);
            vtun.end_port = atoi(end_port);
            break;
        case 'm':
            if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
                perror("Unable to mlockall()");
                exit(-1);
            }
            break;
        case 'D':
            // enable debug
            debug_trace = 1;
            break;
        case 'i':
            vtun.svr_type = VTUN_INETD;
        case 's':
            svr = 1;
            break;
        case 'L':
            vtun.svr_addr = strdup(optarg);
            if (svr) { // WARNING! -s option is required BEFORE -L for server to bind correctly
                vtun.bind_addr.type = VTUN_ADDR_NAME;
                vtun.bind_addr.name = strdup(optarg);
            }
            break;
        case 'P':
            vtun.bind_addr.port = atoi(optarg);
            break;
        case 'f':
            vtun.cfg_file = strdup(optarg);
            break;
        case 'n':
            daemon = 0;
            break;
        case 'Q':
            vtun.quiet = 1;
            break;
        case 'V':
            vtun.quiet = 0;
            break;
        case 'p':
            vtun.persist = 1;
            break;
        case 't':
            vtun.timeout = atoi(optarg);
            break;
        case 'M':
            vtun.MAX_TUNNELS_NUM = atoi(optarg);
            break;
        case 'v':
            version();
            exit(0);
            break;
        case 'h':
        case '?':
            usage();
            exit(0);
            break;
        default:
            usage();
            exit(1);
        }
    }
    reread_config(0);

    if (vtun.syslog != LOG_DAEMON) {
        /* Restart logging to syslog using specified facility  */
        vlog_close();
        vlog_open("vtrunkd", LOG_PID | LOG_NDELAY | LOG_PERROR, vtun.syslog);
    }

    if (!svr) {
        if ( argc - optind < 2 ) {
            usage();
            exit(1);
        }
        hst = argv[optind++];

        if ( !(host = find_host(hst)) ) {
            vlog(LOG_ERR, "Host %s not found in %s", hst, vtun.cfg_file);
            exit(1);
        }

        vtun.svr_name = strdup(argv[optind]);
    }

    /*
     * Now fill uninitialized fields of the options structure
     * with default values.
     */
    if (vtun.bind_addr.port == -1)
        vtun.bind_addr.port = VTUN_PORT;
    if (vtun.persist == -1)
        vtun.persist = 0;
    if (vtun.timeout == -1)
        vtun.timeout = VTUN_TIMEOUT;
    if (vtun.MAX_TUNNELS_NUM == -1)
        vtun.MAX_TUNNELS_NUM = P_MAX_TUNNELS_NUM;

    switch ( vtun.svr_type ) {
    case -1:
        vtun.svr_type = VTUN_STAND_ALONE;
        break;
    case VTUN_INETD:
        sock = dup(0);
        dofork = 0;
        break;
    }

    if ( daemon ) {
        if ( dofork && fork() )
            exit(0);
        struct rlimit core_limit;
        core_limit.rlim_cur = RLIM_INFINITY;
        core_limit.rlim_max = RLIM_INFINITY;

        if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
            vlog(LOG_ERR, "setrlimit: Warning: core dumps may be truncated or non-existant reason %s (%d)", strerror(errno), errno);
        }
        /* Direct stdin,stdout,stderr to '/dev/null' */
        fd = open("/dev/null", O_RDWR);
        close(0); dup(fd);
        close(1); dup(fd);
        close(2); dup(fd);
        close(fd);

        setsid();

        chdir("/");
#ifdef DEBUGG
        // now init the profiler; don;t forget to set GMON_OUT_PREFIX
        extern void _start (void), etext (void);
        monstartup ((u_long) &_start, (u_long) &etext);
#endif
    }

    if (svr) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = reread_config;
        sigaction(SIGHUP, &sa, NULL);

        init_title(argc, argv, env, "vtrunkd[s]: ");

        if ( vtun.svr_type == VTUN_STAND_ALONE )
            write_pid();

        server(sock);
    } else {
        init_title(argc, argv, env, "vtrunkd[c]: ");
        client(host);
    }

    closelog();

    return 0;
}

/*
 * Very simple PID file creation function. Used by server.
 * Overrides existing file.
 */
void write_pid(void)
{
    FILE *f;

    if ( !(f = fopen(VTUN_PID_FILE, "w")) ) {
        vlog(LOG_ERR, "Can't write PID file");
        return;
    }

    fprintf(f, "%d", (int)getpid());
    fclose(f);
}

void reread_config(int sig)
{
    if ( !read_config(vtun.cfg_file) ) {
        vlog(LOG_ERR, "No hosts defined");
        exit(1);
    }
}

void usage(void)
{
    printf("vtrunkd version %s\n", VERSION); // new versioning
    printf("Usage: \n");
    printf("  Server:\n");
    printf("\tvtrunkd <-s> [-f file] [-P port] [-L local address] [-S SHM key] [-D (enable packet debug)] [-Q|-V]\n");
    printf("  Client:\n");
    /* I don't think these work. I'm disabling the suggestion - bish 20050601*/
    /* these actually do work. At least given in config file -- grandrew 20110507*/
    printf("\tvtrunkd [-f file] " /* [-P port] [-L local address] */
           "[-p] [-m] [-t timeout] <host profile> <server address> [-S SHM key] [-D (enable packet debug)] [-Q|-V]\n");
}

void version() {
    printf("vtrunkd ver %s\n", VERSION);
}
