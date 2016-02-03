/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016 Vrayo Systems Ltd. team 

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
 * vtun.h,v 1.7.2.6.2.6 2006/11/16 04:04:17 mtbishop Exp
 */ 

#ifndef _VTUN_H
#define _VTUN_H
#include "llist.h"
#include "frame_llist.h"
#include "const.h"
#include "version.h"
#include <semaphore.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "speed_algo.h"
#include "packet_code.h"

/* Default VTUN port */
#define VTUN_PORT 5000

/* Default VTUN connect timeout in sec */
#define VTUN_CONNECT_TIMEOUT 30

/* General VTUN timeout for several operations, in sec */
#define VTUN_TIMEOUT 30

/* Number of seconds for delay after pppd startup*/
#define VTUN_DELAY_SEC  10 

/* Statistic interval in seconds */
#define VTUN_STAT_IVAL  60  /* 1 min */ /* this will also trigger timeout for socket read */


// these are tunable algorithm parameters...

/* Algorithm configurable runtime defaults */
// general system resolution and stats output period
#define P_TICK_SECS 3 // seconds
// timed weight division 
#define P_RXMIT_CNT_DROP_PERIOD 1 // seconds
// peak weight cut
#define P_MAX_WEIGHT_NORM  19000 // unit*scale
// scaling
#define P_WEIGHT_SCALE 100 // 1/unit; [e.g. 100: 100/100 = 1.00 ]
// how much to approximate weight to "start_weight" each RXMIT_CNT_DROP_PERIOD seconds
#define P_WEIGHT_SMOOTH_DIV  000 // (1/s)*scale
// TODO: DIV_PROPORTIONAL - drop weight proportional to data sent amount; for links with mostly static 
// how much to tend to approximate to start_weight.
#define P_WEIGHT_START_STICKINESS  0 // (1/s)*scale
// nonlinear saw-like weight function step-up smoothness (the higher value the lower is step up and smoother penalty)
#define P_WEIGHT_SAW_STEP_UP_DIV 60 // (1/s)
// minimal step up on weight. With channels with most likely high-difference in speeds 'smooth closeup'
// may be too smooth to quickly reach optimum but setting lower smoothness results in system resonanse
// this threshold helps to reach optimum more quickly with some loss of precision
#define P_WEIGHT_SAW_STEP_UP_MIN_STEP 0 // 1/ms -> in P_WEIGHT_MSEC_DELAY units
// nonlinear step down smoothness; the higher the smoother and less aggressive return to uncontrolled send
#define P_WEIGHT_SAW_STEP_DN_DIV 5 // (1/s)
// sets control delay (and granularity)
#define P_WEIGHT_MSEC_DELAY 2000 // micro(!!)seconds

// this actually affects how much resends will occur, milliseconds
#define P_MAX_LATENCY 2000 // milliseconds
// DROP shall not be reached! if reached - it indicates problems
#define P_MAX_LATENCY_DROP 5 // seconds
// this is hardly dependent on MAX_REORDER (e.g. MR90/MABL350)
#define P_MAX_ALLOWED_BUF_LEN 1800 // int // WARNING: need large buffer for rtt tweaking on fast chans! (500ms * 2MB/s = at least 1MB!
// very sensitive parameter - setting it huge will stuck into MAX_LATENCY* product always
#define P_MAX_REORDER 90 // int
// seconds to timeout. set to 10 for mostly-stable links, to 30 for very-unstable and jitterish
#define P_MAX_IDLE_TIMEOUT 20 // seconds
// notify each N frames of successful writedown with all misses and reordering resolved
// should be < FRAME_BUF_SIZE/TCP_CONN_AMOUNT
#define P_FRAME_COUNT_SEND_LWS 50 // int frames
// seconds to ping. must be less than MAX_IDLE_TIMEOUT, set to higher to reduce idle traffic
#define P_PING_INTERVAL 1 // seconds
// this controls jitter and congestion on tun device (set to higher on faster links, lower on slower)
// setting it to low value will result in packet loss on full load; setting too high will result in significant tx delay
#define P_TUN_TXQUEUE_LEN 1000 // int
// maximum VPNs allocated at server side (aaffects SHM memory)
#define P_MAX_TUNNELS_NUM 20
// amount of tcp channels per process (vpn link) requested by CLIENT mode
#define P_TCP_CONN_AMOUNT 1 // without service channel
// big jitter
#define ABSOLUTE_MAX_JITTER 2500 // in ms
// ag switch compare parameter always less than 1 but higher than 0
#define AG_FLOW_FACTOR 0.2


/* Compiled-in values */
// defines period of LWS notification; helps reduce resend_buf outage probability
// uses TICK_SECS as base interval
#define LWS_NOTIFY_PEROID 3 // seconds; TODO: make this configurable
#define LWS_NOTIFY_MAX_SUB_SEQ 30

// 10 seconds to start accepting tcp channels; otherwise timeout
#define CHAN_START_ACCEPT_TIMEOUT 10

#define TCP_MAX_REORDER 3 // general knowledge
/* End of configurable part */

struct vtun_sopt {
    char *dev;
    char *laddr;
    int  lport;
    char *raddr;
    int  rport;
};

struct vtun_stat {
   unsigned long byte_in;
   unsigned long byte_out;
   unsigned long comp_in;
   unsigned long comp_out;
   FILE *file;
};

struct vtun_cmd {
   char *prog;
   char *args;
   int  flags;
};
/* Command flags */
#define VTUN_CMD_WAIT	0x01 
#define VTUN_CMD_DELAY  0x02
#define VTUN_CMD_SHELL  0x04

struct vtun_addr {
   char *name;
   char *ip;
   int port;
   int type;
};
/* Address types */
#define VTUN_ADDR_IFACE	0x01 
#define VTUN_ADDR_NAME  0x02

struct vtun_host {
   char *host;
   char *passwd;
   char *dev;

   llist up;
   llist down;

   int  flags;
   int  timeout;
   int  spd_in;
   int  spd_out;
   int  zlevel;
   int  cipher;

   int  rmt_fd;
   int  loc_fd;

   uint16_t start_port;
   uint16_t end_port;

   /* Persist mode */
   int  persist;

   /* Multiple connections */
   int  multi;

   /* Keep Alive */
   int ka_interval;
   int ka_failure;

   /* Source address */
   struct vtun_addr src_addr;

   struct vtun_stat stat;

   struct vtun_sopt sopt;
   
   /* Algorithm parameters */
   
   int TICK_SECS;
   int RXMIT_CNT_DROP_PERIOD;
   int MAX_WEIGHT_NORM;
   int WEIGHT_SCALE;
   int WEIGHT_SMOOTH_DIV;
   int WEIGHT_START_STICKINESS;
   int WEIGHT_SAW_STEP_UP_DIV;
   int WEIGHT_SAW_STEP_UP_MIN_STEP;
   int WEIGHT_SAW_STEP_DN_DIV;
   int WEIGHT_MSEC_DELAY;
   int MAX_WINDOW;
   int MAX_LATENCY;
   int MAX_LATENCY_DROP;
   int MAX_ALLOWED_BUF_LEN;
   int MAX_REORDER;
   int MAX_IDLE_TIMEOUT;
   int FRAME_COUNT_SEND_LWS;
   int PING_INTERVAL;
   int TUN_TXQUEUE_LEN;
   int TCP_CONN_AMOUNT;
   int START_WEIGHT;
   int RT_MARK;
   
};



//
// -= these are not tunable... =-
//

// absolutly minimal weight
#define MIN_WEIGHT 100000000

// asserts of frame seq_num difference 
#define STRANGE_SEQ_FUTURE 1000 // unsigned long int frames
#define STRANGE_SEQ_PAST 50000 // unsigned long int frames

// SHM key
#define SHM_TUN_KEY 567888

// these are static ...

// RMODE (rxmit mode) tunes % stickiness; mostly unused
#define MAX_RETRANSMIT_RMODE 1

// when to timeout fd_server process and free shm memory and tun device
#define PROCESS_FD_SHM_TIMEOUT 30 // seconds

// statics
#define MODE_NORMAL 0
#define MODE_RETRANSMIT 1

// start val
#define SEQ_START_VAL 10
#define SUP_TCP_CONN_TIMEOUT_SECS 15

// more frame flags
#define FLAGS_RESERVED 200 // 0-200 is reserved for flags
#define FRAME_MODE_NORM 0
#define FRAME_MODE_RXMIT 1
#define FRAME_JUST_STARTED 2
#define FRAME_PRIO_PORT_NOTIFY 3
#define FRAME_LAST_WRITTEN_SEQ 4
#define FRAME_TIME_LAG 5 // time lag from favorite CONN - Issue #11
#define FRAME_DEAD_CHANNEL 6
#define FRAME_CHANNEL_INFO 7
#define FRAME_LOSS_INFO 8
#define FRAME_L_LOSS_INFO 9
#define FRAME_REDUNDANCY_CODE 10

#define HAVE_MSGHDR_MSG_CONTROL

#define TERM_NONFATAL 1000
#define TERM_FATAL 1001

#define CUBIC_C 0.2

#define AG_MODE 1
#define R_MODE 0


#define PLP_BUF_TIMEOUT_MS 5000 // timeout for PLP buffer values


struct streams_seq {
    unsigned int seq;
    struct timeval ts;
    int packets;
};


#include "v_struct.h"

struct resent_chk {
    unsigned long seq_num;
    int chan_num;
};

#define MAX_NUM_RESEND 1 //max number of resend in retransmit mode

struct last_sent_packet {
    uint32_t seq_num;
    unsigned long num_resend; //how many time resend
};

#define SEM_KEY 567000
#define FD_SEM 0
#define WB_SEM 1
#define RB_SEM 2

extern llist host_list;

/* Flags definitions */
#define VTUN_TTY        0x0100
#define VTUN_PIPE       0x0200
#define VTUN_ETHER      0x0400
#define VTUN_TUN        0x0800
#define VTUN_TYPE_MASK  (VTUN_TTY | VTUN_PIPE | VTUN_ETHER | VTUN_TUN) 

#define VTUN_TCP        0x0010  
#define VTUN_UDP        0x0020  
#define VTUN_PROT_MASK  (VTUN_TCP | VTUN_UDP) 
#define VTUN_KEEP_ALIVE 0x0040	

#define VTUN_ZLIB       0x0001
#define VTUN_LZO        0x0002
#define VTUN_SHAPE      0x0004
#define VTUN_ENCRYPT    0x0008

/* Cipher options */
#define VTUN_ENC_BF128ECB	1
#define VTUN_ENC_BF128CBC	2
#define VTUN_ENC_BF128CFB	3
#define VTUN_ENC_BF128OFB	4
#define VTUN_ENC_BF256ECB	5
#define VTUN_ENC_BF256CBC	6
#define VTUN_ENC_BF256CFB	7
#define VTUN_ENC_BF256OFB	8

#define VTUN_ENC_AES128ECB	9
#define VTUN_ENC_AES128CBC	10
#define VTUN_ENC_AES128CFB	11
#define VTUN_ENC_AES128OFB	12
#define VTUN_ENC_AES256ECB	13
#define VTUN_ENC_AES256CBC	14
#define VTUN_ENC_AES256CFB	15
#define VTUN_ENC_AES256OFB	16

/* Mask to drop the flags which will be supplied by the server */
#define VTUN_CLNT_MASK  0xf000

#define VTUN_STAT	0x1000
#define VTUN_PERSIST    0x2000

/* Constants and flags for VTun protocol */
#define VTUN_FRAME_SIZE     2048
#define VTUN_FRAME_OVERHEAD 100
#define VTUN_FSIZE_MASK 0x0fff

#define VTUN_CONN_CLOSE 0x1000
#define VTUN_ECHO_REQ	0x2000
#define VTUN_ECHO_REP	0x4000
#define VTUN_BAD_FRAME  0x8000

#define RESENT_MEM 1000 // very heavy load on this

/* Authentication message size */
#define VTUN_MESG_SIZE	50

/* Support for multiple connections */
#define VTUN_MULTI_DENY		0  /* no */ 
#define VTUN_MULTI_ALLOW	1  /* yes */
#define VTUN_MULTI_KILL		2

/* keep interface in persistant mode */
#define VTUN_PERSIST_KEEPIF     2

/* Values for the signal flag */

#define VTUN_SIG_TERM 1
#define VTUN_SIG_HUP  2

/* Authentication errors */
#define D_NOSHAKE1 1
#define D_NOSHAKE2 2
#define D_ST_CHAL 3
#define D_CHAL 4
#define D_NOHOST 5
#define D_NOMULT 6
#define D_GREET 7
#define D_PWD 8
#define D_NOREAD 9
#define D_OTHER 10


/* Global options */
struct vtun_opts {
   int  timeout;
   int  persist;
   int quiet;
   int MAX_TUNNELS_NUM;

   char *cfg_file;

   char *shell; 	 /* Shell */
   char *ppp;		 /* Command to configure ppp devices */
   char *ifcfg;		 /* Command to configure net devices */
   char *route;		 /* Command to configure routing */
   char *fwall; 	 /* Command to configure FireWall */
   char *iproute;	 /* iproute command */

   char *svr_name;       /* Server's host name */
   char *svr_addr;       /* Server's address (string) */
   struct vtun_addr bind_addr;	 /* Server should listen on this address */
   uint16_t start_port;
   uint16_t end_port;
   int  svr_type;	 /* Server mode */
   int  syslog; 	 /* Facility to log messages to syslog under */
   key_t shm_key;
};
#define VTUN_STAND_ALONE	0 
#define VTUN_INETD		1	

#ifndef BUILD_DATE
  #define BUILD_DATE VERSION
#endif

extern struct vtun_opts vtun;
extern int debug_trace;

void server(int sock);
void client(struct vtun_host *host);
int  tunnel(struct vtun_host *host, int srv, sem_t * shm_sem);
int  read_config(char *file);
struct vtun_host * find_host(char *host);

int read_fd_full(int *fd, char *dev);

#endif
