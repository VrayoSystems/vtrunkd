/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011  Andrew Gryaznov <realgrandrew@gmail.com>

   Vtrunkd has been derived from VTUN package by Maxim Krasnyansky. 
   vtun Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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
#include <semaphore.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdint.h>

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

/* Max lenght of device name */
#define VTUN_DEV_LEN  20 

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
// can not add weight penalty (increase weight units) faster than this
#define P_PEN_USEC_IMMUNE 500000 // microseconds

// this actually affects how much resends will occur, milliseconds
#define P_MAX_LATENCY 2000 // milliseconds
// DROP shall not be reached! if reached - it indicates problems
#define P_MAX_LATENCY_DROP 5 // seconds
// this is hardly dependent on MAX_REORDER (e.g. MR90/MABL350)
#define P_MAX_ALLOWED_BUF_LEN 250 // int
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
#define P_TUN_TXQUEUE_LEN 100 // int
// maximum VPNs allocated at server side (aaffects SHM memory)
#define P_MAX_TUNNELS_NUM 20
// amount of tcp channels per process (vpn link) requested by CLIENT mode
#define P_TCP_CONN_AMOUNT 5 // int


/* Compiled-in values */
// defines period of LWS notification; helps reduce resend_buf outage probability
// uses TICK_SECS as base interval
#define LWS_NOTIFY_PEROID 3 // seconds; TODO: make this configurable
// should be --> MAX_ALLOWED_BUF_LEN*TCP_CONN_AMOUNT to exclude outages
#define FRAME_BUF_SIZE 400 // int
// to avoid drops absolutely, this should be able to hold up to MAX_LATENCY_DROP*(TCP_CONN_AMOUT+1)*speed packets!
#define RESEND_BUF_SIZE 1200 // int
// maximum compiled-in buffers for tcp channels per link
#define MAX_TCP_LOGICAL_CHANNELS 100 // int
// max aggregated VPN-links compiled-in (+ some extras for racing)
#define MAX_TCP_PHYSICAL_CHANNELS 7
// 10 seconds to start accepting tcp channels; otherwise timeout
#define CHAN_START_ACCEPT_TIMEOUT 10

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
   int PEN_USEC_IMMUNE;
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

#define HAVE_MSGHDR_MSG_CONTROL

#define TERM_NONFATAL 1000
#define TERM_FATAL 1001

struct _write_buf {
    struct frame_llist frames;
    //struct frame_llist free_frames; /* init all elements here */
    struct frame_llist now; // maybe unused
    unsigned long last_written_seq; // last pack number has written into device
    struct timeval last_write_time; // into device
    int buf_len;
    int broken_cnt;
    unsigned long remote_lws; // last written packet into device on remote side
    unsigned long last_lws_notified;
};

/**
 * local structure
 * per channel
 */
struct time_lag_info {
	uint64_t time_lag_sum;
	uint16_t time_lag_cnt;
	uint8_t once_flag:1;
};

/**
 * local structure
 * for local pid
 */
struct time_lag {
	uint32_t time_lag_remote; // calculater here
	uint32_t time_lag; // get from another side
	int pid_remote; // pid from another side
	int pid; // our pid
};

/**
 * global structure
 */
struct conn_stats {
    int pid; /* current pid */
    int pid_remote; // pid from another side
    long int weight; /* bandwith-delay product */
    long int last_tick; // watch dog timer
    // time_lag = old last written time - new written time (in millisecond)
    // and get from another side
    uint32_t time_lag_remote;// calculated here
    uint32_t time_lag; // get from another side
    uint32_t current_speed; // current physical channel's speed
};


struct conn_info {
    // char sockname[100], /* remember to init to "/tmp/" and strcpy from byte *(sockname+5) or &sockname[5]*/ // not needed due to devname
    char devname[50];
    sem_t fd_sem;
    struct frame_seq frames_buf[FRAME_BUF_SIZE];			// memory for write_buf
    struct frame_seq resend_frames_buf[RESEND_BUF_SIZE];	// memory for resend_buf
    int resend_buf_idx;
    struct _write_buf write_buf[MAX_TCP_LOGICAL_CHANNELS]; // input
    struct frame_llist wb_free_frames; /* init all elements here */ // input (to device)
    sem_t write_buf_sem;
    struct _write_buf resend_buf[MAX_TCP_LOGICAL_CHANNELS]; // output
    struct frame_llist rb_free_frames; /* init all elements here */ // output (to net)
    sem_t resend_buf_sem;
    unsigned long seq_counter[MAX_TCP_LOGICAL_CHANNELS];	// packet sequense counter
    short usecount;
    short lock_pid;	// who has locked shm
    char normal_senders;
    int rxmt_mode_pid; // unused?
    sem_t stats_sem;
    struct conn_stats stats[MAX_TCP_PHYSICAL_CHANNELS]; // need to synchronize because can acces few proccees
    //int broken_cnt;
    long int lock_time;
    long int alive;
    int rdy; /* ready flag */
    sem_t AG_flags_sem; // semaphore for AG_ready_flags and channels_mask
    uint16_t AG_ready_flags; // contain flags for all physical channels 1 - retransmit mode, 0 - ready to aggregation
    uint16_t channels_mask; // 1 - channel is working 0 - channel is dead
};

struct resent_chk {
    unsigned long seq_num;
    int chan_num;
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

/* Global options */
struct vtun_opts {
   int  timeout;
   int  persist;
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
   int  svr_type;	 /* Server mode */
   int  syslog; 	 /* Facility to log messages to syslog under */
};
#define VTUN_STAND_ALONE	0 
#define VTUN_INETD		1	

#ifndef BUILD_DATE
  #define BUILD_DATE "build_XXXXXXXXXX"
#endif

extern struct vtun_opts vtun;

void server(int sock);
void client(struct vtun_host *host);
int  tunnel(struct vtun_host *host, int srv);
int  read_config(char *file);
struct vtun_host * find_host(char *host);

int read_fd_full(int *fd, char *dev);

#endif
