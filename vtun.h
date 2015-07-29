/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011  Andrew Gryaznov <realgrandrew@gmail.com>,
   Andrey Kuznetsov <andreykyz@gmail.com>

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
#define P_MAX_ALLOWED_BUF_LEN 4000 // int // WARNING: need large buffer for rtt tweaking on fast chans! (500ms * 2MB/s = at least 1MB!
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
// should be --> MAX_ALLOWED_BUF_LEN*TCP_CONN_AMOUNT to exclude outages
#define FRAME_BUF_SIZE 4500 // int WARNING: see P_MAX_ALLOWED_BUF_LEN
// to avoid drops absolutely, this should be able to hold up to MAX_LATENCY_DROP*(TCP_CONN_AMOUT+1)*speed packets!
#ifdef LOW_MEM
    #define RESEND_BUF_SIZE 600 // int
    #define JS_MAX 1000 // data for logs, * 3 times is allocated
#else
    #define RESEND_BUF_SIZE 3000 // int
    #define JS_MAX 20000 // 100kb string len of JSON logs * 3 size is used!
#endif
// maximum compiled-in buffers for tcp channels per link
#define MAX_TCP_LOGICAL_CHANNELS 7//100 // int
// max aggregated VPN-links compiled-in (+ some extras for racing)
#define MAX_TCP_PHYSICAL_CHANNELS 7
// 10 seconds to start accepting tcp channels; otherwise timeout
#define CHAN_START_ACCEPT_TIMEOUT 10
#define FAST_RESEND_BUF_SIZE (MAX_TCP_PHYSICAL_CHANNELS*3)

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
#define FRAME_DEAD_CHANNEL 6
#define FRAME_CHANNEL_INFO 7
#define FRAME_LOSS_INFO 8
#define FRAME_L_LOSS_INFO 9
#define FRAME_REDUNDANCY_CODE 10

#define HAVE_MSGHDR_MSG_CONTROL

#define TERM_NONFATAL 1000
#define TERM_FATAL 1001

#define C_LOW 0.1
#define C_MED 0.2
#define C_HI 0.5

#define AG_MODE 1
#define R_MODE 0

#define W_STREAMS_AMT 10000 // amount of streams (in collisions) of write buffer retransmit seq queueing

#define PLP_BUF_SIZE 20 // size of buffer used for old values of PBL for PLP calc
#define PLP_BUF_TIMEOUT_MS 5000 // timeout for PLP buffer values

#define FLUSHED_PACKET_ARRAY_SIZE 1000

#define SESSION_NAME_SIZE 50
#define CHECK_SZ 256 // size of bit check field
struct _write_buf {
    struct frame_llist frames;
    //struct frame_llist free_frames; /* init all elements here */
    struct frame_llist now; // maybe unused
    unsigned long last_written_seq; // last pack number has written into device
    unsigned long wr_lws; // last pack number has written into device
    unsigned long last_received_seq[MAX_TCP_PHYSICAL_CHANNELS]; // max of 30 physical channels
    unsigned long last_received_seq_shadow[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder
    unsigned long possible_seq_lost[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder
    unsigned long packet_lost_state[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder

    struct timeval last_write_time; // into device
    int buf_len;
    unsigned long remote_lws; // last written packet into device on remote side
    unsigned long last_lws_notified;
    uint16_t complete_seq_quantity;
    int top_packet_physical_channel_num;
};

/**
 * local structure
 * per channel
 */
struct time_lag_info {
	uint64_t time_lag_sum;
	uint16_t time_lag_cnt;
	uint32_t packet_lag_sum; // lag in packets
	uint16_t packet_lag_cnt;
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

struct speed_chan_data_struct {
    uint32_t up_current_speed; // current physical channel's speed(kbyte/s) = up_data_len_amt / time
    uint32_t up_recv_speed;
    uint32_t up_data_len_amt; // in byte
    uint32_t down_current_speed; // current physical channel's speed(kbyte/s) = down_data_len_amt / time
    uint32_t down_data_len_amt; // in byte

    uint32_t down_packets; // per last_tick. need for speed calculation
    uint32_t down_packet_speed;
    uint32_t send_q_loss;

};

/**
 * global structure
 */
struct conn_stats {
    char name[SESSION_NAME_SIZE];
    int lssqn; // TODO: remove this after tests
    int hsnum; /* session name hash - identical between prodesses */
    int pid; /* current pid */
    int pid_remote; // pid from another side
    long int weight; /* bandwith-delay product */
    long int last_tick; // watch dog timer
    // time_lag = old last written time - new written time (in millisecond)
    // and get from another side
    uint32_t time_lag_remote;// calculated here
    uint32_t time_lag; // get from another side
    struct speed_chan_data_struct speed_chan_data[MAX_TCP_LOGICAL_CHANNELS];
    uint32_t max_upload_speed;
    uint32_t max_send_q;
    uint32_t max_send_q_avg;
    int32_t send_q_limit;
    uint16_t miss_packets_max; // get from another side
    int32_t ACK_speed;
    int32_t max_ACS2;
    int32_t max_PCS2;
    int32_t max_sqspd;
    int32_t W_cubic;
    int32_t W_cubic_u;
    int32_t rsr; // sync on stats_sem
    int rtt_phys_avg; // accurate on idling
    int rtt2; // RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int srtt2_10; // COPIED from info RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int srtt2_100; // COPIED from info RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int sqe_mean;
    int sqe_mean_lossq;
    int my_max_send_q_chan_num;
    int ag_flag_local;
    int hold;
    int channel_dead;
    int exact_rtt;
    int rttvar; // pure ms
    int head_in;
    int head_use;
    struct timeval bdp1;
    struct timeval real_loss_time;
    int packet_speed_ag;
    int packet_speed_rmit;
    int local_seq_num_beforeloss;
    int packet_recv_counter_afterloss;
    int l_pbl;
    int l_pbl_recv;
    int brl_ag_enabled;
    int l_pbl_tmp; 
    int l_pbl_unrec;
    int l_pbl_tmp_unrec; 
    int pbl_lossed;
    int pbl_lossed_cnt;
    int packet_upload_cnt;
    int packet_upload_spd;
    struct timeval packet_upload_tv;
    struct timeval agon_time;
    struct timeval agoff_immunity_tv;
    int recv_mode;
    struct timeval plp_immune;
    int l_pbl_recv_saved;
    int l_pbl_tmp_saved;
    int pbl_lossed_saved;
    int pbl_lossed_cnt_saved;
    int remote_head_channel;
    uint32_t la_sqn; // last received global seq_num ACK
    int loss_send_q;
    int32_t ACK_speed_avg;  /**< Moving average of @see ACK_speed */
};
/**
 * Structure for garbage statistic and information
 * about logical channels. Include service channel[0]
 */
struct logical_status {
    /** Information about tcp connection */
    uint16_t rport;  /**< remote(dst) tcp port */
    uint16_t lport;  /**< local(src) tcp port */
    int descriptor; /** file descriptor associated with this connection*/

    /** AVG measuring speed */
    uint32_t upload;    /**< upload speed */
    uint32_t up_len;    /**< how much bytes are uploaded */
    uint32_t up_packets; /**< how much packets are uploaded */
    uint32_t download;  /**< download speed */
    uint32_t down_len;    /**< how much bytes are downloaded */
    uint32_t packet_download;
    uint32_t down_packets;
    uint32_t rtt;       /**< rtt is measured by vtrunkd */
    uint32_t tcp_rtt;   /**< rtt is said by @see get_format_tcp_info() */
    uint32_t magic_rtt;   /**< rtt based on @see ACK_speed_avg */

    /** Net buffer control information */
    uint32_t send_q;    /**< current send_q value */
    struct timeval send_q_time;
    uint32_t send_q_old;    /**< previous send_q value */
    int32_t send_q_limit;  /**< current send_q_limit value */
    int32_t ACK_speed[SPEED_AVG_ARR];      /**< Speed based on how fast ACK packets come back. Last 10 measurements @see avg_count */
    int avg_count;         /**< Counter for @see ACK_speed_avg calculate*/
    uint32_t local_seq_num;
    uint32_t local_seq_num_recv;
    uint32_t local_seq_num_beforeloss; /** used for max_reorder support */
    struct timeval loss_time; /** time from last detected packet loss on this chan_num (incoming stream) */
    struct timeval last_recv_time;
    struct timeval last_info_send_time;
    int16_t packet_loss_counter;
    uint16_t packet_recv_counter;
    uint16_t packet_recv_counter_afterloss;
    struct timeval packet_recv_time;
    int16_t packet_loss;
    uint16_t packet_recv;
    uint32_t packet_seq_num_acked;
    uint32_t packet_recv_period;
    uint32_t packet_recv_upload;
    uint32_t packet_recv_upload_avg;
    struct timeval get_tcp_info_time_old; /**< Previous value of @see get_tcp_info_time.*/
    int32_t ACS2;
    uint32_t old_packet_seq_num_acked;
    uint32_t bytes_put;
};

struct _smalldata {
    double *ACS;
    double *rtt;
    double *w;
    double *send_q; // static 'x' axist
    struct timeval *ts;
};



/**
 * Structure for storing all information about
 * physical channel
 */
struct phisical_status { // A.K.A. "info"
    /** Common information */
    int process_num;    /**< Current physical channel's number */
    int pid; /**< Our pid is got on this side by getpid()  */
    int remote_pid; /**< Pid is got from another side by net */
    int tun_device; /**< /dev/tun descriptor */
    int srv; /**< 1 - if I'm server and 0 - if I'm client */
    int head_channel;
#define LOSSED_BACKLOG_SIZE 100
    struct {
        unsigned int seq_num;
        unsigned int local_seq_num;
    } lossed_loop_data[LOSSED_BACKLOG_SIZE]; // array of seq_nums for lossed detect
    int lossed_complete_received;
    int lossed_last_received;
    /** Collect statistic*/
    int mode;   /**< local aggregation flag, can be AG_MODE and R_MODE */
    struct timeval current_time;    /**< Is last got time.*/
    struct timeval current_time_old; /**< Previous value of @see current_time. Need for for the Tick module */
    uint32_t max_send_q_avg;
    uint32_t max_send_q_avg_arr[SPEED_AVG_ARR];
    uint32_t max_send_q_min;
    uint32_t max_send_q_max;
    uint32_t max_send_q_calc; // = cwnd * mss
    int max_send_q_counter;
    unsigned int speed_efficient;
    unsigned int speed_resend;
    unsigned int speed_r_mode;
    unsigned int byte_efficient;
    unsigned int byte_resend;
    unsigned int byte_r_mode;
    int rtt;
    uint32_t packet_recv_upload_avg;
    struct timeval bdp1;

    /** Calculated values*/
    int32_t send_q_limit_cubic;
    int32_t send_q_limit;
    int32_t send_q_limit_cubic_max;
    int32_t rsr;
    struct timeval cycle_last;
    double C;
    double Cu;
    double B;
    double Bu;
    int W_u_max;
    int cubic_t_max_u;
    struct timeval u_loss_tv;
    int max_send_q;
    int max_send_q_u;
    struct timeval tv_sqe_mean_added;
    /** Logical channels information and statistic*/
    int channel_amount;   /**< Number elements in @see channel array AKA Number of logical channels already established(created)*/
    struct logical_status *channel; /**< Array for all logical channels */
    uint32_t session_hash_this; /**< Session hash for this machine */
    uint32_t session_hash_remote; /**< Session hash for remote machine */
    /** Events */
    int just_started_recv; /**< 0 - when @see FRAME_JUST_STARTED hasn't received yet and 1 - already */
    int check_shm; /**< 1 - need to check some shm values */
    uint32_t least_rx_seq[MAX_TCP_LOGICAL_CHANNELS]; // local store of least received seq_num across all phy

    uint32_t rtt2_lsn[MAX_TCP_LOGICAL_CHANNELS];
    int32_t max_sqspd;
    int32_t rtt2_send_q[MAX_TCP_LOGICAL_CHANNELS];
    struct timeval rtt2_tv[MAX_TCP_LOGICAL_CHANNELS]; 
    int rtt2; // max..?
    int srtt2_10; // max..?
    int srtt2_100; // max..?
    int srtt2var; 
    int dropping;
    struct timeval max_reorder_latency;
    struct timeval max_latency_drop;
    int eff_len;
    int send_q_limit_threshold;
    int exact_rtt;
    int flush_sequential; // PSL
    int ploss_event_flag; /** flag to detect PLOSS at tflush */
    int mean_latency_us;
    int max_latency_us;
    int frtt_us_applied;
    int PCS2_recv; // through FRAME_CHANNEL_INFO
    
    int i_plp; /** inverse packet loss probability (sent) */
    int p_lost;
    int last_loss_lsn;
    int i_rplp; /** inverse packet loss probability (received) */
    int r_lost;
    int last_rlost_lsn;

    int l_pbl;
    int pbl_cnt;
    struct {
        int pbl;
        struct timeval ts;
    } plp_buf[PLP_BUF_SIZE];
    
    int fast_pcs_old;
    int pcs_sent_old;
    struct timeval fast_pcs_ts;
    struct timeval last_sent_FLI;
    int last_sent_FLI_idx;
    int last_sent_FLLI_idx;
    int tpps_old;
    int32_t encap_streams_bitcnt;
    int encap_streams;
    int W_cubic_copy;
    int Wu_cubic_copy;
    struct timeval hold_time;
    struct timeval head_change_tv;
    int head_change_safe; // enough time passed since head change
    int frtt_remote_predicted;
    int select_immediate; /** immediate select times counter */
    int Wmax_saved;
    struct timeval Wmax_tv;
    int gsend_q_grow;
    int whm_cubic;
    int whm_rsr;
    int whm_send_q;
    int previous_idle;
    int head_send_q_shift;
    int head_send_q_shift_old;
};

#define LOSS_ARRAY 80
struct timed_loss {
    struct timeval timestamp;
    uint16_t name;
    int pbl;
    int psl;
    uint32_t sqn;
    int16_t who_lost;
};

struct streams_seq {
    unsigned int seq;
    struct timeval ts;
};


#define SHM_SYSLOG 100000

/** @struct conn_info
 *  @brief Common shm struct.
 *
 *  Description
 */
struct conn_info {
#ifdef SHM_DEBUG
    volatile char void11[4096];
    char void1[4096];
#endif
    // char sockname[100], /* remember to init to "/tmp/" and strcpy from byte *(sockname+5) or &sockname[5]*/ // not needed due to devname
    char devname[50];
    sem_t hard_sem;
    //sem_t frtt; // for frtt calculations and tokens
    sem_t tun_device_sem;
    int packet_debug_enabled;
    struct frame_seq frames_buf[FRAME_BUF_SIZE];			// memory for write_buf
    struct frame_seq resend_frames_buf[RESEND_BUF_SIZE];	// memory for resend_buf
    int resend_buf_idx;
    struct frame_seq fast_resend_buf[FAST_RESEND_BUF_SIZE];
    int fast_resend_buf_idx; // how many packets in fast_resend_buf
    struct _write_buf write_buf[MAX_TCP_LOGICAL_CHANNELS]; // input todo need to synchronize
    int write_sequential; // PBL sync by write_buf_sem
    int prev_flushed; // PBL/PSL flagsync by write_buf_sem
    struct frame_llist wb_just_write_frames[MAX_TCP_LOGICAL_CHANNELS];
    struct frame_llist wb_free_frames; /* init all elements here */ // input (to device)
    sem_t write_buf_sem; //for write buf, seq_counter
    struct _write_buf resend_buf[MAX_TCP_LOGICAL_CHANNELS]; // output
    struct frame_llist rb_free_frames; /* init all elements here */ // output (to net)
    sem_t resend_buf_sem; //for resend buf,  (ever between write_buf_sem if need double blocking)
    sem_t common_sem; // for seq_counter
    unsigned long seq_counter[MAX_TCP_LOGICAL_CHANNELS];	// packet sequense counter
    uint32_t flushed_packet[FLUSHED_PACKET_ARRAY_SIZE]; //sync by write_buf_sem
    short usecount;
    short lock_pid;	// who has locked shm
    char normal_senders;
    int rxmt_mode_pid; // unused?
    sem_t stats_sem;
    uint16_t miss_packets_max; // get from another side sync on stats_sem
    int buf_len_recv,buf_len, buf_len_recv_counter, buf_len_send_counter;
    struct conn_stats stats[MAX_TCP_PHYSICAL_CHANNELS]; // need to synchronize because can acces few proccees
    uint32_t miss_packets_max_recv_counter; // sync on stats_sem
    uint32_t miss_packets_max_send_counter; // sync on stats_sem
#ifdef SHM_DEBUG
    char void12[4096];
    char void2[4096];
#endif
    long int lock_time;
    long int alive;
    int rdy; /* ready flag */
    sem_t AG_flags_sem; // semaphore for AG_ready_flags and channels_mask
    uint32_t AG_ready_flag; // contain global flags for aggregation possible 0 - enable 1 - disable sync by AG_flags_sem
    uint32_t channels_mask; // 1 - channel is working 0 - channel is dead sync by AG_flags_sem
    uint32_t hold_mask; // 0 - channel is on hold, 1 = send allowed
    uint32_t need_to_exit; // sync by AG_flags_sem
    uint32_t session_hash_this; /**< Session hash for this machine sync by @see AG_flags_sem*/
    uint32_t session_hash_remote; /**< Session hash for remote machine sync by @see AG_flags_sem*/
    unsigned char check[CHECK_SZ]; // check-buf. TODO: fill with pattern "170" aka 10101010
    int head_process;
    int tflush_counter, tflush_counter_recv;
    struct timeval chanel_info_time;
    int flood_flag[MAX_TCP_PHYSICAL_CHANNELS];
    struct timeval last_flood_sent;
    struct timeval last_switch_time;
    int head_all;
    int max_chan;
    int dropping;
    int head_lossing;
    struct timeval forced_rtt_start_grow;
    int forced_rtt;
    int forced_rtt_recv; //in ms
    int idle;
    struct timeval drop_time; // time that we DROPPED by fact!
    struct timed_loss loss[LOSS_ARRAY]; // sync by write_buf_sem
    struct timed_loss loss_recv[LOSS_ARRAY]; // sync by recv_loss_sem
    struct timed_loss l_loss[LOSS_ARRAY]; // sync by write_buf_sem
    struct timed_loss l_loss_recv[LOSS_ARRAY]; // sync by recv_loss_sem
    sem_t recv_loss_sem;
    int loss_idx; // sync by write_buf_sem
    int l_loss_idx; // sync by write_buf_sem
    struct {
#define EFF_LEN_BUFF 15
        int warming_up;
        int counter;
        int len_num[EFF_LEN_BUFF];
        int sum;
    } eff_len; /**< Session hash for remote machine sync by @see common_sem*/
    int t_model_rtt100; // RTT multiplied by 100, in ms, for tcp model, calculated as toata avg rtt
    unsigned char streams[32];
    int single_stream;
    struct packet_sum packet_code[SELECTION_NUM][MAX_TCP_LOGICAL_CHANNELS];// sync by common_sem
    struct packet_sum packet_code_recived[MAX_TCP_LOGICAL_CHANNELS][BULK_BUFFER_PACKET_CODE];// sync by common_sem
    int packet_code_bulk_counter;
    struct packet_sum test_packet_code[MAX_TCP_LOGICAL_CHANNELS];
    struct timeval last_written_recv_ts;
    struct timeval last_head;
    int frtt_ms;
    int drtt;
    int frtt_local_applied;
    struct timeval frtt_smooth_tick;
    uint32_t ag_mask; // unsynced
    uint32_t ag_mask_recv; // unsynced
    int max_rtt_lag;
    int APCS_cnt; // counter for coming packets with AG mode
    int APCS; // speed for packets per seconf in AG mode coming to WB
    struct timeval APCS_tick_tv;
    struct timeval tpps_tick_tv;
    int tokens;
    struct timeval tokens_lastadd_tv;
    int max_chan_new;
    struct timeval head_detected_ts;
    int max_allowed_rtt; // MAR calculated against current speed and send_q
    int tpps;
    int forced_rtt_remote;
    int rttvar_worst;
    int remote_head_pnum; // remote head local pnum (for TPC)
    int write_speed_avg;
    int write_speed;
    int write_speed_b;
    int min_rtt_pnum;
    int max_rtt_pnum;
    int max_stuck_buf_len;
    int max_stuck_rtt;
    int lbuf_len_recv; // received lbuf_len
    int total_max_rtt;
    int total_max_rtt_var;
    int total_min_rtt;
    int total_min_rtt_var;
    int full_cwnd;
    struct timeval msbl_tick;
    struct timeval msrt_tick;
    int tokens_in_out;
    int ssd_gsq_old;
    int ssd_pkts_sent;
    int slow_start;
    int slow_start_recv;
    int slow_start_prev;
    int slow_start_allowed;
    int slow_start_force;
    struct timeval slow_start_tv;
    struct streams_seq w_streams[W_STREAMS_AMT];
    struct timeval cwr_tv; // for CWND Reserve 1s
    int head_send_q_shift_recv; 
    struct timeval head_change_htime_tv;
    int head_change_htime;
    int tokenbuf;
#ifdef SHM_DEBUG
    char void13[4096];
    char void3[4096];
#endif
    struct {
        sem_t logSem;
        char log[SHM_SYSLOG];
        int counter;
    } syslog;
};

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
int  tunnel(struct vtun_host *host, int srv);
int  read_config(char *file);
struct vtun_host * find_host(char *host);

int read_fd_full(int *fd, char *dev);

#endif
