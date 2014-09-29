/*
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network.

   Copyright (C) 2011  Andrew Gryaznov <realgrandrew@gmail.com>
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
 * linkfd.c,v 1.4.2.15.2.2 2006/11/16 04:03:23 mtbishop Exp
 */

/*
 * To fully utilize all capabilities you need linux kernel of at least >=2.6.25
 */

/*
 * TODO:
 * - collect LOSS stats: Packets Between Loss (PBL); Packets Sequentially Lost (PSL)
 * - overcome rtt,rtt2 < 1ms limitation(s)
 * - dynamic buffer: fixed size in MB (e.g. 5MB), dynamic packet list (Start-Byte-Rel; End-Byte-Rel)
 * - stable channels with stabilizing weights
 *
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <semaphore.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "driver.h"
#include "net_structs.h"
#include "netlib.h"
#include "netlink_socket_info.h"
#include "speed_algo.h"
#include "timer.h"
#include <stdarg.h>
struct my_ip {
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#define CH_THRESH 30
#define CS_THRESH 60
#define SEND_Q_IDLE 7000 // send_q less than this enters idling mode; e.g. head is detected by rtt
#define SEND_Q_LIMIT_MINIMAL 9000 // 7000 seems to work
#define SENQ_Q_LIMIT_THRESHOLD_MIN 13000 // the value with which that AG starts
#define SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER 5 // send_q AG allowed threshold = RSR / SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER
#define SEND_Q_EFF_WORK 10000 // value for send_q_eff to detect that channel is in use
// TODO: use mean send_q value for the following def
#define SEND_Q_AG_ALLOWED_THRESH 25000 // depends on RSR_TOP and chan speed. TODO: refine, Q: understand if we're using more B/W than 1 chan has?
//#define MAX_LATENCY_DROP { 0, 550000 }
#define MAX_LATENCY_DROP_USEC 180000 // typ. is 204-250 upto 450 max RTO at CUBIC
#define MAX_LATENCY_DROP_SHIFT 100 // ms. to add to forced_rtt - or use above
//#define MAX_REORDER_LATENCY { 0, 50000 } // is rtt * 2 actually, default. ACTUALLY this should be in compliance with TCP RTO
#define MAX_REORDER_LATENCY_MAX 499999 // usec
#define MAX_REORDER_LATENCY_MIN 200 // usec
#define MAX_REORDER_PERPATH 4
#define RSR_TOP 2990000 // now infinity...
#define DROPPING_LOSSING_DETECT_SECONDS 7 // seconds to pass after drop or loss to say we're not lossing or dropping anymore
//#define MAX_BYTE_DELIVERY_DIFF 100000 // what size of write buffer pumping is allowed? -> currently =RSR_TOP
#define SELECT_SLEEP_USEC 50000 // crucial for mean sqe calculation during idle
#define SUPERLOOP_MAX_LAG_USEC 10000 // 15ms max superloop lag allowed!
#define FCI_P_INTERVAL 3 // interval in packets to send ACK if ACK is not sent via payload packets
#define CUBIC_T_DIV 50
#define CUBIC_T_MAX 200

#define MAX_SD_W 1700 // stat buf max send_q (0..MAX_SD_W)
#define SD_PARITY 2 // stat buf len = MAX_SD_W / SD_PARITY
#define SLOPE_POINTS 30 // how many points ( / SD_PARITY ) to make linear fit from
#define PESO_STAT_PKTS 200 // packets to collect for ACS2 statistics to be correct for PESO
#define ZERO_W_THR 2000.0 // ms. when to consider weight of point =0 (value outdated)
#define SPEED_REDETECT_TV {2,0} // timeval (interval) for chan speed redetect

#define LIN_RTT_SLOWDOWN 70 // Grow rtt 40x slower than real-time
#define LIN_FORCE_RTT_GROW 0 // ms // TODO: need to find optimal value for required performance region

#define DEAD_RTT 1500 // ms. RTT to consider chan dead
#define DEAD_RSR_USG 40 // %. RSR utilization to consider chan dead if ACS=0

#define RSR_SMOOTH_GRAN 10 // ms granularity
#define RSR_SMOOTH_FULL 3000 // ms for full convergence
#define TRAIN_PKTS 80
#define WRITE_OUT_MAX 30 // write no more than 30 packets at once
//#define NOCONTROL
//#define NO_ACK

#define RCVBUF_SIZE 1048576

// #define TIMEWARP

#ifdef TIMEWARP
    #define TW_MAX 10000000

    char *timewarp;
    int tw_cur;
#endif

char *js_buf; // for tick JSON
int js_cur;

#define SEND_Q_LOG

#ifdef SEND_Q_LOG
char *jsSQ_buf; // for send_q compressor
int jsSQ_cur;
#endif

// flags:
uint8_t time_lag_ready;

int skip=0;
int forced_rtt_reached=1;

char rxmt_mode_request = 0; // flag
long int weight = 0; // bigger weight more time to wait(weight == penalty)
long int weight_cnt = 0;
int acnt = 0; // assert variable
char *out_buf;
uint16_t dirty_seq_num;
int sendbuff;
#define START_SQL 5000

int drop_packet_flag = 0, drop_counter=0;
int skip_write_flag = 0;
// these are for retransmit mode... to be removed
short retransmit_count = 0;
char channel_mode = MODE_NORMAL;
int hold_mode = 0; // 1 - hold 0 - normal
int force_hold_mode = 1;
int buf_len, incomplete_seq_len = 0, rtt_shift=0;
int16_t my_miss_packets_max = 0; // in ms; calculated here
int16_t miss_packets_max = 0; // get from another side
int proto_err_cnt = 0;
int my_max_send_q_chan_num = 0;
uint32_t my_max_send_q = 0, max_reorder_byte = 0;
uint32_t last_channels_mask = 0;
int32_t send_q_eff = 0;
int max_chan=-1;
uint32_t start_of_train = 0, end_of_train = 0;
struct timeval flood_start_time = { 0, 0 };

/*Variables for the exact way of measuring speed*/
struct timeval send_q_read_time, send_q_read_timer = {0,0}, send_q_read_drop_time = {0, 100000}, send_q_mode_switch_time = {0,0}, net_model_start = {0,0};
int32_t ACK_coming_speed_avg = 0;
int32_t send_q_limit = 7000;
int32_t magic_rtt_avg = 0;

/* Host we are working with.
 * Used by signal handlers that's why it is global.
 */
struct vtun_host *lfd_host;
struct conn_info *shm_conn_info;

struct lfd_mod *lfd_mod_head = NULL, *lfd_mod_tail = NULL;
struct channel_info *chan_info = NULL;

struct phisical_status info; /**< We store here all process closed information */

struct {
    int bytes_sent_norm;
    int bytes_rcvd_norm;
    int bytes_sent_rx;
    int bytes_rcvd_rx;
    int pkts_dropped;
    int rxmit_req; // outdated: use max_latency_hit + max_reorder_hit
    int rxmit_req_rx;
    int rxmits;	// number of resended packets
    int rxmits_notfound; // number of resend packets which not found
    int max_latency_hit; // new
    int max_reorder_hit; // new
    int mode_switches;
    int rxm_ntf;
    int chok_not;
    int max_latency_drops; // new
    int bytes_sent_chan[MAX_TCP_LOGICAL_CHANNELS];
    int bytes_rcvd_chan[MAX_TCP_LOGICAL_CHANNELS];
} statb;

struct {
    int v_min;
    int v_avg;
    int v_max;
} v_mma;

struct {
    int WT;
    int RT;
    int D;
    int CL;
    int DL;
} ag_stat;

struct time_lag_info time_lag_info_arr[MAX_TCP_LOGICAL_CHANNELS];
struct time_lag time_lag_local;
struct timeval socket_timeout = { 10, 0 };

struct last_sent_packet last_sent_packet_num[MAX_TCP_LOGICAL_CHANNELS]; // initialized by 0 look for memset(..

fd_set fdset, fdset_w, *pfdset_w;
int delay_acc; // accumulated send delay
int delay_cnt;
uint32_t my_max_speed_chan;
uint32_t my_holded_max_speed;
//uint32_t my_max_send_q;

int assert_cnt(int where) {
    if((acnt++) > (FRAME_BUF_SIZE*2)) {
        vtun_syslog(LOG_ERR, "ASSERT FAILED! Infinite loop detected at %d. Emergency break.", where);
        return 1;
    }
    return 0;
}

/* convert ms(milliseconds) to timeval struct */
void ms2tv(struct timeval *result, unsigned long interval_ms) {
    result->tv_sec = (interval_ms / 1000);
    result->tv_usec = ((interval_ms % 1000) * 1000);
}

uint32_t tv2ms(struct timeval *a) {
    return ((a->tv_sec * 1000) + (a->tv_usec / 1000));
}


int fit_wlinear (const double *x, const size_t xstride,
                 const double *w, const size_t wstride,
                 const double *y, const size_t ystride,
                 const size_t n,
                 double *c0, double *c1,
                 double *cov_00, double *cov_01, double *cov_11,
                 double *chisq)
{

  /* compute the weighted means and weighted deviations from the means */

  /* wm denotes a "weighted mean", wm(f) = (sum_i w_i f_i) / (sum_i w_i) */

  double W = 0, wm_x = 0, wm_y = 0, wm_dx2 = 0, wm_dxdy = 0;

  size_t i;

  for (i = 0; i < n; i++)
    {
      const double wi = w[i * wstride];

      if (wi > 0)
        {
          W += wi;
          wm_x += (x[i * xstride] - wm_x) * (wi / W);
          wm_y += (y[i * ystride] - wm_y) * (wi / W);
        }
    }

  W = 0;                        /* reset the total weight */

  for (i = 0; i < n; i++)
    {
      const double wi = w[i * wstride];

      if (wi > 0)
        {
          const double dx = x[i * xstride] - wm_x;
          const double dy = y[i * ystride] - wm_y;

          W += wi;
          wm_dx2 += (dx * dx - wm_dx2) * (wi / W);
          wm_dxdy += (dx * dy - wm_dxdy) * (wi / W);
        }
    }

  /* In terms of y = a + b x */

  {
    double d2 = 0;
    double b = wm_dxdy / wm_dx2;
    double a = wm_y - wm_x * b;

    *c0 = a;
    *c1 = b;

    *cov_00 = (1 / W) * (1 + wm_x * wm_x / wm_dx2);
    *cov_11 = 1 / (W * wm_dx2);

    *cov_01 = -wm_x / (W * wm_dx2);

    /* Compute chi^2 = \sum w_i (y_i - (a + b * x_i))^2 */

    for (i = 0; i < n; i++)
      {
        const double wi = w[i * wstride];

        if (wi > 0)
          {
            const double dx = x[i * xstride] - wm_x;
            const double dy = y[i * ystride] - wm_y;
            const double d = dy - b * dx;
            d2 += wi * d * d;
          }
      }

    *chisq = d2;
  }

  return 1;
}


int percent_delta_equal(int A, int B, int percent) {
    int delta = A>B?A-B:B-A;
    if(delta > 10000000) return 0;
    if(A < 2 && B < 2) {
        return 1;
    }
    int dp = delta * 100 / (A/2 + B/2);
    if(dp <= percent) {
        return 1;
    }
    return 0;
}

int frame_llist_getSize_asserted(int max, struct frame_llist *l, struct frame_seq *flist, int * size) {
    int len = 0;
    *size = 0;
    
    //if(l->rel_head == -1 && l->rel_tail !=-1) {
    //    return -8;
    //}
    
    if(l->rel_head != -1 && l->rel_tail ==-1) {
        return -9;
    }
    
    if(l->rel_head == -1) {
        return 0;
    }
    
    if(l->rel_head < -1) {
        return -1;
    }
    if(l->rel_tail < -1) {
        return -2;
    }
    if(l->rel_head > max) {
        return -3;
    }
    if(l->rel_tail > max) {
        return -4;
    }
    
    for (int i = l->rel_head; i != -1; i = flist[i].rel_next) {
        if(flist[i].rel_next < -1) {
            vtun_syslog(LOG_ERR, "ASSERT FAILED! frame[%d]->rel_next=%d,seq_num=%"PRIu32",len=%d,chan_num=%d", i, flist[i].rel_next, flist[i].seq_num, flist[i].len, flist[i].chan_num);
            return -5;
        }
        if(flist[i].rel_next > max) {
            return -6;
        }
        len++;
    }
    *size = len;
    return 0;
}


int check_consistency_free(int framebuf_size, int llist_amt, struct _write_buf wb[], struct frame_llist *lfree, struct frame_seq flist[]) {
    int free_cnt = 0;
    int size = 0;
    int size_total = 0;
    int result;
    
    for(int i=0; i < llist_amt; i++) {
        result = frame_llist_getSize_asserted(framebuf_size, &wb[i].frames, flist, &size);
        if (result < 0) return result;
        size_total += size;
    }
    
    result = frame_llist_getSize_asserted(framebuf_size, lfree, flist, &size);
    if (result < 0) return result-100;
    if(size_total + size != framebuf_size) {
        vtun_syslog(LOG_ERR, "ASSERT FAILED! total used in write_buf: %d, free: %d, sum: %d, total: %d", size_total, size, (size_total+size), framebuf_size);
        return -7;
    }
    
    return 0;
}


/********** Linker *************/
/* Termination flag */
static volatile sig_atomic_t linker_term;

void segfault_sigaction(int signal, siginfo_t *si, void *arg)
{
    printf("CRITICAL ERROR Caught mem-free segfault at address %p; will continue anyway since we are USS 1408 Enterprise !! q:-)\\-<\n", si->si_addr);
    //exit(0);
}

static void sig_term(int sig)
{
    vtun_syslog(LOG_INFO, "Get sig_term");
    vtun_syslog(LOG_INFO, "Closing connection");
    io_cancel();
    linker_term = VTUN_SIG_TERM;
}

static void sig_hup(int sig)
{
    vtun_syslog(LOG_INFO, "Get sig_hup");
    vtun_syslog(LOG_INFO, "Reestablishing connection");
    io_cancel();
    linker_term = VTUN_SIG_HUP;
}

/* Statistic dump */
void sig_alarm(int sig)
{
    vtun_syslog(LOG_INFO, "Get sig_alarm");
    static time_t tm;
    static char stm[20];
    /*
       tm = time(NULL);
       strftime(stm, sizeof(stm)-1, "%b %d %H:%M:%S", localtime(&tm));
       fprintf(lfd_host->stat.file,"%s %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32"\n", stm,
    lfd_host->stat.byte_in, lfd_host->stat.byte_out,
    lfd_host->stat.comp_in, lfd_host->stat.comp_out);
    */
    //alarm(VTUN_STAT_IVAL);
    alarm(lfd_host->MAX_IDLE_TIMEOUT);
}

static void sig_usr1(int sig)
{
    vtun_syslog(LOG_INFO, "Get sig_usr1, check_shm UP");
    info.check_shm = 1;
}

/**
 * колличество отставших пакетов
 * buf[] - номера пакетов
 */
int missing_resend_buffer (int chan_num, uint32_t buf[], int *buf_len) {
    return 0; // disabled!
    int i = shm_conn_info->write_buf[chan_num].frames.rel_head, n;
    uint32_t isq,nsq, k;
    int idx=0;
    int blen=0, lws, chs;

    if(i == -1) {
        *buf_len = 0;
        return 0;
    }

    lws = shm_conn_info->write_buf[chan_num].last_written_seq;
    chs = shm_conn_info->frames_buf[i].seq_num;


    if(  ( (chs - lws) >= FRAME_BUF_SIZE) || ( (lws - chs) >= FRAME_BUF_SIZE)) { // this one will not happen :-\
        vtun_syslog(LOG_ERR, "WARNING: frame difference too high: last w seq: %"PRIu32" fbhead: %"PRIu32" . FIXED. chs %d<->%d lws cn %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->write_buf[chan_num].frames_buf[i].seq_num, chs, lws, chan_num);
        shm_conn_info->write_buf[chan_num].last_written_seq = shm_conn_info->frames_buf[i].seq_num-1;
    }

    // fix for diff btw start
    for(k=1; k<(shm_conn_info->frames_buf[i].seq_num - shm_conn_info->write_buf[chan_num].last_written_seq); k++) {
        buf[idx] = shm_conn_info->write_buf[chan_num].last_written_seq + k;
        idx++;
        //vtun_syslog(LOG_INFO, "MRB: found in start : tot %d", idx);
        if(idx >= FRAME_BUF_SIZE) {
            vtun_syslog(LOG_ERR, "WARNING: MRB2 frame difference too high: last w seq: %"PRIu32" fbhead: %"PRIu32" . FIXED. chs %d<->%d lws ch %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->frames_buf[i].seq_num, chs, lws, chan_num);
            shm_conn_info->write_buf[chan_num].last_written_seq = shm_conn_info->frames_buf[i].seq_num-1;
            idx=0;
            break;
        }
    }
    acnt = 0;
    while(i > -1) {
        n = shm_conn_info->frames_buf[i].rel_next;
        //vtun_syslog(LOG_INFO, "MRB: scan1");
        if( n > -1 ) {

            isq = shm_conn_info->frames_buf[i].seq_num;
            nsq = shm_conn_info->frames_buf[n].seq_num;
            //vtun_syslog(LOG_INFO, "MRB: scan2 %"PRIu32" > %"PRIu32" +1 ?", nsq, isq);
            if(nsq > (isq+1)) {
                //vtun_syslog(LOG_INFO, "MRB: scan2 yes!");
                for(k=1; k<=(nsq-(isq+1)); k++) {
                    if(idx >= FRAME_BUF_SIZE) {
                        vtun_syslog(LOG_ERR, "WARNING: frame seq_num diff in write_buf > FRAME_BUF_SIZE");
                        *buf_len = blen;
                        return idx;
                    }

                    buf[idx] = isq+k;
                    idx++;
                    //vtun_syslog(LOG_INFO, "MRB: found in middle : tot %d", idx);
                }
            }
        }
        i = n;
        blen++;
#ifdef DEBUGG
        if(assert_cnt(1)) break;
#endif
    }
    //vtun_syslog(LOG_INFO, "missing_resend_buf called and returning %d %d ", idx, blen);
    *buf_len = blen;
    return idx;
}

/* check if we are allowed to drop packet again  */
int check_drop_period_unsync() {
    struct timeval tv_tm, tv_rtt;
    timersub(&info.current_time, &shm_conn_info->drop_time, &tv_tm);
    ms2tv(&tv_rtt, shm_conn_info->stats[info.process_num].exact_rtt);
    if(timercmp(&tv_tm, &tv_rtt, >=)) {
        //vtun_syslog(LOG_ERR, "Last drop passed: %d ms > rtt %d ms", tv2ms(&tv_tm), tv2ms(&tv_rtt));
        return 1;
    }
    // else
    return 0;
}

/* Check if the packet sent right now will be delivered in time */
int check_delivery_time(int mld_divider) {
    // RTT-only for now..
    //    struct timeval max_latency_drop = MAX_LATENCY_DROP;
    sem_wait(&(shm_conn_info->stats_sem));
    int ret = check_delivery_time_unsynced(mld_divider);
    sem_post(&(shm_conn_info->stats_sem));
    return ret;
}

// this method is crutial as it controls AG/R_MODE operation while in R_MODE
int check_delivery_time_unsynced(int mld_divider) {
    struct timeval max_latency_drop = info.max_latency_drop;
    // check for dead channel
    if(shm_conn_info->stats[info.process_num].channel_dead && (shm_conn_info->max_chan != info.process_num)) {
        // vtun_syslog(LOG_ERR, "WARNING check_delivery_time DEAD and not HEAD"); // TODO: out-once this!
        return 0;
    }
    // TODO: re-think this!
    if( ( (info.rsr < info.send_q_limit_threshold) || (info.send_q_limit_cubic < info.send_q_limit_threshold)) && (shm_conn_info->max_chan != info.process_num)) {
        vtun_syslog(LOG_ERR, "WARNING check_delivery_time RSR %d < THR || CUBIC %d < THR=%d", info.rsr, (int32_t)info.send_q_limit_cubic, info.send_q_limit_threshold);
        return 0;
    }
    //if( (shm_conn_info->stats[info.process_num].rtt_phys_avg - shm_conn_info->stats[shm_conn_info->ax_chan].rtt_phys_avg) > ((int32_t)(tv2ms(&max_latency_drop) / 2)) ) {
    if( (shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt) > ((int32_t)(tv2ms(&max_latency_drop)/mld_divider)) ) {
        // no way to deliver in time
        vtun_syslog(LOG_ERR, "WARNING check_delivery_time %d - %d > %d", shm_conn_info->stats[info.process_num].exact_rtt, shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt, (tv2ms(&max_latency_drop)));
        return 0;
    }
    //vtun_syslog(LOG_ERR, "CDT OK");
    return 1;
}

int check_rtt_latency_drop() {
    struct timeval max_latency_drop = info.max_latency_drop;
    if(shm_conn_info->stats[info.process_num].channel_dead && (shm_conn_info->max_chan != info.process_num)) {
        return 0;
    }
    if( (shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt) > (int32_t)(tv2ms(&max_latency_drop)) ) {
        return 0;
    }
    return 1;
}

// TODO: this MUST be heavily optimized! vvv
static inline int check_force_rtt_max_wait_time(int chan_num) {
    int i = shm_conn_info->write_buf[chan_num].frames.rel_head, n;
    int cnt = 0;
    int max_wait = 0, rtt_fix;
    struct timeval tv_tmp, rtt_fix_tv, max_wait_tv = {0,0};
    
    if(shm_conn_info->forced_rtt_recv == 0) return 1;

    while(i > -1) {
        rtt_fix = shm_conn_info->forced_rtt_recv - shm_conn_info->frames_buf[i].current_rtt;
        rtt_fix = rtt_fix < 0 ? 0 : rtt_fix;
        ms2tv(&rtt_fix_tv, rtt_fix);
        timersub(&info.current_time, &shm_conn_info->frames_buf[i].time_stamp, &tv_tmp);
        if ( timercmp(&tv_tmp, &max_wait_tv, >=) ) {
            max_wait_tv = tv_tmp;
        }

        // TODO: code with rtt in account - is much more heavier than just oldest packet
//        if ( timercmp(&shm_conn_info->frames_buf[i].time_stamp, &max_wait_tv, >=) ) {
//            max_wait_tv = shm_conn_info->frames_buf[i].time_stamp;
//        }

        n = shm_conn_info->frames_buf[i].rel_next;
        i = n;
        
        cnt++;
        if(cnt > 200) break; // do not look too deep?
    }
    ms2tv(&tv_tmp, shm_conn_info->forced_rtt_recv);
    return timercmp(&max_wait_tv, &tv_tmp, >=);
}

int get_write_buf_wait_data() {
    // TODO WARNING: is it synchronized?
    //struct timeval max_latency_drop = MAX_LATENCY_DROP;
    struct timeval max_latency_drop = info.max_latency_drop;
    struct timeval tv_tmp;
    uint32_t chan_mask = shm_conn_info->channels_mask;
    for (int i = 0; i < info.channel_amount; i++) {
        info.least_rx_seq[i] = UINT32_MAX;
        for(int p=0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
            if (chan_mask & (1 << p)) {
                if( (shm_conn_info->stats[p].max_PCS2 <= 1) || (shm_conn_info->stats[p].max_ACS2 <= 3) ) {
                    // vtun_syslog(LOG_ERR, "get_write_buf_wait_data(), detected dead channel");
                    continue;
                }
                if (shm_conn_info->write_buf[i].last_received_seq[p] < info.least_rx_seq[i]) {
                    info.least_rx_seq[i] = shm_conn_info->write_buf[i].last_received_seq[p];
                }
            }
        }
        
        if (shm_conn_info->write_buf[i].frames.rel_head != -1) {
            forced_rtt_reached=check_force_rtt_max_wait_time(i);
            timersub(&info.current_time, &shm_conn_info->write_buf[i].last_write_time, &tv_tmp);
            if (shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].seq_num
                    == (shm_conn_info->write_buf[i].last_written_seq + 1)) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "get_write_buf_wait_data(), next seq");
#endif
                return forced_rtt_reached;
            } else if (timercmp(&tv_tmp, &max_latency_drop, >=)) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "get_write_buf_wait_data(), latency drop %ld.%06ld", tv_tmp.tv_sec, tv_tmp.tv_usec);
#endif
                return 1;
            } else if (shm_conn_info->write_buf[i].last_written_seq < info.least_rx_seq[i]) { // this is required to flush pkt in case of LOSS
                return forced_rtt_reached; // do NOT add any other if's here - it SHOULD drop immediately!
            }
        }
    }
    return 0;
}
// untested module!
int fix_free_writebuf() {
    int i, j, st, found;

    for(j=0; j<FRAME_BUF_SIZE; j++) {
        for (i = 0; i < info.channel_amount; i++) {
            st = shm_conn_info->write_buf[i].frames.rel_head;
            found = 0;
            acnt=0;
            while(st > -1) {
                if(st == j) found = 1;
                st = shm_conn_info->frames_buf[st].rel_next;
#ifdef DEBUGG
                if(assert_cnt(2)) break;
#endif
            }
        }
        if(!found) {
            // append to tail free
            if(shm_conn_info->wb_free_frames.rel_head == -1) {
                shm_conn_info->wb_free_frames.rel_head = shm_conn_info->wb_free_frames.rel_tail = j;
            } else {
                shm_conn_info->frames_buf[shm_conn_info->wb_free_frames.rel_tail].rel_next=j;
                shm_conn_info->wb_free_frames.rel_tail = j;
            }
            shm_conn_info->frames_buf[j].rel_next = -1;
        }
    }
    return 0;
}

// get next frame that need to be sent
// it is either the seq_num referenced as input argument (usually last_sent+1)
// or oldest non-expired seq_num frame
int get_resend_frame(int chan_num, uint32_t *seq_num, char **out, int *sender_pid) {
    int i, j, j_previous, len = -1;
    struct timeval expiration_date;
    struct timeval max_latency;

    int mrl_ms, drtt_ms, expiration_ms_fromnow;

    sem_wait(&(shm_conn_info->stats_sem));
    // drtt should be equal in AG mode as we balance the buffers, only takes place in PING-like mode
    drtt_ms = shm_conn_info->stats[info.process_num].rtt_phys_avg - shm_conn_info->stats[max_chan].rtt_phys_avg;
    sem_post(&(shm_conn_info->stats_sem));

    // MRL is allowed time to lag
    mrl_ms = info.max_reorder_latency.tv_usec / 1000; // WARNINIG: no MRL > 1000ms !!
    expiration_ms_fromnow = mrl_ms - drtt_ms;
    if(expiration_ms_fromnow < 0) { 
        // we can get no frames; handle this above
        return -1;
    }
    ms2tv(&max_latency, expiration_ms_fromnow);
    
    gettimeofday(&info.current_time, NULL ); // why?? to be exact!
    timersub(&info.current_time, &max_latency, &expiration_date);
    
    //find start point
    j = shm_conn_info->resend_buf_idx - 1 < 0 ? RESEND_BUF_SIZE - 1 : shm_conn_info->resend_buf_idx - 1;
    j_previous = j;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
//        vtun_syslog(LOG_INFO, "look for %"PRIu32" start point step - j %i chan_num %i seq_num %"PRIu32" ",*seq_num, j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            j_previous = j;
            break;
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }

    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
//                vtun_syslog(LOG_INFO, "j %i chan_num %i seq_num %"PRIu32" ", j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if ((shm_conn_info->resend_frames_buf[j].chan_num == chan_num) || (shm_conn_info->resend_frames_buf[j].chan_num == 0)) {
            if (timercmp(&expiration_date, &shm_conn_info->resend_frames_buf[j].time_stamp, >)
                    || (shm_conn_info->resend_frames_buf[j].seq_num < *seq_num) || (shm_conn_info->resend_frames_buf[j].chan_num == 0)) {
                *seq_num = shm_conn_info->resend_frames_buf[j_previous].seq_num;
                len = shm_conn_info->resend_frames_buf[j_previous].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j_previous].sender_pid;
//                vtun_syslog(LOG_INFO, "previous j %i chan_num %i seq_num %"PRIu32" ", j_previous, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j_previous].seq_num );
                return len;
            } else if (shm_conn_info->resend_frames_buf[j].seq_num == *seq_num) {
                if (timercmp(&expiration_date, &shm_conn_info->resend_frames_buf[j].time_stamp, <=)) {
                    j_previous = j;
                } else {
			vtun_syslog(LOG_ERR, "WARNING get_resend_frame returning previous frame");
		}
                *seq_num = shm_conn_info->resend_frames_buf[j_previous].seq_num;
                len = shm_conn_info->resend_frames_buf[j_previous].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j_previous].sender_pid;
//                vtun_syslog(LOG_INFO, "bottom ret j %i chan_num %i seq_num %"PRIu32" ", j_previous, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j_previous].seq_num );
                return len;
            } else {
                j_previous = j;
            }
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE;
        }
    }

    //if(i == RESEND_BUF_SIZE) {
        // means we have not found the most recent frame in resend_buf
        // that means that we are too new, return -1!
    //}

    return len;
}


// the same GRF but no expiration
int get_resend_frame_unconditional(int chan_num, uint32_t *seq_num, char **out, int *sender_pid) {
    int i, j, j_previous, len = -1;
    
    //find start point
    j = shm_conn_info->resend_buf_idx - 1 < 0 ? RESEND_BUF_SIZE - 1 : shm_conn_info->resend_buf_idx - 1;
    j_previous = j;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            j_previous = j;
            break;
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }

    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
//                vtun_syslog(LOG_INFO, "j %i chan_num %i seq_num %"PRIu32" ", j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if ((shm_conn_info->resend_frames_buf[j].chan_num == chan_num) || (shm_conn_info->resend_frames_buf[j].chan_num == 0)) {
            if (shm_conn_info->resend_frames_buf[j].seq_num == *seq_num) {
                j_previous = j;
                *seq_num = shm_conn_info->resend_frames_buf[j_previous].seq_num;
                len = shm_conn_info->resend_frames_buf[j_previous].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j_previous].sender_pid;
//                vtun_syslog(LOG_INFO, "bottom ret j %i chan_num %i seq_num %"PRIu32" ", j_previous, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j_previous].seq_num );
                return len;
            } else {
                j_previous = j;
            }
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE;
        }
    }

    return len;
}



// cycle resend buffer from top down to old to get any packet
int get_last_packet_seq_num(int chan_num, uint32_t *seq_num) {
    int j = shm_conn_info->resend_buf_idx-1;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            *seq_num = shm_conn_info->resend_frames_buf[j].seq_num;
            return j;
        }
        j--;
        if (j < 0) {
            j = RESEND_BUF_SIZE - 1;
        }
    }
    return -1;
}

int get_oldest_packet_seq_num(int chan_num, uint32_t *seq_num) {
    int j = shm_conn_info->resend_buf_idx;
    j++;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {
        if (j == RESEND_BUF_SIZE) {
            j = 0;
        }
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            *seq_num = shm_conn_info->resend_frames_buf[j].seq_num;
            return j;
        }
        j++;
    }
    return -1;
}

int get_last_packet(int chan_num, uint32_t *seq_num, char **out, int *sender_pid) {
    int j = get_last_packet_seq_num(chan_num, seq_num);
    if(j == -1) return -1;
    int len = shm_conn_info->resend_frames_buf[j].len;
    *((uint16_t *) (shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
    *out = shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV;
    *sender_pid = shm_conn_info->resend_frames_buf[j].sender_pid;
    return len;
}

int seqn_break_tail(char *out, int len, uint32_t *seq_num, uint16_t *flag_var, uint32_t *local_seq_num, uint16_t *mini_sum, uint32_t *last_recv_lsn, uint32_t *packet_recv_spd) {
    *seq_num = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *flag_var = ntohs(*((uint16_t *)(&out[len - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *local_seq_num = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *mini_sum = ntohs(*((uint16_t *)(&out[len - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    
    *last_recv_lsn = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint32_t)])));
    *packet_recv_spd = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t)])));
    return len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t);
}

/**
 * Function for add flag and seq_num to packet
 */
int pack_packet(int chan_num, char *buf, int len, uint32_t seq_num, uint32_t local_seq_num, int flag) {
    uint32_t seq_num_n = htonl(seq_num);
    uint16_t flag_n = htons(flag);
    uint32_t local_seq_num_n = htonl(local_seq_num);
    uint16_t mini_sum = htons((uint16_t)(seq_num + local_seq_num + info.channel[chan_num].local_seq_num_recv));
    uint32_t last_recv_lsn = htonl(info.channel[chan_num].local_seq_num_recv);
    uint32_t packet_recv_spd = htonl(info.channel[chan_num].packet_download);
    memcpy(buf + len, &seq_num_n, sizeof(uint32_t));
    memcpy(buf + len + sizeof(uint32_t), &flag_n, sizeof(uint16_t));
    memcpy(buf + len + sizeof(uint32_t) + sizeof(uint16_t), &local_seq_num_n, sizeof(local_seq_num_n));
    memcpy(buf + len + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(local_seq_num_n), &mini_sum, sizeof(uint16_t));
    memcpy(buf + len + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(local_seq_num_n) + sizeof(uint16_t), &last_recv_lsn, sizeof(uint32_t));
    memcpy(buf + len + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(local_seq_num_n) + sizeof(uint16_t) + sizeof(uint32_t), &packet_recv_spd, sizeof(uint32_t));
    return len + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t);
}

/**
 * Generate new packet number, wrapping packet and add to resend queue. (unsynchronized)
 *
 * @param conn_num
 * @param buf - data for send
 * @param out - pointer to pointer to output packet
 * @param len - data length
 * @param seq_num - output packet number
 * @param flag
 * @param sender_pid
 */
void seqn_add_tail(int conn_num, char *buf, int len, uint32_t seq_num, uint16_t flag, int sender_pid) {
    int newf = shm_conn_info->resend_buf_idx;

    shm_conn_info->resend_buf_idx++;
    if (shm_conn_info->resend_buf_idx == RESEND_BUF_SIZE) {
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "seqn_add_tail() resend_frames_buf loop end");
#endif
        shm_conn_info->resend_buf_idx = 0;
    }

    shm_conn_info->resend_frames_buf[newf].seq_num = seq_num;
    shm_conn_info->resend_frames_buf[newf].sender_pid = sender_pid;
    shm_conn_info->resend_frames_buf[newf].chan_num = conn_num;
    shm_conn_info->resend_frames_buf[newf].len = len;
    gettimeofday(&info.current_time, NULL );
    shm_conn_info->resend_frames_buf[newf].time_stamp = info.current_time;
    memcpy((shm_conn_info->resend_frames_buf[newf].out + LINKFD_FRAME_RESERV), buf, len);
}

/**
 * Add packet to fast resend buffer
 *
 * @param conn_num
 * @param buf - pointer to packet
 * @return -1 - error if buffer full and packet's quantity if success
 */
int add_fast_resend_frame(int conn_num, char *buf, int len, uint32_t seq_num) {
    if (shm_conn_info->fast_resend_buf_idx >= MAX_TCP_PHYSICAL_CHANNELS) {
        return -1; // fast_resend_buf is full
    }
    int i = shm_conn_info->fast_resend_buf_idx; // get next free index
    ++(shm_conn_info->fast_resend_buf_idx);
    uint16_t flag = MODE_NORMAL;
    shm_conn_info->fast_resend_buf[i].seq_num = seq_num;
    shm_conn_info->fast_resend_buf[i].sender_pid = 0;
    shm_conn_info->fast_resend_buf[i].chan_num = conn_num;
    shm_conn_info->fast_resend_buf[i].len = len;

    memcpy((shm_conn_info->fast_resend_buf[i].out + LINKFD_FRAME_RESERV), buf, len);
    return shm_conn_info->fast_resend_buf_idx;
}

/**
 * Add packet to fast resend buffer
 *
 * @param conn_num - pointer for available variable
 * @param buf - pointer to allocated memory
 * @return
 */
int get_fast_resend_frame(int *conn_num, char *buf, int *len, uint32_t *seq_num) {
    if (shm_conn_info->fast_resend_buf_idx == 0) {
        return -1; // buffer is blank
    }
    int i = --(shm_conn_info->fast_resend_buf_idx);
    memcpy(buf, shm_conn_info->fast_resend_buf[i].out + LINKFD_FRAME_RESERV, shm_conn_info->fast_resend_buf[i].len);
    *conn_num = shm_conn_info->fast_resend_buf[i].chan_num;
    *seq_num = shm_conn_info->fast_resend_buf[i].seq_num;
    *len = shm_conn_info->fast_resend_buf[i].len;
    return i+1;
}

/**
 *
 * @return 0 if buffer blank
 */
int check_fast_resend() {
    if (shm_conn_info->fast_resend_buf_idx == 0) {
        return 0; // buffer is blank
    }
    return 1;
}


/*
          _                                 _ _                            _ 
         | |                               (_) |                          | |
 _ __ ___| |_ _ __ __ _ _ __  ___ _ __ ___  _| |_       ___  ___ _ __   __| |
| '__/ _ \ __| '__/ _` | '_ \/ __| '_ ` _ \| | __|     / __|/ _ \ '_ \ / _` |
| | |  __/ |_| | | (_| | | | \__ \ | | | | | | |_      \__ \  __/ | | | (_| |
|_|  \___|\__|_|  \__,_|_| |_|___/_| |_| |_|_|\__|     |___/\___|_| |_|\__,_|
                                               ______                        
                                              |______|                       
*/

/**
 * Function for trying resend
 */ 
int retransmit_send(char *out2, int n_to_send) {
    if (drop_packet_flag) {
        return LASTPACKETMY_NOTIFY; // go dropping
    } else if (drop_counter > 0) {
        vtun_syslog(LOG_INFO, "drop_packet_flag (retransmit_send) TOTAL %d pkts; info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d", drop_counter, info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel, shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg);
        drop_counter = 0;
    }
    if (hold_mode) {
        return CONTINUE_ERROR;
    }
    struct timeval tv = {0,0};

    int len = 0, send_counter = 0, mypid, get_unconditional = 0;
    uint32_t top_seq_num, seq_num_tmp = 1, remote_lws = SEQ_START_VAL;
    sem_wait(&(shm_conn_info->resend_buf_sem));
    if (check_fast_resend()){ // fast_resend technique is used for info.channel_amount > 1
        sem_post(&(shm_conn_info->resend_buf_sem));
        return HAVE_FAST_RESEND_FRAME;
    }
    sem_post(&(shm_conn_info->resend_buf_sem));
    for (int i = 1; i < info.channel_amount; i++) {
        sem_wait(&(shm_conn_info->common_sem));
        top_seq_num = shm_conn_info->seq_counter[i];
        sem_post(&(shm_conn_info->common_sem));
        sem_wait(&(shm_conn_info->write_buf_sem));
        remote_lws = shm_conn_info->write_buf[i].remote_lws;
        if (remote_lws > top_seq_num) { // do we ever need this???
            shm_conn_info->write_buf[i].remote_lws = top_seq_num; // ????top_seq_num - 1
            remote_lws = top_seq_num;
        }
        sem_post(&(shm_conn_info->write_buf_sem));
        if ((last_sent_packet_num[i].seq_num + 1) <= remote_lws) {
            last_sent_packet_num[i].seq_num = remote_lws;
        }

        if ((top_seq_num <= last_sent_packet_num[i].seq_num) || (top_seq_num == SEQ_START_VAL)) {
#ifdef DEBUGG
           vtun_syslog(LOG_INFO, "debug: retransmit_send skipping logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
            // TODO MOVE THE FOLLOWING LINE TO DEBUG! --vvv
            if (top_seq_num < last_sent_packet_num[i].seq_num) vtun_syslog(LOG_INFO, "WARNING! impossible: chan#%i last sent seq_num %"PRIu32" is > top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
            if( (!info.head_channel) && (shm_conn_info->dropping || shm_conn_info->head_lossing)) {
                last_sent_packet_num[i].seq_num--; // push to top! (push policy)
                get_unconditional = 1;
            } else {
                if(check_delivery_time(2)) { // TODO: head always passes!
                    continue; // means that we have sent everything from rxmit buf and are ready to send new packet: no send_counter increase
                }
                // else means that we need to send something old
                vtun_syslog(LOG_ERR, "WARNING cannot send new packets as we won't deliver in time; skip sending"); // TODO: add skip counter
                send_counter++;
                continue; // do not send anything at all
            }
        }

        // perform check that we can write w/o blocking I/O; take into account that we need to notify that we still need to retransmit
        fd_set fdset2;
        FD_ZERO(&fdset2);
        FD_SET(info.channel[i].descriptor, &fdset2);
        int sel_ret = select(info.channel[i].descriptor + 1, NULL, &fdset2, NULL, &tv);
        if (sel_ret == 0) {
            send_counter++; // deny meaning that we've sent everything from retransmit and must no go on sending new packets
            continue; // continuing w/o reading/sending pkts AND send_counter++ will cause to fast-loop; we effectively do a poll here
        } else if (sel_ret == -1) {
            vtun_syslog(LOG_ERR, "retransmit send Could not select chan %d reason %s (%d)", i, strerror(errno), errno);
        }
        // now we have something to retransmit:

        last_sent_packet_num[i].seq_num++;
        seq_num_tmp = last_sent_packet_num[i].seq_num; // save old seq_num for test

#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
        sem_wait(&(shm_conn_info->resend_buf_sem));
        if(info.head_channel == 1) {
            // on head channel, do not allow to skip even if we see outdated packets?
            len = get_resend_frame_unconditional(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
            if (len == -1) {
                if (check_delivery_time(1)) { // TODO: head channel will always pass this test
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vtun_syslog(LOG_ERR, "WARNING no packets found in RB on head_channel and we can deliver new in time; sending new");
                    continue; // ok to send new packet
                } 
                len = get_last_packet(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
                vtun_syslog(LOG_ERR, "WARNING all RB packets expired on head_channel!!! & can not deliver new packet in time; getting newest packet from RB... seq_num %"PRIu32" top %d", last_sent_packet_num[i].seq_num, top_seq_num);
                if(len == -1) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vtun_syslog(LOG_ERR, "WARNING no packets found in RB; HEAD sending new");
                    continue;
                }
            }
        } else {
            // this is required to not read new packets if being pushed to top and all packets exhausted ->>>
            if(get_unconditional) len = get_resend_frame_unconditional(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
            else                  len = get_resend_frame              (i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
            if (len == -1) {
                last_sent_packet_num[i].seq_num--;
                if (check_delivery_time(2)) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    // TODO: disable AG in case of this event!
                    vtun_syslog(LOG_ERR, "WARNING all packets in RB are sent AND we can deliver new in time; sending new");
                    continue; // ok to send new packet
                } 
                // else there is no way we can deliver anything in time; now get latest packet
                len = get_last_packet(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
                // TODO: counter here -->
                vtun_syslog(LOG_ERR, "WARNING all RB packets expired & can not deliver new packet in time; getting newest packet from RB... seq_num %"PRIu32" top %d", last_sent_packet_num[i].seq_num, top_seq_num);
                if(len == -1) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vtun_syslog(LOG_ERR, "WARNING no packets found in RB; hd==0 sending new!!!");
                    continue;
                }
            }
        }
        if((last_sent_packet_num[i].seq_num != seq_num_tmp) && (info.head_channel == 1)) {
            vtun_syslog(LOG_ERR, "WARNING retransmit_send on head channel skippig seq's from %"PRIu32" to %"PRIu32" chan %d len %d", seq_num_tmp, last_sent_packet_num[i].seq_num, i, len);
        }
        memcpy(out_buf, out2, len);
        sem_post(&(shm_conn_info->resend_buf_sem));

#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, len);
#endif
        if(debug_trace) {
            vtun_syslog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, len);
        }

        statb.bytes_sent_rx += len;        
        
        // TODO: add select() here!
        // TODO: optimize here
        uint32_t tmp_seq_counter;
        uint32_t local_seq_num_p;
        uint16_t tmp_flag;
        uint16_t sum;
        len = seqn_break_tail(out_buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
        len = pack_packet(i, out_buf, len, tmp_seq_counter, info.channel[i].local_seq_num, tmp_flag);
        if( (info.rtt2_lsn[i] == 0) && ((shm_conn_info->stats[info.process_num].max_ACS2/info.eff_len) > (1000/shm_conn_info->stats[info.process_num].exact_rtt)) ) {
            info.rtt2_lsn[i] = info.channel[i].local_seq_num;
            info.rtt2_tv[i] = info.current_time;
            info.rtt2_send_q[i] = info.channel[i].send_q;
        }
        // send DATA
        int len_ret = udp_write(info.channel[i].descriptor, out_buf, len);
        info.channel[i].packet_recv_counter = 0;
        if (len && (len_ret < 0)) {
            vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", i, strerror(errno), errno);
            return BREAK_ERROR;
        }
        info.channel[i].local_seq_num++;
    
        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
        info.channel[i].up_len += len_ret;
        info.channel[i].up_packets++;
        info.channel[i].bytes_put++;
//if(drop_packet_flag) {  vtun_syslog(LOG_INFO, "bytes_pass++ retransmit_send"); } 
        info.byte_r_mode += len_ret;

        send_counter++;
    }
    
    if (send_counter == 0) {
        if (check_delivery_time(1)) { // TODO: REMOVE THIS EXTRA CHECK (debug only; should never happen due to previous checks)
            return LASTPACKETMY_NOTIFY;
        } else {
            vtun_syslog(LOG_ERR, "WARNING STILL can not deliver new packet in time; skipping read from tun");
            return CONTINUE_ERROR;
        }
    }
        
    return 1;
}

int select_net_write(chan_num) {
    struct timeval tv;

    fd_set fdset2;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fdset2);
    FD_SET(info.channel[chan_num].descriptor, &fdset2);
    int sel_ret = select(info.channel[chan_num].descriptor + 1, NULL, &fdset2, NULL, &tv);
    if (sel_ret == 0) {
        return 0; // save rtt!
    } else if (sel_ret == -1) {
        vtun_syslog(LOG_ERR, "write_buf_check_n_flush select error! errno %d",errno);
        return 0;
    }
    return 1;
}

/*
          _           _                            _ 
         | |         | |                          | |
 ___  ___| | ___  ___| |_       ___  ___ _ __   __| |
/ __|/ _ \ |/ _ \/ __| __|     / __|/ _ \ '_ \ / _` |
\__ \  __/ |  __/ (__| |_      \__ \  __/ | | | (_| |
|___/\___|_|\___|\___|\__|     |___/\___|_| |_|\__,_|
                       ______                        
                      |______|                       
*/
/**
 * Procedure select all(only tun_device now) file descriptors and if data available read from tun device, pack and write to net
 *
 *  @return - number of error or sent len
 *      -1 - continue error (CONTINUE_ERROR)
 *      -2 - break error (BREAK_ERROR)
 *
 *
 */
int select_devread_send(char *buf, char *out2) {
    int len, select_ret, idx;
    uint32_t tmp_seq_counter = 0;
    int chan_num;
    struct my_ip *ip;
    struct tcphdr *tcp;
    struct timeval tv;
    int new_packet = 0;
    fd_set fdset_tun;

    uint32_t local_seq_num_p;
    uint16_t tmp_flag;
    uint16_t sum;
    sem_wait(&(shm_conn_info->resend_buf_sem));
    idx = get_fast_resend_frame(&chan_num, buf, &len, &tmp_seq_counter);
    sem_post(&(shm_conn_info->resend_buf_sem));
    if (idx == -1) {
        if (!FD_ISSET(info.tun_device, &fdset)) {
#ifdef DEBUGG
if(drop_packet_flag) {
            vtun_syslog(LOG_INFO, "debug: Nothing to read from tun device (first FD_ISSET)");
}
#endif
            return TRYWAIT_NOTIFY;
        }
        FD_ZERO(&fdset_tun);
        FD_SET(info.tun_device, &fdset_tun);
        int try_flag = sem_trywait(&(shm_conn_info->tun_device_sem));
        if (try_flag != 0) { // if semaphore is locked then go out
            return TRYWAIT_NOTIFY;
        }
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        select_ret = select(info.tun_device + 1, &fdset_tun, NULL, NULL, &tv);
        if (select_ret < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                sem_post(&(shm_conn_info->tun_device_sem));
                vtun_syslog(LOG_INFO, "select error; exit");
                return BREAK_ERROR;
            } else {
                sem_post(&(shm_conn_info->tun_device_sem));
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "select error; continue norm");
#endif
                return CONTINUE_ERROR;
            }
        } else if (select_ret == 0) {
            sem_post(&(shm_conn_info->tun_device_sem));
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: we don't have data on tun device; continue norm.");
#endif
            return CONTINUE_ERROR; // Nothing to read, continue.
        }
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: we have data on tun device...");
#endif
        if (FD_ISSET(info.tun_device, &fdset_tun)) {
        } else {
            sem_post(&(shm_conn_info->tun_device_sem));
            return CONTINUE_ERROR;
        }
        // we aren't checking FD_ISSET because we did select one descriptor
        len = dev_read(info.tun_device, buf, VTUN_FRAME_SIZE - 11);
        sem_post(&(shm_conn_info->tun_device_sem));
        
        if (len < 0) { // 10 bytes for seq number (long? = 4 bytes)
            if (errno != EAGAIN && errno != EINTR) {
                vtun_syslog(LOG_INFO, "sem_post! dev read err");
                return BREAK_ERROR;
            } else { // non fatal error
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "sem_post! else dev read err"); // usually means non-blocking zeroing
#endif
                return CONTINUE_ERROR;
            }
        } else if (len == 0) {
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "sem_post! dev_read() have read nothing");
#endif
            return CONTINUE_ERROR;
        }


        if (drop_packet_flag == 1) {
            drop_counter++;
//#ifdef DEBUGG
            int other_chan = 0;
            if(info.process_num == 0) other_chan=1;
            else other_chan = 0;
            info.dropping = 1;
            if(debug_trace) {
                vtun_syslog(LOG_INFO, "drop_packet_flag info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d, hold_!head: %d", info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel, shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg, shm_conn_info->stats[other_chan].hold);
                info.max_send_q=0;
            }
            
            
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            sem_post(&(shm_conn_info->AG_flags_sem));
            
            // set dropped_flag here
            
            /*
            for (int p = 0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
                if (chan_mask & (1 << p)) {
                    vtun_syslog(LOG_INFO, "pnum %d, w %d, rtt %d, wspd %d", p, shm_conn_info->stats[p].W_cubic, shm_conn_info->stats[p].rtt_phys_avg, (shm_conn_info->stats[p].W_cubic / shm_conn_info->stats[p].rtt_phys_avg));   
                }
            }
            */
//#endif
            /*
            struct timeval time_tmp;
            
            sem_wait(&(shm_conn_info->common_sem));
            timersub(&info.current_time, &shm_conn_info->last_flood_sent, &time_tmp);
            struct timeval time_tmp2 = { 20, 0 };

            if (timercmp(&time_tmp, &time_tmp2, >)) {
                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                    if (chan_mask & (1 << i)) {
                       shm_conn_info->flood_flag[i] = 1;
                    }
                }
                shm_conn_info->last_flood_sent.tv_sec=info.current_time.tv_sec;
                shm_conn_info->last_flood_sent.tv_usec=info.current_time.tv_usec;
            }
            sem_post(&(shm_conn_info->common_sem));
            */
            return CONTINUE_ERROR;
        } else {
            if(drop_counter > 0) {
                vtun_syslog(LOG_INFO, "drop_packet_flag TOTAL %d pkts; info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d", drop_counter, info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel, shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg);
                drop_counter = 0;
            }
        }


#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: we have read data from tun device and going to send it through net");
#endif

        // now determine packet IP..
        ip = (struct my_ip*) (buf);
        unsigned int hash = (unsigned int) (ip->ip_src.s_addr);
        hash += (unsigned int) (ip->ip_dst.s_addr);
        hash += ip->ip_p;
        if (ip->ip_p == 6) { // TCP...
            tcp = (struct tcphdr*) (buf + sizeof(struct my_ip));
            //vtun_syslog(LOG_INFO, "TCP port s %d d %d", ntohs(tcp->source), ntohs(tcp->dest));
            hash += tcp->source;
            hash += tcp->dest;
        }
        chan_num = (hash % (info.channel_amount - 1)) + 1; // send thru 1-n channel
        sem_wait(&(shm_conn_info->common_sem));
        (shm_conn_info->seq_counter[chan_num])++;
        tmp_seq_counter = shm_conn_info->seq_counter[chan_num];
        sem_post(&(shm_conn_info->common_sem));
        // TODO: is it correct to first get the packet and then check if we can write it to net?
        // LSN is incorrect here! will reqrite it later
        //len = pack_packet(buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num++, channel_mode);

        len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, channel_mode);

        new_packet = 1;
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "local_seq_num %"PRIu32" seq_num %"PRIu32" len %d", info.channel[chan_num].local_seq_num, tmp_seq_counter, len);
#endif
    }
#ifdef DEBUGG
    else {
        vtun_syslog(LOG_INFO, "Trying to send from fast resend buf chan_num - %i, len - %i, seq - %"PRIu32", packet amount - %i", chan_num, len, tmp_seq_counter, idx);
    }
#endif
    
    FD_ZERO(&fdset_tun);
    FD_SET(info.channel[chan_num].descriptor, &fdset_tun);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    select_ret = select(info.channel[chan_num].descriptor + 1, NULL, &fdset_tun, NULL, &tv);
#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "Trying to select descriptor %i channel %d", info.channel[chan_num].descriptor, chan_num);
#endif
    if (select_ret != 1) {
        sem_wait(&(shm_conn_info->resend_buf_sem));
        idx = add_fast_resend_frame(chan_num, buf, len, tmp_seq_counter); // fast_resend technique is used for info.channel_amount > 1
        sem_post(&(shm_conn_info->resend_buf_sem));
        //if(new_packet) {
        //    info.channel[chan_num].local_seq_num--; // send next time... another pkt will have this lsn soon!
        //}
        if (idx == -1) {
            vtun_syslog(LOG_ERR, "ERROR: fast_resend_buf is full");
        }
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "BUSY - descriptor %i channel %d");
#endif
        return NET_WRITE_BUSY_NOTIFY;
    }
#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "READY - descriptor %i channel %d");
#endif
    sem_wait(&(shm_conn_info->resend_buf_sem));
    seqn_add_tail(chan_num, buf, len, tmp_seq_counter, channel_mode, info.pid);
    sem_post(&(shm_conn_info->resend_buf_sem));

    statb.bytes_sent_norm += len;

#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "writing to net.. sem_post! finished blw len %d seq_num %d, mode %d chan %d, dirty_seq_num %u", len, shm_conn_info->seq_counter[chan_num], (int) channel_mode, chan_num, (dirty_seq_num+1));
    vtun_syslog(LOG_INFO, "select_devread_send() frame ... chan %d seq %"PRIu32" len %d", chan_num, tmp_seq_counter, len);
#endif
    if(debug_trace) {
        vtun_syslog(LOG_INFO, "writing to net.. sem_post! finished blw len %d seq_num %d, mode %d chan %d, dirty_seq_num %u", len, shm_conn_info->seq_counter[chan_num], (int) channel_mode, chan_num, (dirty_seq_num+1));
    }

    // now add correct mini_sum and local_seq_num
    //if(!new_packet) {
        local_seq_num_p=0;
        tmp_flag=0;
        sum=0;
        len = seqn_break_tail(buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
        len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, tmp_flag);
        if( (info.rtt2_lsn[chan_num] == 0) && ((shm_conn_info->stats[info.process_num].max_ACS2/info.eff_len) > (1000/shm_conn_info->stats[info.process_num].exact_rtt)) ) {
            info.rtt2_lsn[chan_num] = info.channel[chan_num].local_seq_num;
            info.rtt2_tv[chan_num] = info.current_time;
            info.rtt2_send_q[chan_num] = info.channel[chan_num].send_q;
        }
    //}

    struct timeval send1; // need for mean_delay calculation (legacy)
    struct timeval send2; // need for mean_delay calculation (legacy)
    gettimeofday(&send1, NULL );
    // send DATA
    int len_ret = udp_write(info.channel[chan_num].descriptor, buf, len);
    info.channel[chan_num].packet_recv_counter = 0;
    if (len && (len_ret < 0)) {
        vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
        return BREAK_ERROR;
    }
    sem_wait(&shm_conn_info->common_sem);
    if (shm_conn_info->eff_len.warming_up < EFF_LEN_BUFF) {
        shm_conn_info->eff_len.warming_up++;
    }
    shm_conn_info->eff_len.len_num[shm_conn_info->eff_len.counter] = len_ret;
    if (shm_conn_info->eff_len.counter++ >= EFF_LEN_BUFF) {
        shm_conn_info->eff_len.counter = 0;
    }
    shm_conn_info->eff_len.sum = shm_conn_info->eff_len.len_num[0];
    for (int i = 1; i < shm_conn_info->eff_len.warming_up; i++) {
        shm_conn_info->eff_len.sum += shm_conn_info->eff_len.len_num[i];
    }
    shm_conn_info->eff_len.sum /= shm_conn_info->eff_len.warming_up;
    if (shm_conn_info->eff_len.sum <= 0)
        shm_conn_info->eff_len.sum = 1;
    sem_post(&shm_conn_info->common_sem);
    gettimeofday(&send2, NULL );

    info.channel[chan_num].local_seq_num++;
    if (info.channel[chan_num].local_seq_num == (UINT32_MAX - 1)) {
       info.channel[chan_num].local_seq_num = 0; // TODO: 1. not required; 2. disaster at CLI-side! 3. max. ~4TB of data
    }

    delay_acc += (int) ((send2.tv_sec - send1.tv_sec) * 1000000 + (send2.tv_usec - send1.tv_usec)); // need for mean_delay calculation (legacy)
    delay_cnt++; // need for mean_delay calculation (legacy)
#ifdef DEBUGG
    if((delay_acc/delay_cnt) > 100) vtun_syslog(LOG_INFO, "SEND DELAY: %u us", (delay_acc/delay_cnt));
#endif

    shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_data_len_amt += len_ret;
    info.channel[chan_num].up_len += len_ret;
    info.channel[chan_num].up_packets++;
    info.channel[chan_num].bytes_put++;
if(drop_packet_flag) {  vtun_syslog(LOG_INFO, "bytes_pass++ select_send"); } 
    info.byte_efficient += len_ret;

    last_sent_packet_num[chan_num].seq_num = tmp_seq_counter;

    return len;
}

int write_buf_check_n_flush(int logical_channel) {
    int fprev = -1;
    int fold = -1;
    int len;
    //struct timeval max_latency_drop = MAX_LATENCY_DROP;
    struct timeval max_latency_drop = info.max_latency_drop;
    int rtt_fix; //in ms
    struct timeval tv_tmp, rtt_fix_tv;
    struct timeval tv;
    forced_rtt_reached = check_force_rtt_max_wait_time(logical_channel);
    fprev = shm_conn_info->write_buf[logical_channel].frames.rel_head;
    shm_conn_info->write_buf[logical_channel].complete_seq_quantity = 0;

    // first select tun
    fd_set fdset2;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fdset2);
    FD_SET(info.tun_device, &fdset2);
    int sel_ret = select(info.tun_device + 1, NULL, &fdset2, NULL, &tv);
    if (sel_ret == 0) {
        return 0; // save rtt!
    } else if (sel_ret == -1) {
        vtun_syslog(LOG_ERR, "write_buf_check_n_flush select error! errno %d",errno);
        return 0;
    }

#ifdef DEBUGG
    if (fprev == -1) {
        vtun_syslog(LOG_INFO, "no data to write at all!");
    } else {
        vtun_syslog(LOG_INFO, "trying to write to to dev: seq_num %"PRIu32" lws %"PRIu32" chan %d", shm_conn_info->frames_buf[fprev].seq_num,
                shm_conn_info->write_buf[logical_channel].last_written_seq, logical_channel);
    }
#endif
    acnt = 0;
    if (fprev > -1) {
        if(info.least_rx_seq[logical_channel] == UINT32_MAX) {
            info.least_rx_seq[logical_channel] = 0; // protect us from possible failures to calculate LRS in get_write_buf_wait_data()
        }
        timersub(&info.current_time, &shm_conn_info->frames_buf[fprev].time_stamp, &tv_tmp);
        int cond_flag = shm_conn_info->frames_buf[fprev].seq_num == (shm_conn_info->write_buf[logical_channel].last_written_seq + 1) ? 1 : 0;
        if (             (cond_flag && forced_rtt_reached) 
                      || (buf_len > lfd_host->MAX_ALLOWED_BUF_LEN)
                      || ( timercmp(&tv_tmp, &max_latency_drop, >=))
                      || ( (shm_conn_info->frames_buf[fprev].seq_num < info.least_rx_seq[logical_channel]) && forced_rtt_reached )
           ) {
            if (!cond_flag) {
                shm_conn_info->tflush_counter += shm_conn_info->frames_buf[fprev].seq_num
                        - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
                if(buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) {
                    vtun_syslog(LOG_INFO, "MAX_ALLOWED_BUF_LEN tflush_counter %"PRIu32" %d",  shm_conn_info->tflush_counter, incomplete_seq_len);
                } else if (timercmp(&tv_tmp, &max_latency_drop, >=)) {
                    vtun_syslog(LOG_INFO, "MAX_LATENCY_DROP tflush_counter %"PRIu32" isl %d sqn %d, lws %d lrxsqn %d bl %d lat %d ms",  shm_conn_info->tflush_counter, incomplete_seq_len, shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq, info.least_rx_seq[logical_channel], buf_len, tv2ms(&tv_tmp));
                } else if (shm_conn_info->frames_buf[fprev].seq_num < info.least_rx_seq[logical_channel]) {
                    if(info.prev_flushed) {
                        info.flush_sequential += 
                            shm_conn_info->frames_buf[fprev].seq_num - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
                    } else {
                        // TODO: write avg stats here?
                        info.flush_sequential = 
                            shm_conn_info->frames_buf[fprev].seq_num - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
                    }
                    info.prev_flushed = 1;
                    vtun_syslog(LOG_INFO, "LOSS PSL=%d : PBL=%d; tflush_counter %"PRIu32" %d sqn %d, lws %d lrxsqn %d lat %d ms", info.flush_sequential, info.write_sequential, shm_conn_info->tflush_counter, incomplete_seq_len, shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq, info.least_rx_seq[logical_channel], tv2ms(&tv_tmp));
                }
            }
            
            if(info.prev_flushed) {
                // TODO: write avg stats here?
                info.write_sequential = 1;
            } else {
                info.write_sequential++;
            }
            info.prev_flushed = 0;

            struct frame_seq frame_seq_tmp = shm_conn_info->frames_buf[fprev];
#ifdef DEBUGG
            struct timeval work_loop1, work_loop2;
            gettimeofday(&work_loop1, NULL );
            if (timercmp(&tv_tmp, &max_latency_drop, >=)) {
                vtun_syslog(LOG_INFO, "flush packet %"PRIu32" lws %"PRIu32" %ld.%06ld", shm_conn_info->frames_buf[fprev].seq_num,
                        shm_conn_info->write_buf[logical_channel].last_written_seq, tv_tmp.tv_sec, tv_tmp.tv_usec);
            }
#endif
            if ((len = dev_write(info.tun_device, frame_seq_tmp.out, frame_seq_tmp.len)) < 0) {
                vtun_syslog(LOG_ERR, "error writing to device %d %s chan %d", errno, strerror(errno), logical_channel);
                if (errno != EAGAIN && errno != EINTR) { // TODO: WTF???????
                    vtun_syslog(LOG_ERR, "dev write not EAGAIN or EINTR");
                } else {
                    vtun_syslog(LOG_ERR, "dev write intr - need cont");
                    return 0;
                }

            } else {
                if (len < frame_seq_tmp.len) {
                    vtun_syslog(LOG_ERR, "ASSERT FAILED! could not write to device immediately; dunno what to do!! bw: %d; b rqd: %d", len,
                            shm_conn_info->frames_buf[fprev].len);
                }
            }
#ifdef DEBUGG
            gettimeofday(&work_loop2, NULL );
            vtun_syslog(LOG_INFO, "dev_write time: %"PRIu32" us", (long int) ((work_loop2.tv_sec - work_loop1.tv_sec) * 1000000 + (work_loop2.tv_usec - work_loop1.tv_usec)));
            vtun_syslog(LOG_INFO, "writing to dev: bln is %d icpln is %d, sqn: %"PRIu32", lws: %"PRIu32" mode %d, ns: %d, w: %d len: %d, chan %d", buf_len, incomplete_seq_len,
                    shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq, (int) channel_mode, shm_conn_info->normal_senders,
                    weight, shm_conn_info->frames_buf[fprev].len, logical_channel);
#endif
            shm_conn_info->write_buf[logical_channel].last_written_seq = shm_conn_info->frames_buf[fprev].seq_num;
            shm_conn_info->write_buf[logical_channel].last_write_time.tv_sec = info.current_time.tv_sec;
            shm_conn_info->write_buf[logical_channel].last_write_time.tv_usec = info.current_time.tv_usec;

            fold = fprev;
            fprev = shm_conn_info->frames_buf[fprev].rel_next;
            frame_llist_free(&shm_conn_info->write_buf[logical_channel].frames, &shm_conn_info->wb_free_frames, shm_conn_info->frames_buf, fold);
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}


/*
               _ _             _            __               _     _ 
              (_) |           | |          / _|             | |   | |
__      ___ __ _| |_ ___      | |__  _   _| |_      __ _  __| | __| |
\ \ /\ / / '__| | __/ _ \     | '_ \| | | |  _|    / _` |/ _` |/ _` |
 \ V  V /| |  | | ||  __/     | |_) | |_| | |     | (_| | (_| | (_| |
  \_/\_/ |_|  |_|\__\___|     |_.__/ \__,_|_|      \__,_|\__,_|\__,_|
                      ______              ______                     
                     |______|            |______|                    
*/

int write_buf_add(int conn_num, char *out, int len, uint32_t seq_num, uint32_t incomplete_seq_buf[], int *buf_len, int mypid, char *succ_flag) {
    char *ptr;
    int mlen = 0;
#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "write_buf_add called! len %d seq_num %"PRIu32" chan %d", len, seq_num, conn_num);
#endif
    if(debug_trace) {
        vtun_syslog(LOG_INFO, "write_buf_add called! len %d seq_num %"PRIu32" chan %d", len, seq_num, conn_num);
    }
    // place into correct position first..
    int i = shm_conn_info->write_buf[conn_num].frames.rel_head, n;
    int newf;
    uint32_t istart;
    int j=0;
/*  this code moved to upper level a few lines before call
    if(info.channel[conn_num].local_seq_num_beforeloss == 0) {
        // TODO: this fix actually not required if we don't mess packets too much -->
        //if((seq_num - MAX_REORDER_PERPATH) > shm_conn_info->write_buf[conn_num].last_received_seq[info.process_num]) {
           shm_conn_info->write_buf[conn_num].last_received_seq[info.process_num] = seq_num - MAX_REORDER_PERPATH;
        //}
    } else {
        shm_conn_info->write_buf[conn_num].last_received_seq_shadow[info.process_num] = seq_num;
    }
*/
/*
    if(conn_num <= 0) { // this is a workaround for some bug... TODO!!
            vtun_syslog(LOG_INFO, "BUG! write_buf_add called with broken chan_num %d: seq_num %"PRIu32" len %d", conn_num, seq_num, len );
            *succ_flag = -2;
            return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
    }
     */
    if (i == -1) {
        shm_conn_info->write_buf[conn_num].last_write_time = info.current_time;
    }
    if (( (seq_num > shm_conn_info->write_buf[conn_num].last_written_seq) &&
            (seq_num - shm_conn_info->write_buf[conn_num].last_written_seq) >= STRANGE_SEQ_FUTURE ) ||
            ( (seq_num < shm_conn_info->write_buf[conn_num].last_written_seq) &&
              (shm_conn_info->write_buf[conn_num].last_written_seq - seq_num) >= STRANGE_SEQ_PAST )) { // this ABS comparison makes checks in MRB unnesesary...
        vtun_syslog(LOG_INFO, "WARNING! DROP BROKEN PKT logical channel %i seq_num %"PRIu32" lws %"PRIu32"; diff is: %d >= 1000", conn_num, seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, (seq_num - shm_conn_info->write_buf[conn_num].last_written_seq));
        shm_conn_info->write_buf[conn_num].broken_cnt++;
        if(shm_conn_info->write_buf[conn_num].broken_cnt > 3) {
            // fix lws
            shm_conn_info->write_buf[conn_num].last_written_seq = seq_num-1;
            vtun_syslog(LOG_INFO, "Broken is perm , Applying permanent fix...");
        } else {
            *succ_flag = -2;
            return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
        }
    }
    shm_conn_info->write_buf[conn_num].broken_cnt = 0;

    if ( (seq_num <= shm_conn_info->write_buf[conn_num].last_written_seq)) {
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "drop dup pkt seq_num %"PRIu32" lws %"PRIu32"", seq_num, shm_conn_info->write_buf[conn_num].last_written_seq);
#endif
        *succ_flag = -2;
        return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
    }
    // now check if we can find it in write buf current .. inline!
    // TODO: run from BOTTOM! if seq_num[i] < seq_num: break
    acnt = 0;
    if(seq_num <= shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_tail].seq_num) {
        while( i > -1 ) {
            if(shm_conn_info->frames_buf[i].seq_num == seq_num) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "drop exist pkt seq_num %"PRIu32" sitting in write_buf chan %i", seq_num, conn_num);
#endif
                //return -3;
                return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
            }
            i = shm_conn_info->frames_buf[i].rel_next;
#ifdef DEBUGG
            if(assert_cnt(5)) break;
#endif
        }
    }
    i = shm_conn_info->write_buf[conn_num].frames.rel_head;

    if(frame_llist_pull(   &shm_conn_info->wb_free_frames,
                           shm_conn_info->frames_buf,
                           &newf) < 0) {
        // try a fix
        vtun_syslog(LOG_ERR, "WARNING! write buffer exhausted");
        return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
        vtun_syslog(LOG_ERR, "WARNING! No free elements in wbuf! trying to free some...");
        fix_free_writebuf();
        if(frame_llist_pull(&shm_conn_info->wb_free_frames,
                            shm_conn_info->frames_buf,
                            &newf) < 0) {
            vtun_syslog(LOG_ERR, "FATAL: could not fix free wb.");
            *succ_flag = -1;
            return -1;
        }
    }
    //vtun_syslog(LOG_INFO, "TESTT %d lws: %"PRIu32"", 12, shm_conn_info->write_buf.last_written_seq);
    shm_conn_info->frames_buf[newf].seq_num = seq_num;
    memcpy(shm_conn_info->frames_buf[newf].out, out, len);
    shm_conn_info->frames_buf[newf].len = len;
    shm_conn_info->frames_buf[newf].sender_pid = mypid;
    shm_conn_info->frames_buf[newf].physical_channel_num = info.process_num;
    shm_conn_info->frames_buf[newf].time_stamp = info.current_time;
    shm_conn_info->frames_buf[newf].current_rtt = info.exact_rtt;
    if(i<0) {
        // expensive op; may be optimized!
        shm_conn_info->frames_buf[newf].rel_next = -1;
        shm_conn_info->write_buf[conn_num].frames.rel_head = shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;
        //*buf_len = 1;
        //return  ((seq_num == (shm_conn_info->write_buf.last_written_seq+1)) ? 0 : 1);
        mlen = missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
        //vtun_syslog(LOG_INFO, "write: add to head!");
        *succ_flag=0;
        return mlen;
    } else {
        //vtun_syslog(LOG_INFO, "write: add to tail!");

        istart = shm_conn_info->frames_buf[i].seq_num;
        if( (shm_conn_info->frames_buf[i].seq_num > seq_num) &&
                (shm_conn_info->frames_buf[i].rel_next > -1)) {
            // append to head
            shm_conn_info->write_buf[conn_num].frames.rel_head = newf;
            shm_conn_info->frames_buf[newf].rel_next = i;
        } else {
            if(shm_conn_info->frames_buf[i].rel_next > -1) {
                acnt = 0;
                while( i > -1 ) {
                    n = shm_conn_info->frames_buf[i].rel_next;
                    if(n > -1) {
                        if( shm_conn_info->frames_buf[n].seq_num > seq_num) {
                            shm_conn_info->frames_buf[i].rel_next = newf;
                            shm_conn_info->frames_buf[newf].rel_next = n;
                            break;
                        } // else try next...
                    } else {
                        // append to tail

                        shm_conn_info->frames_buf[i].rel_next=newf;
                        shm_conn_info->frames_buf[newf].rel_next = -1;
                        shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;

                        break;
                    }
                    i = n;
                    istart++;
#ifdef DEBUGG
                    if(assert_cnt(6)) break;
#endif
                }

            } else {
                if(shm_conn_info->frames_buf[i].seq_num > seq_num) {
                    shm_conn_info->write_buf[conn_num].frames.rel_head = newf;
                    shm_conn_info->frames_buf[newf].rel_next = i;
                } else {
                    shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;
                    shm_conn_info->frames_buf[i].rel_next = newf;
                    shm_conn_info->frames_buf[newf].rel_next = -1;
                }

            }
        }
    }

    mlen = missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);

    *succ_flag= 0;
    return mlen;
}

void sem_post_if(int *dev_my, sem_t *rd_sem) {
    if(*dev_my) sem_post(rd_sem);
    else {
        // it is actually normal to try to post sem in idle-beg and in net-end blocks
        // vtun_syslog(LOG_INFO, "ASSERT FAILED! posting posted rd_sem");
    }
    *dev_my = 0;
}

/**
 * не отправлен ли потерянный пакет уже на перезапрос
 */
int check_sent (uint32_t seq_num, struct resent_chk sq_rq_buf[], int *sq_rq_pos, int chan_num) {
    int i;
    for(i=(RESENT_MEM-1); i>=0; i--) {
        if( (sq_rq_buf[i].seq_num == seq_num) && (sq_rq_buf[i].chan_num == chan_num)) {
            return 1;
        }
    }
    // else - increment pos;

    sq_rq_buf[*sq_rq_pos].seq_num = seq_num;
    sq_rq_buf[*sq_rq_pos].chan_num = chan_num;
    (*sq_rq_pos) ++;
    if(*sq_rq_pos >= RESENT_MEM) {
        *sq_rq_pos = 0;
    }
    return 0;
}

// TODO: profiler says it is expensive function. get rid of timed wait! it is
//  for debugging only!
int sem_wait_tw(sem_t *sem) { 
    struct timeval tv;
    struct timespec ts;
    int sval;
    gettimeofday(&tv, NULL);
    //ts.tv_sec = tv.tv_sec + 2 + (tv.tv_usec % 3);
    ts.tv_sec = tv.tv_sec + 5 + (tv.tv_usec % 3);
    ts.tv_nsec = 0;

    sem_getvalue(sem, &sval);
    if(sval > 1) {
        vtun_syslog(LOG_ERR, "ASSERT FAILED! Semaphore value > 1: %d, doing one more sem_wait", sval);
        sem_wait(sem);
    }

    if( sem_timedwait(sem, &ts) < 0 ) {
        vtun_syslog(LOG_ERR, "ASSERT FAILED! Emergrency quit semaphore waiting");
        sem_post(sem);
    }
    return 0;
}


int set_max_chan(uint32_t chan_mask) {
    //must sync on stats_sem
    int min_bdp = 1000000;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i))
            && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
            if(tv2ms(&shm_conn_info->stats[i].bdp1) < min_bdp) {
                min_bdp = tv2ms(&shm_conn_info->stats[i].bdp1);
                max_chan = i;
            }
        }
    }
    vtun_syslog(LOG_INFO, "Head change BDP");
    shm_conn_info->max_chan = max_chan;
}

int redetect_head_unsynced(int32_t chan_mask, int exclude) {
    int fixed = 0;
    int Ch = 0;
    int Cs = 0;
     // This is AG_MODE algorithm
    int moremax = 0;
    int max_chan_H = -1;
    int max_chan_CS = -1;
    int min_rtt = 99999;
    int max_ACS = 0;
    int max_ACS_chan = -1;

    if(shm_conn_info->idle) {
        // use RTT-only choosing of head while idle!
        int min_rtt = 99999;
        int min_rtt_chan = 0;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                    min_rtt = shm_conn_info->stats[i].exact_rtt;
                    min_rtt_chan = i;
                }
            }
        }
        vtun_syslog(LOG_INFO, "IDLE: Head is %d due to lowest rtt %d", min_rtt_chan, min_rtt);
        shm_conn_info->max_chan = min_rtt_chan;
        fixed = 1;
        shm_conn_info->last_switch_time = info.current_time; // nothing bad in this..
    } else {
        // this code works only if not idling!
        // This is ALL-mode algorithm, almost useless
        if(shm_conn_info->stats[max_chan].srtt2_10 > 0 && (shm_conn_info->stats[max_chan].ACK_speed/100) > 0) {
                max_chan = shm_conn_info->max_chan;
                int min_Ch = 1000000;
                int min_Ch_chan = 1000000;
                int min_Cs = 1000000;
                int min_Cs_chan = 1000000;
                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                    if ((chan_mask & (1 << i))
                        && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                        if(shm_conn_info->stats[i].ACK_speed/100 == 0) continue;
                        Ch = 100*shm_conn_info->stats[i].srtt2_10/shm_conn_info->stats[max_chan].srtt2_10;
                        Cs = shm_conn_info->stats[max_chan].ACK_speed/(shm_conn_info->stats[i].ACK_speed/100);
                        if(Ch < min_Ch) {
                            min_Ch = Ch;
                            min_Ch_chan = i;
                        }
                        if(Cs < min_Cs) {
                            min_Cs = Cs;
                            min_Cs_chan = i;
                        }
                    }
                }
                if(min_Cs < CS_THRESH && min_Ch < CH_THRESH && min_Cs_chan == min_Ch_chan) {
                    vtun_syslog(LOG_INFO, "CS/CH: Need changing HEAD to %d with Cs %d Ch %d", min_Ch_chan, min_Cs, min_Ch);
                    //shm_conn_info->max_chan = min_Ch_chan;
                    max_chan_CS = min_Ch_chan; // is result here!
                }

            }

            // ---> ACS == and rtt
            min_rtt = shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt;
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ( (chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != shm_conn_info->max_chan) && (i != exclude) ) {
                    if(percent_delta_equal(shm_conn_info->stats[i].ACK_speed, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed, 10)) { // 15% corridor to consider speeds the same
                        // new ALGO: Si ~= Sh => we almost certainly selected head wrong.
                        // now choose best rtt2 from all chans that have same speed!
                        if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                            min_rtt = shm_conn_info->stats[i].exact_rtt;
                            max_chan_H = i;
                        }
                        // TODO: need smoothed percent compare! with selections auto-mgmt!
                    }
                }
            }

            if(max_chan_H > -1) {
                vtun_syslog(LOG_INFO, "ACS~=: Need changing HEAD to %d with ACS %d and rtt %d", max_chan_H, shm_conn_info->stats[max_chan_H].ACK_speed, shm_conn_info->stats[max_chan_H].exact_rtt);
            }

            // TODO: what to do if these two methods disagree? Is it possible?
            
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ( (chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != shm_conn_info->max_chan) && (i != exclude) ) {
                    if( !percent_delta_equal(shm_conn_info->stats[i].ACK_speed, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed, 10)
                             && ( shm_conn_info->stats[i].ACK_speed > shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed )) { // 15% corridor to consider speeds the same
                        max_chan_H = i;
                        vtun_syslog(LOG_INFO, "ACS>>: Need changing HEAD to %d with ACS %d > ACS(max) %d", i, shm_conn_info->stats[i].ACK_speed, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed);
                    }
                }
            }
        
        // TODO HERE: What if Wf < Wh and Sf > Sh => RSRf < RSRh => f can not get full speed due to RSRf
        if(max_chan_H != -1 && max_chan_CS == -1) {
//                        vtun_syslog(LOG_INFO, "Head change H");
            shm_conn_info->max_chan = max_chan_H;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
        } else if (max_chan_H == -1 && max_chan_CS != -1) {
            vtun_syslog(LOG_INFO, "Head change CS");
            shm_conn_info->max_chan = max_chan_CS;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
        } else if (max_chan_H != -1 && max_chan_CS != -1) {
            if(max_chan_H != max_chan_CS) {
                vtun_syslog(LOG_INFO, "Head change: CS/CH don't agree with Si/Sh: using latter");
            }
            shm_conn_info->max_chan = max_chan_H;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
        } else { // means max_chan = -1; find first alive chan
            // Two possibilities here: 1. we detected correct channel 2. there is only one channel alive
            // 3. it may come that chan is excluded and only one chan is there
            int alive_cnt = 0;
            int alive_chan = -1;
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != exclude)) { // excluded = dead
                    alive_chan = i;
                    alive_cnt++;
                }
            }
            if(alive_cnt == 1) {
                vtun_syslog(LOG_INFO, "Head change - first alive (default): %d, excluded: %d ACS2=%d,PCS2=%d (idle? %d) (sqe %d) (rsr %d) ", alive_chan, exclude, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2, shm_conn_info->idle, send_q_eff, info.rsr );
                shm_conn_info->max_chan = alive_chan;
            }
            if(alive_cnt == 0) { // no chan is alive, do without excluded
                int alive_cnt = 0;
                int alive_chan = -1;
                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                    if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) {
                        alive_chan = i;
                        alive_cnt++;
                    }
                }
                if(alive_cnt == 1) {
                    vtun_syslog(LOG_INFO, "Head no change - first and only channel dead: %d, excluded: %d", alive_chan, exclude);
                    shm_conn_info->max_chan = alive_chan;
                } else {
                    vtun_syslog(LOG_ERR, "WARNING! No chan is alive; no head (undefined): %d", shm_conn_info->max_chan);
                }
            }
            if(alive_cnt > 1) {
                // all is OK
                vtun_syslog(LOG_INFO, "Head detect - current max chan is correct: max_chan=%d, exclude=%d", shm_conn_info->max_chan, exclude);
            }
        }
    }
    return fixed;
}

/* M = Wmax, W = desired Wcubic */
double t_from_W (double W, double M, double B, double C) {
    // Math form: t = ((B M)/C)^(1/3)+(C^2 W-C^2 M)^(1/3)/C
    return cbrt(B * M / C) + cbrt( (W - M) / C );
}

// t in ms
int set_W_unsync(int t) {
    double K = cbrt((((double) info.send_q_limit_cubic_max) * info.B) / info.C);
    uint32_t limit_last = info.send_q_limit_cubic;
    info.send_q_limit_cubic = (uint32_t) (info.C * pow(((double) (t)) - K, 3) + info.send_q_limit_cubic_max);
    shm_conn_info->stats[info.process_num].W_cubic = info.send_q_limit_cubic;

    return 1;
}

int set_W_to(int send_q, int slowness, struct timeval *loss_time) {
    int new_cubic = (int32_t)info.send_q_limit_cubic - ((int32_t)info.send_q_limit_cubic - send_q) / slowness;
    int t = (int) t_from_W( new_cubic, info.send_q_limit_cubic_max, info.B, info.C);
    // No logs here: it will always be trying to converge here
    //vtun_syslog(LOG_INFO,"Down converging from %d to %d s_q_e %d", (int32_t)info.send_q_limit_cubic, new_cubic, send_q_eff);
    struct timeval new_lag;
    ms2tv(&new_lag, t * CUBIC_T_DIV); // multiply to compensate
    timersub(&info.current_time, &new_lag, loss_time); // set new loss time back in time
    set_W_unsync(t);
}

// returns max value for send_q (NOT index) at which weight is > 0.7
int set_smalldata_weights( struct _smalldata *sd, int *pts) {
    struct timeval tv_tmp;
    int ms;
    int max_good_sq = -1;
    for (int i=0; i< (MAX_SD_W / SD_PARITY); i++) {
        timersub(&info.current_time, &sd->ts[i], &tv_tmp);
        ms = tv2ms(&tv_tmp);
        sd->w[i] = -(double)ms / (double)ZERO_W_THR + 1.0;
        if(sd->w[i] < 0.0) sd->w[i] = 0;
        if(sd->w[i] > 0.1) (*pts)++;
        if(sd->w[i] > 1.0) {
            // TODO: check unnesessary
            vtun_syslog(LOG_ERR, "ssw: ERROR! Weight somehow was > 1.0: %f ms %d ", sd->w[i], ms);
            sd->w[i] = 1.0;
        }
        if(sd->w[i] > 0.7) {
            //vtun_syslog(LOG_INFO, "ssw: Found last datapoint sq=%f ACS=%f w=%f ms %d", sd->send_q[i], sd->ACS[i], sd->w[i], ms);
            max_good_sq = i;
        }
    }
    return max_good_sq * SD_PARITY;
}

int get_slope(struct _smalldata *sd) {
    int len = SLOPE_POINTS; // 15 datapoints to draw slope
    int pts = 0;
    int to_idx = set_smalldata_weights(sd, &pts);
    if( ((to_idx / SD_PARITY) < SLOPE_POINTS+1) || pts < 15) { // TODO: is 5 ok for slope?
        return 999999; // could not get slope?
    }
    int from_idx = to_idx / SD_PARITY - len;

    double c0, c1, cov00, cov01, cov11, chisq; // model Y = c_0 + c_1 X
/*
    vtun_syslog(LOG_INFO, "slope: s_q %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f", 
                            sd->send_q[from_idx+0],  sd->send_q[from_idx+1], sd->send_q[from_idx+2], sd->send_q[from_idx+3], sd->send_q[from_idx+4], sd->send_q[from_idx+5], sd->send_q[from_idx+6], sd->send_q[from_idx+7], sd->send_q[from_idx+8], sd->send_q[from_idx+9], sd->send_q[from_idx+10], sd->send_q[from_idx+12], sd->send_q[from_idx+13], sd->send_q[from_idx+14], sd->send_q[from_idx+15]);
    vtun_syslog(LOG_INFO, "slope: ACS %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f", 
                            sd->ACS[from_idx+0],  sd->ACS[from_idx+1], sd->ACS[from_idx+2], sd->ACS[from_idx+3], sd->ACS[from_idx+4], sd->ACS[from_idx+5], sd->ACS[from_idx+6], sd->ACS[from_idx+7], sd->ACS[from_idx+8], sd->ACS[from_idx+9], sd->ACS[from_idx+10], sd->ACS[from_idx+12], sd->ACS[from_idx+13], sd->ACS[from_idx+14], sd->ACS[from_idx+15]);
    vtun_syslog(LOG_INFO, "slope:   w %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f", 
                            sd->w[from_idx+0],  sd->w[from_idx+1], sd->w[from_idx+2], sd->w[from_idx+3], sd->w[from_idx+4], sd->w[from_idx+5], sd->w[from_idx+6], sd->w[from_idx+7], sd->w[from_idx+8], sd->w[from_idx+9], sd->w[from_idx+10], sd->w[from_idx+12], sd->w[from_idx+13], sd->w[from_idx+14], sd->w[from_idx+15]);
*/
    fit_wlinear (&sd->send_q[from_idx], 1, &sd->w[from_idx], 1, &sd->ACS[from_idx], 1, len, 
                   &c0, &c1, &cov00, &cov01, &cov11, &chisq);

    //vtun_syslog(LOG_INFO, "slope: Linear fit c1 is %f", c1);
    if(isnan(c1)) return 999999;
    return (int) (c1 * 100.0);
}

/*
.__   _____   .___    .__  .__        __                     ___  ___    
|  |_/ ____\__| _/    |  | |__| ____ |  | __ ___________    /  /  \  \   
|  |\   __\/ __ |     |  | |  |/    \|  |/ // __ \_  __ \  /  /    \  \  
|  |_|  | / /_/ |     |  |_|  |   |  \    <\  ___/|  | \/ (  (      )  ) 
|____/__| \____ |_____|____/__|___|  /__|_ \\___  >__|     \  \    /  /  
               \/_____/            \/     \/    \/          \__\  /__/   
*/

int lfd_linker(void)
{
    memset((void *)&ag_stat, 0, sizeof(ag_stat));
    
    #ifdef TIMEWARP
        timewarp = malloc(TW_MAX); // 10mb time-warp
        memset(timewarp, 0, TW_MAX);
        tw_cur = 0;
        sprintf(timewarp+tw_cur, "started\n");
        int fdc = open("/tmp/TIMEWARP.log", O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        close(fdc);
        int send_q_min = 999999999;
        int send_q_eff_min = 999999999;
    #endif
    
    js_buf = malloc(JS_MAX);
    memset(js_buf, 0, JS_MAX);
    js_cur = 0;

    #ifdef SEND_Q_LOG
        jsSQ_buf = malloc(JS_MAX);
        memset(jsSQ_buf, 0, JS_MAX);
        jsSQ_cur = 0;
        struct timer_obj *jsSQ_timer = create_timer();
        struct timeval t1 = { 0, 300 }; // this time is crucial to detect send_q dops in case of long hold
        set_timer(jsSQ_timer, &t1);
        start_json_arr(jsSQ_buf, &jsSQ_cur, "send_q");
    #endif
    
    struct timeval MAX_REORDER_LATENCY = { 0, 50000 };


    int service_channel = lfd_host->rmt_fd; //aka channel 0
    int len, len1, fl;
    int err=0;
    struct timeval tv;
    char *out, *out2 = NULL;
    char *buf; // in common for info packet
    uint32_t seq_num;

    int maxfd;
    int imf;
    int fprev = -1;
    int fold = -1;
    uint32_t incomplete_seq_buf[FRAME_BUF_SIZE];
    send_q_limit = START_SQL; // was 55000
    
    uint16_t tmp_s;
    uint32_t tmp_l;

    sem_t *resend_buf_sem = &(shm_conn_info->resend_buf_sem);
    sem_t *write_buf_sem = &(shm_conn_info->write_buf_sem);

    struct timeval send1; // calculate send delay
    struct timeval send2;
    struct timeval old_time = {0, 0};
    struct timeval ping_req_tv[MAX_TCP_LOGICAL_CHANNELS];
    for(int i=0; i<MAX_TCP_LOGICAL_CHANNELS; i++) {
        gettimeofday(&ping_req_tv[i], NULL);
    }
    long int last_action = 0; // for ping; TODO: too many vars... this even has clone ->
    long int last_net_read = 0; // for timeout;

    struct resent_chk sq_rq_buf[RESENT_MEM]; // for check_sent
    int sq_rq_pos = 0; // for check_sent

    uint16_t flag_var; // packet struct part

    char succ_flag; // return flag

    int dev_my_cnt = 0; // statistic and watchdog
    
    // timing
    long int last_tick = 0; // important ticking
    struct timeval last_timing = {0, 0};
    struct timeval timer_resolution = {0, 0};
    struct timeval max_latency = {0, 0};
    struct timeval tv_tmp;
        // now set up timer resolution
     max_latency.tv_sec = lfd_host->MAX_LATENCY/1000;
     max_latency.tv_usec = (lfd_host->MAX_LATENCY - max_latency.tv_sec * 1000) * 1000;
    
    if( (lfd_host->TICK_SECS * 1000) > lfd_host->MAX_LATENCY) {
          timer_resolution.tv_sec = max_latency.tv_sec;
          timer_resolution.tv_usec = max_latency.tv_usec;
    } else {
          timer_resolution.tv_sec = lfd_host->TICK_SECS;
          timer_resolution.tv_usec = 0;
    }

#ifdef HAVE_SCHED_H
    int cpu_numbers = sysconf(_SC_NPROCESSORS_ONLN); /* Get numbers of CPUs */
    if (cpu_numbers != -1) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(info.process_num % cpu_numbers, &cpu_set);
        if (1) {
            vtun_syslog(LOG_INFO, "Can't set cpu");
        } else {
            vtun_syslog(LOG_INFO, "Set process %i on cpu %i", info.process_num, info.process_num % cpu_numbers);
        }
    } else {
        vtun_syslog(LOG_INFO, "sysconf(_SC_NPROCESSORS_ONLN) return error");
    }
#endif
    int sender_pid; // tmp var for resend detect my own pid

    uint32_t last_last_written_seq[MAX_TCP_LOGICAL_CHANNELS]; // for LWS notification TODO: move this to write_buf!

    // ping stats
    int ping_rcvd = 1; // flag that ping is rcvd; ok to send next
    long int last_ping=0;

    //int weight = 1; // defined at top!!!???

    // weight processing in delay algo
    delay_acc = 0; // accumulated send delay
    delay_cnt = 0; //
    int mean_delay = 0; // mean_delay = delay_acc/delay_cnt (arithmetic(al) mean)

    // TCP sepconn vars
    struct sockaddr_in my_addr, cl_addr, localaddr, rmaddr;
    socklen_t prio_opt=1, laddrlen, rmaddrlen;
    int prio_s=-1, fd_tmp=-1;

    char ipstr[INET6_ADDRSTRLEN];
    int chan_num = 0, chan_num_virt = 0;
    int i, j, fd0;
    int break_out = 0;

    if( !(buf = lfd_alloc(VTUN_FRAME_SIZE+VTUN_FRAME_OVERHEAD)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker");
        return 0;
    }
    char *save_buf = buf;
    if( !(out_buf = lfd_alloc(VTUN_FRAME_SIZE+VTUN_FRAME_OVERHEAD)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate out buffer for the linker");
        return 0;
    }
    char *save_out_buf = out_buf;
    memset(time_lag_info_arr, 0, sizeof(struct time_lag_info) * MAX_TCP_LOGICAL_CHANNELS);
    memset(last_last_written_seq, 0, sizeof(uint32_t) * MAX_TCP_LOGICAL_CHANNELS);
    memset((void *)&statb, 0, sizeof(statb));
    memset(last_sent_packet_num, 0, sizeof(struct last_sent_packet) * MAX_TCP_LOGICAL_CHANNELS);
    my_max_speed_chan = 0;
    dirty_seq_num = 0;
    for (int i = 0; i < MAX_TCP_LOGICAL_CHANNELS; i++) {
        last_sent_packet_num[i].seq_num = SEQ_START_VAL;
    }
    maxfd = (service_channel > info.tun_device ? service_channel : info.tun_device);

    linker_term = 0;
    srand((unsigned int) time(NULL ));

    if (setsockopt(service_channel, SOL_SOCKET, SO_RCVTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
        vtun_syslog(LOG_ERR, "setsockopt failed");
        linker_term = TERM_NONFATAL;
    }
    if (setsockopt(service_channel, SOL_SOCKET, SO_SNDTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
        vtun_syslog(LOG_ERR, "setsockopt failed");
        linker_term = TERM_NONFATAL;
    }
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].rtt_phys_avg = 1;
    sem_post(&(shm_conn_info->stats_sem));    
#ifdef CLIENTONLY
    info.srv = 0;
#endif
    if(info.srv) {
        /** Server accepted all logical channel here and get and send pid */
        // now read one single byte
        vtun_syslog(LOG_INFO,"Waiting for client to request channels...");
		read_n(service_channel, buf, sizeof(uint16_t)+sizeof(uint16_t));
        info.channel_amount = ntohs(*((uint16_t *) buf)); // include info channel
        info.channel_amount = 2; // WARNING! TODO! HARDCODED 2 hardcoded chan_amt
        if (info.channel_amount > MAX_TCP_LOGICAL_CHANNELS) {
            vtun_syslog(LOG_ERR, "Client ask for %i channels. Exit ", info.channel_amount);
            info.channel_amount = MAX_TCP_LOGICAL_CHANNELS;
            linker_term = TERM_NONFATAL;
        }
        if(info.channel_amount < 1) {
            vtun_syslog(LOG_ERR, "Client ask for %i channels. Exit ", info.channel_amount);
            info.channel_amount = 1;
            linker_term = TERM_NONFATAL;
        }
        info.channel = calloc(info.channel_amount, sizeof(*(info.channel)));
        if (info.channel == NULL) {
            vtun_syslog(LOG_ERR, "Cannot allocate memory for info.channel, process - %i, pid - %i",info.process_num, info.pid);
            return 0;
        }
        chan_info = (struct channel_info *) calloc(info.channel_amount, sizeof(struct channel_info));
        if (chan_info == NULL ) {
            vtun_syslog(LOG_ERR, "Can't allocate array for struct chan_info for the linker");
            return 0;
        }
		sem_wait(&(shm_conn_info->stats_sem));
        info.channel[0].descriptor = service_channel; // load service channel
		shm_conn_info->stats[info.process_num].pid_remote = ntohs(*((uint16_t *) (buf + sizeof(uint16_t))));
		time_lag_local.pid_remote = shm_conn_info->stats[info.process_num].pid_remote;
		time_lag_local.pid = shm_conn_info->stats[info.process_num].pid;
    	*((uint16_t *) buf) = htons(shm_conn_info->stats[info.process_num].pid);
		sem_post(&(shm_conn_info->stats_sem));
		write_n(service_channel, buf, sizeof(uint16_t));
#ifdef DEBUGG
 		vtun_syslog(LOG_ERR,"Remote pid - %d, local pid - %d", time_lag_local.pid_remote, time_lag_local.pid);
#endif
        vtun_syslog(LOG_INFO,"Will create %d channels", info.channel_amount);
        uint16_t port_tmp = lfd_host->start_port;
        if (port_tmp != 0 )
            vtun_syslog(LOG_INFO,"port range is %"PRIu16" - %"PRIu16"", lfd_host->start_port, lfd_host->end_port);
        for (int i = 1; i < info.channel_amount; i++) {
            if ((info.channel[i].descriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                vtun_syslog(LOG_ERR, "Can't create Channels socket");
                return -1;
            }

            // Get buffer size
            socklen_t optlen = sizeof(sendbuff);
            if (getsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen) == -1) {
                vtun_syslog(LOG_ERR, "Error getsockopt one");
            } else {
                vtun_syslog(LOG_INFO, "send buffer size = %d\n", sendbuff);
            }

            sendbuff = RCVBUF_SIZE;
            // WARNING! This should be on sysadmin's duty to optimize!
            if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &sendbuff, sizeof(int)) == -1) {
                vtun_syslog(LOG_ERR, "WARNING! Can not set rmem (SO_RCVBUF) size. Performance will be poor.");
            }

//            prio_opt = 1;
//            setsockopt(prio_s, SOL_SOCKET, SO_REUSEADDR, &prio_opt, sizeof(prio_opt));
            for (; ; ++port_tmp <= lfd_host->end_port) {
                // try to bind to portnum my_num+smth:
                memset(&my_addr, 0, sizeof(my_addr));
                my_addr.sin_addr.s_addr = INADDR_ANY;
                my_addr.sin_port = htons(port_tmp);
                memset(&rmaddr, 0, sizeof(rmaddr));
                my_addr.sin_family = AF_INET;
                if (bind(info.channel[i].descriptor, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) {
                    if ((errno == EADDRINUSE) & (port_tmp < lfd_host->end_port)) {
                        vtun_syslog(LOG_ERR, "Can't bind port %"PRIu16", try next", port_tmp);
                    } else if ((errno == EADDRINUSE) & (port_tmp == lfd_host->end_port)) {
                        vtun_syslog(LOG_ERR, "Can't found free port in range %"PRIu16"-%"PRIu16"", lfd_host->start_port, lfd_host->end_port);
                        return -1;
                    } else {
                        vtun_syslog(LOG_ERR, "Can't bind to the Channels socket reason: %s (%d)", strerror(errno), errno);
                        return -1;
                    }
                } else {
                    break;
                }
            }
            // now get my port number
            laddrlen = sizeof(localaddr);
            if (getsockname(info.channel[i].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                vtun_syslog(LOG_ERR, "My port socket getsockname error; retry %s(%d)", strerror(errno), errno);
                close(prio_s);
                return 0;
            }

            info.channel[i].lport = ntohs(localaddr.sin_port);
        }
        for (int i = 1; i < info.channel_amount; i++) {
            uint16_t hton_ret = htons(info.channel[i].lport);
            memcpy(buf + sizeof(uint16_t) * (i - 1), &hton_ret, sizeof(uint16_t));
            vtun_syslog(LOG_INFO, "Send port to client %u", info.channel[i].lport);
        }
        write_n(service_channel, buf, sizeof(uint16_t) * (info.channel_amount - 1));


        *((uint32_t *) buf) = htonl(0); // already in htons format...
        *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_PRIO_PORT_NOTIFY);
        if (proto_write(service_channel, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
            vtun_syslog(LOG_ERR, "Could not send FRAME_PRIO_PORT_NOTIFY pkt; exit %s(%d)", strerror(errno), errno);
            close(prio_s);
            return 0;
        }

        // now listen to socket, wait for connection

        vtun_syslog(LOG_INFO,"Entering loop to create %d channels", info.channel_amount - 1);
        // TODO: how many TCP CONN AMOUNT allowed for server??
        for (i = 1; (i < info.channel_amount) && (i < MAX_TCP_LOGICAL_CHANNELS); i++) {
#ifdef DEBUGG
            vtun_syslog(LOG_INFO,"Chan %d", i);
#endif
            prio_opt = sizeof(cl_addr);
            struct timeval accept_time;
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(info.channel[i].descriptor, &rfds);

            accept_time.tv_sec = 5;
            accept_time.tv_usec = 0;

            if (select(info.channel[i].descriptor + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &accept_time) == 1) {
                struct sockaddr_in cli_addr;
                socklen_t slen = sizeof(cli_addr);
                int ret_len = recvfrom(info.channel[i].descriptor, buf, sizeof(uint16_t), 0, (struct sockaddr*) &cli_addr, &slen);
                if (ret_len == -1) {
                    vtun_syslog(LOG_ERR, "Recvfrom err on chan %i %s(%d)", i, strerror(errno), errno);
                    break_out = 1;
                    break;
                }
                connect(info.channel[i].descriptor, &cli_addr, sizeof(cli_addr));
                info.channel[i].rport = ntohs(cli_addr.sin_port);
            } else {
                vtun_syslog(LOG_ERR, "Accept timeout on chan %i", i);
                break_out = 1;
                break;
            }
            alarm(0);
        }

        if(break_out) {
            close(prio_s);
            for(; i>=0; i--) {
                close(info.channel[i].descriptor);
            }
            linker_term = TERM_NONFATAL;
            alarm(0);
        }

        memset(&rmaddr, 0, sizeof(rmaddr));
        memset(&localaddr, 0, sizeof(localaddr));
        rmaddrlen = sizeof(rmaddr);
        laddrlen = sizeof(localaddr);
        if (getpeername(info.channel[0].descriptor, (struct sockaddr *) (&rmaddr), &rmaddrlen) < 0) {
            vtun_syslog(LOG_ERR, "Service channel socket getsockname error; retry %s(%d)", strerror(errno), errno);
            linker_term = TERM_NONFATAL;
        }
        if (getsockname(info.channel[0].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
            vtun_syslog(LOG_ERR, "Service channel socket getsockname error; retry %s(%d)", strerror(errno), errno);
            linker_term = TERM_NONFATAL;
         }
        info.channel[0].rport = ntohs(rmaddr.sin_port);
        info.channel[0].lport = ntohs(localaddr.sin_port);

        gettimeofday(&info.current_time, NULL );
        maxfd = info.tun_device;
        for (int i = 0; i < info.channel_amount; i++) {
            vtun_syslog(LOG_INFO, "Server descriptor - %i logical channel - %i lport - %i rport - %i", info.channel[i].descriptor, i,
                    info.channel[i].lport, info.channel[i].rport);
            if (maxfd < info.channel[i].descriptor) {
                maxfd = info.channel[i].descriptor;
            }
            memcpy(&info.channel[i].get_tcp_info_time_old, &info.current_time, sizeof(info.channel[i].get_tcp_info_time_old));
            memcpy(&info.channel[i].send_q_time, &info.current_time, sizeof(info.channel[i].send_q_time));
        }
    } else {
        /** Send to server information about channel amount and get and send pid */
        info.channel_amount = 2; // WARNING TODO chan_amt hardcoded here
    	*((uint16_t *) buf) = htons(info.channel_amount);
    	sem_wait(&(shm_conn_info->stats_sem));
    	*((uint16_t *) (buf + sizeof(uint16_t))) = htons(shm_conn_info->stats[info.process_num].pid);
    	time_lag_local.pid = shm_conn_info->stats[info.process_num].pid;
    	sem_post(&(shm_conn_info->stats_sem));
        write_n(service_channel, buf, sizeof(uint16_t) + sizeof(uint16_t));

 		read_n(service_channel, buf, sizeof(uint16_t));
 		sem_wait(&(shm_conn_info->stats_sem));
 		shm_conn_info->stats[info.process_num].pid_remote = ntohs(*((uint16_t *) buf));
 		time_lag_local.pid_remote = shm_conn_info->stats[info.process_num].pid_remote;
 		sem_post(&(shm_conn_info->stats_sem));
 		vtun_syslog(LOG_ERR,"Remote pid - %d, local pid - %d", time_lag_local.pid_remote, time_lag_local.pid);

 		len = read_n(service_channel, buf, sizeof(uint16_t) * (info.channel_amount - 1));
        vtun_syslog(LOG_INFO, "remote ports len %d", len);

        for (int i = 1; i < info.channel_amount; i++) {
            uint16_t rport_h;
            memcpy(&rport_h, buf + (i - 1) * sizeof(uint16_t), sizeof(uint16_t));
            info.channel[i].rport = ntohs(rport_h);
            vtun_syslog(LOG_INFO, "remote port recived %u", info.channel[i].rport);
        }
 		info.channel_amount = 1; // now we'll accumulate here established logical channels
    }

    // we start in a normal mode...
    if(channel_mode == MODE_NORMAL) {
        shm_conn_info->normal_senders++;
        vtun_syslog(LOG_INFO, "normal sender added: now %d", shm_conn_info->normal_senders);
    }

    sem_wait(&(shm_conn_info->AG_flags_sem));
    *((uint32_t *) buf) = htonl(shm_conn_info->session_hash_this);
    sem_post(&(shm_conn_info->AG_flags_sem));
    *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_JUST_STARTED);
    if (proto_write(service_channel, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
        vtun_syslog(LOG_ERR, "Could not send init pkt; exit");
        linker_term = TERM_NONFATAL;
    }
#ifdef JSON
    vtun_syslog(LOG_INFO,"{\"name\":\"%s\",\"start\":1, \"build\":\"%s\"}", lfd_host->host, BUILD_DATE);
#endif

    shm_conn_info->stats[info.process_num].weight = lfd_host->START_WEIGHT;
    
    gettimeofday(&info.current_time, NULL);
    last_action = info.current_time.tv_sec;
    last_net_read = info.current_time.tv_sec;
    shm_conn_info->lock_time = info.current_time.tv_sec;
    net_model_start = info.current_time;
    
//    alarm(lfd_host->MAX_IDLE_TIMEOUT);
    struct timeval get_info_time, get_info_time_last, tv_tmp_tmp_tmp;
    get_info_time.tv_sec = 0;
    get_info_time.tv_usec = 10000;
    get_info_time_last.tv_sec = 0;
    get_info_time_last.tv_usec = 0;
    timer_resolution.tv_sec = 1;
    timer_resolution.tv_usec = 0;
    struct timeval  json_timer;
    gettimeofday(&json_timer, NULL);
    info.check_shm = 0; // zeroing check_shm

    struct timer_obj *recv_n_loss_send_timer = create_timer();
    struct timeval recv_n_loss_time = { 0, 100000 }; // this time is crucial to detect send_q dops in case of long hold
    set_timer(recv_n_loss_send_timer, &recv_n_loss_time);

    struct timer_obj *send_q_limit_change_timer = create_timer();
    struct timeval send_q_limit_change_time = { 0, 500000 };
    set_timer(send_q_limit_change_timer, &send_q_limit_change_time);

    struct timer_obj *s_q_lim_drop_timer = create_timer();
    fast_update_timer(s_q_lim_drop_timer, &info.current_time);

    struct timer_obj *packet_speed_timer = create_timer();
    struct timeval packet_speed_timer_time = { 0, 500000 };
    set_timer(packet_speed_timer, &packet_speed_timer_time);

    struct timer_obj *head_channel_switch_timer = create_timer();
    struct timeval head_channel_switch_timer_time = { 0, 0 };
    set_timer(head_channel_switch_timer, &head_channel_switch_timer_time);

    struct timeval t_tv;
    struct timeval loss_time, loss_immune, loss_tv = { 0, 0 }, real_loss_time = {0,0};
    gettimeofday(&loss_time, NULL);
    gettimeofday(&loss_immune, NULL);
    
    sem_wait(&(shm_conn_info->AG_flags_sem));
    last_channels_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
    drop_packet_flag = 0;
    /*
    if (info.process_num == 0) {
        info.head_channel = 1;
        info.C = C_HI;
    } else {
        info.head_channel = 0;
        info.C = C_LOW/2;
    }*/
    info.C = C_LOW;
    //info.C = 0.9; // VERY FAST!
    info.max_send_q = 0;

    gettimeofday(&info.cycle_last, NULL); // for info.rsr smooth avg
    int ag_flag_local = R_MODE;
    
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].ag_flag_local = ag_flag_local;
    sem_post(&(shm_conn_info->stats_sem));
    
    info.rsr = RSR_TOP;
    info.send_q_limit = RSR_TOP;
    info.send_q_limit_cubic_max = RSR_TOP;
    int agag = 0; // AG_MODE aggressiveness value 0 to 256
    int ag_flag = R_MODE;
    int ag_flag_local_prev = R_MODE;
    struct timeval agon_time; // time at which ag_flag_local bacame 1
    gettimeofday(&agon_time, NULL);
    
    info.max_reorder_latency = MAX_REORDER_LATENCY; // is rtt * 2 actually

    for (int i = 0; i < MAX_TCP_LOGICAL_CHANNELS; i++) {
        info.rtt2_lsn[i] = 0;
        info.rtt2_send_q[i] = 0;
//        info.channel[i].ACS2 = 0;
//        info.channel[i].old_packet_seq_num_acked = 0;
//        info.channel[i].local_seq_num_beforeloss = 0;
        gettimeofday(&info.rtt2_tv[i], NULL);
    }
    info.rtt2 = 0;
    int was_hold_mode = 0; // TODO: remove, testing only!
    int send_q_eff_mean = 0;
    int channel_dead = 0;
    int exact_rtt = 0;
    int t; // time for W
    //int head_rel = 0;
    struct timeval drop_time = info.current_time;
struct timeval cpulag;
    gettimeofday(&cpulag, NULL);
    int super = 0;
    uint32_t my_max_send_q_prev=0;
    int buf_len_sent[MAX_TCP_PHYSICAL_CHANNELS];
    for(i=0; i<MAX_TCP_PHYSICAL_CHANNELS;i++) {
        buf_len_sent[i]=0;
    }

    struct _smalldata smalldata;
    smalldata.rtt = malloc(sizeof(double) * (MAX_SD_W / SD_PARITY));
    smalldata.ACS = malloc(sizeof(double) * (MAX_SD_W / SD_PARITY));
    smalldata.w = malloc(sizeof(double) * (MAX_SD_W / SD_PARITY));
    smalldata.send_q = malloc(sizeof(double) * (MAX_SD_W / SD_PARITY));
    smalldata.ts = malloc(sizeof(struct timeval) * (MAX_SD_W / SD_PARITY));

    for(int i = 0; i < (MAX_SD_W / SD_PARITY); i++) {
        smalldata.send_q[i] = (double) (i * SD_PARITY * 1000);
        smalldata.rtt[i] = 0; // TODO: memset?
        smalldata.ACS[i] = 0; // TODO: memset?
        smalldata.w[i] = 0; // TODO: memset?
        smalldata.ts[i] = info.current_time;
    }
    int last_smalldata_ACS = 0;
    t = (int) t_from_W( SENQ_Q_LIMIT_THRESHOLD_MIN + 2000, info.send_q_limit_cubic_max, info.B, info.C);
    struct timeval new_lag;
    ms2tv(&new_lag, t * CUBIC_T_DIV); // multiply to compensate
    timersub(&info.current_time, &new_lag, &loss_time);
    sem_wait(&(shm_conn_info->stats_sem));
    set_W_unsync(t);
    sem_post(&(shm_conn_info->stats_sem));
    struct timeval peso_lrl_ts = info.current_time;
    int32_t peso_old_last_recv_lsn = 10;
    int ELD_send_q_max = 0;
    int need_send_FCI = 0;
    info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC;
    int PCS = 0;
/**
 *
 *
    _________                         .__                        
   /   _____/__ ________   ___________|  |   ____   ____ ______  
   \_____  \|  |  \____ \_/ __ \_  __ \  |  /  _ \ /  _ \\____ \ 
   /        \  |  /  |_> >  ___/|  | \/  |_(  <_> |  <_> )  |_> >
  /_______  /____/|   __/ \___  >__|  |____/\____/ \____/|   __/ 
          \/      |__|        \/                         |__|                                                            
 *
 *
 * Main program loop
 */
    while( !linker_term ) {
        errno = 0;
        super++;
        
        // EXACT_RTT >>>
        // Section to set exact_rtt
        timersub(&ping_req_tv[1], &info.rtt2_tv[1], &tv_tmp);
        if( (send_q_eff_mean > SEND_Q_EFF_WORK) || timercmp(&tv_tmp, &((struct timeval) {lfd_host->PING_INTERVAL, 0}), <=)) { // TODO: threshold depends on phys RTT and speed; investigate that!
            if(info.rtt2 == 0) {
                vtun_syslog(LOG_ERR, "WARNING! info.rtt2 == 0!");
                info.rtt2 = 1;
            }
            exact_rtt = info.rtt2; 
        } else {
            // TODO: make sure that we sent PING after high load __before__ this happens!
            if(info.rtt == 0) {
                vtun_syslog(LOG_ERR, "WARNING! info.rtt == 0!");
                info.rtt = 1;
            }
            exact_rtt = info.rtt;
        }
        info.exact_rtt = exact_rtt;
        // <<< END EXACT_RTT
        

        // CPU LAG >>>
        gettimeofday(&cpulag, NULL);
        timersub(&cpulag, &old_time, &tv_tmp_tmp_tmp);
        if(tv_tmp_tmp_tmp.tv_usec > SUPERLOOP_MAX_LAG_USEC) {
            vtun_syslog(LOG_ERR,"WARNING! CPU deficiency detected! Cycle lag: %ld.%06ld", tv_tmp_tmp_tmp.tv_sec, tv_tmp_tmp_tmp.tv_usec);
        }
        // <<< END CPU_LAG


        // SEND_Q_EFF CALC >>>
        uint32_t my_max_send_q = info.channel[my_max_send_q_chan_num].send_q;
        int64_t bytes_pass = 0;

        timersub(&info.current_time, &info.channel[my_max_send_q_chan_num].send_q_time, &t_tv);
        //bytes_pass = time_sub_tmp.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].ACK_speed_avg
        //        + (time_sub_tmp.tv_usec * info.channel[my_max_send_q_chan_num].ACK_speed_avg) / 1000;
        int64_t upload_eff = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        if(upload_eff < 10) upload_eff = 100000; // 1000kpkts default start speed
        
        bytes_pass = (((int64_t)t_tv.tv_sec * upload_eff
                + (((int64_t)t_tv.tv_usec/10) * upload_eff) / 100000)*3)/10;

        uint32_t speed_log = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        sem_wait(&shm_conn_info->common_sem);
        info.eff_len = shm_conn_info->eff_len.sum;
        sem_post(&shm_conn_info->common_sem);
        send_q_eff = //my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000;
            (my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * info.eff_len) > bytes_pass ?
                    my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * info.eff_len - bytes_pass : 0;
#ifdef DEBUGG
        if(drop_packet_flag) {
        vtun_syslog(LOG_INFO,"Calc send_q_eff: %d + %d * %d - %d", my_max_send_q, info.channel[my_max_send_q_chan_num].bytes_put, info.eff_len, bytes_pass);
        } 
#endif
        // <<< END SEND_Q_EFF CALC
        

        // AVERAGE (MEAN) SEND_Q_EFF calculation --->>>
        timersub(&info.current_time, &info.tv_sqe_mean_added, &tv_tmp_tmp_tmp);
        if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, SELECT_SLEEP_USEC }), >=)) {
            send_q_eff_mean += (send_q_eff - send_q_eff_mean) / 30; // TODO: choose aggressiveness for smoothed-sqe (50?)
            info.tv_sqe_mean_added = info.current_time;
            int s_q_idx = send_q_eff / info.eff_len / SD_PARITY;
            if(s_q_idx < (MAX_SD_W / SD_PARITY)) {
                // TODO: write averaged data ? more points -> more avg!
                if(last_smalldata_ACS != info.packet_recv_upload_avg) {
                    smalldata.ACS[s_q_idx] = info.packet_recv_upload_avg;
                    smalldata.rtt[s_q_idx] = info.rtt2;
                    smalldata.ts[s_q_idx] = info.current_time;
                    last_smalldata_ACS = info.packet_recv_upload_avg;
                }
            } else {
                vtun_syslog(LOG_ERR, "WARNING! send_q too big!");
            }
            
            // push up forced_rtt
                sem_wait(write_buf_sem);
                if (((shm_conn_info->head_lossing) || (shm_conn_info->dropping)) && info.srv) { // server only
                    if (shm_conn_info->forced_rtt_start_grow.tv_sec == 0) {
                        shm_conn_info->forced_rtt_start_grow = info.current_time;
                    }
                    struct timeval tmp_tv;
                    timersub(&info.current_time, &shm_conn_info->forced_rtt_start_grow, &tmp_tv);
                    int time = tv2ms(&tmp_tv) / LIN_RTT_SLOWDOWN; // 15x slower time
                    // TODO: overflow here! ^^^
                    time = time > LIN_FORCE_RTT_GROW ? LIN_FORCE_RTT_GROW : time; // max 500ms
                    //vtun_syslog(LOG_INFO, "New forced rtt: %d", time);
                    if(shm_conn_info->forced_rtt != time) {
                        shm_conn_info->forced_rtt = time;
                        //vtun_syslog(LOG_INFO, "Apply & send forced rtt: %d", time);
                        need_send_FCI = 1; // force immediate FCI send!
                    }
                } else {
                    shm_conn_info->forced_rtt_start_grow.tv_sec = 0;
                    shm_conn_info->forced_rtt_start_grow.tv_usec = 0;
                    shm_conn_info->forced_rtt = 0;
                }
                sem_post(write_buf_sem);
        

        }
        // << END AVERAGE (MEAN) SEND_Q_EFF calculation

        
        /* Temporarily disabled this due to massive loss :-\
        // EXTERNAL LOSS DETECT >>> 
        if(send_q_eff > info.send_q_limit_threshold && (send_q_eff < ELD_send_q_max) && !percent_delta_equal(send_q_eff, ELD_send_q_max, 20)) {
            vtun_syslog(LOG_INFO, "WARNING: External loss detected! send_q from %d to %d", ELD_send_q_max, send_q_eff);
            ELD_send_q_max = send_q_eff;
        } else if (send_q_eff > ELD_send_q_max) {
            ELD_send_q_max = send_q_eff;
        }
        // <<< END EXTERNAL LOSS DETECT
        */


        // PACKET TRAIN AKA BDP >>>
        if ((send_q_eff > 10000) && (send_q_eff_mean < 10000) && 0) { // WARNING: switched off! <-- remove this code
            // now check all other chans
            // shm_conn_info->stats[info.process_num].sqe_mean = send_q_eff_mean;
            // shm_conn_info->stats[info.process_num].max_send_q = send_q_eff;
            int need_send = 1;
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            sem_post(&(shm_conn_info->AG_flags_sem));

            sem_wait(&(shm_conn_info->stats_sem));

            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                    if( !( (shm_conn_info->stats[i].sqe_mean < 10000) && (shm_conn_info->stats[i].max_send_q > 10000) )) {
                        need_send = 0;
                    }
                }
            }
            sem_post(&(shm_conn_info->stats_sem));
            if(need_send) {
                sem_wait(&(shm_conn_info->common_sem));
                struct timeval time_tmp;
                timersub(&info.current_time, &shm_conn_info->last_flood_sent, &time_tmp);
                struct timeval time_tmp2 = { 20, 0 };
                if (timercmp(&time_tmp, &time_tmp2, >)) {
                    vtun_syslog(LOG_INFO,"Sending train sqe %d > 10000 sqe_mean %d < 10000", send_q_eff, send_q_eff_mean);
                    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                        if (chan_mask & (1 << i)) {
                            shm_conn_info->flood_flag[i] = 1;
                        }
                    }
                    shm_conn_info->last_flood_sent.tv_sec = info.current_time.tv_sec;
                    shm_conn_info->last_flood_sent.tv_usec = info.current_time.tv_usec;
                }
                sem_post(&(shm_conn_info->common_sem));
            }
        }
        // <<< END PACKET TRAIN AKA BDP


#ifdef SEND_Q_LOG
        if(fast_check_timer(jsSQ_timer, &info.current_time)) {
           add_json_arr(jsSQ_buf, &jsSQ_cur, "%d", send_q_eff);
           fast_update_timer(jsSQ_timer, &info.current_time);
        }
#endif


        // calculate on-line RTT: >>>
        if(ping_rcvd == 0) {
            timersub(&info.current_time, &ping_req_tv[0], &tv_tmp);
            int cur_rtt = tv2ms(&tv_tmp);
            sem_wait(&(shm_conn_info->stats_sem));
            //for(int i=0; i<info.channel_amount; i++) { // only chan 0 !
            if(cur_rtt > shm_conn_info->stats[info.process_num].rtt_phys_avg) {
                shm_conn_info->stats[info.process_num].rtt_phys_avg = cur_rtt;
                info.rtt = cur_rtt;
            }
            //}
            // TODO: in case of DDS initiate second ping immediately!!??
            sem_post(&(shm_conn_info->stats_sem));
        }
        // <<< END calculate on-line RTT

        
        // DEAD DETECT and COPY HEAD from SHM >>>
        max_chan=-1;
        sem_wait(&(shm_conn_info->AG_flags_sem));
        uint32_t chan_mask = shm_conn_info->channels_mask;
        sem_post(&(shm_conn_info->AG_flags_sem));
        
        sem_wait(&(shm_conn_info->stats_sem));
        if(info.dropping) { // will ONLY drop if PESO in play. Never as of now...
            info.dropping = 0;
            shm_conn_info->drop_time = info.current_time;
            shm_conn_info->dropping = 1;
        }

        if(shm_conn_info->idle) {
            // use rtt
            if(shm_conn_info->stats[info.process_num].exact_rtt > DEAD_RTT) {
                channel_dead = 1;
            } else {
                channel_dead = 0;
            }
        } else {
            // TODO: what if info.rsr is ~ 0 ??
            channel_dead = (percent_delta_equal(send_q_eff, info.rsr, DEAD_RSR_USG) && ((shm_conn_info->stats[info.process_num].max_ACS2 == 0) || (shm_conn_info->stats[info.process_num].max_PCS2 == 0)));
        }

        if(channel_dead == 1 && channel_dead != shm_conn_info->stats[info.process_num].channel_dead) {
            vtun_syslog(LOG_INFO, "Warning! Channel %s suddenly died! (head? %d) (idle? %d) (sqe %d) (rsr %d) (ACS %d) (PCS %d)", lfd_host->host, info.head_channel, shm_conn_info->idle, send_q_eff, info.rsr, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2);
            shm_conn_info->last_switch_time.tv_sec = 0;
            if(info.head_channel) {
                vtun_syslog(LOG_INFO, "Warning! %s is head! Re-detecting new HEAD!", lfd_host->host);
                redetect_head_unsynced(chan_mask, info.process_num);
            }
        }
        shm_conn_info->stats[info.process_num].channel_dead = channel_dead;
        shm_conn_info->stats[info.process_num].sqe_mean = send_q_eff_mean;
        shm_conn_info->stats[info.process_num].max_send_q = send_q_eff;
        shm_conn_info->stats[info.process_num].exact_rtt = exact_rtt;
        max_chan = shm_conn_info->max_chan;
#ifdef FIX_HEAD_CHAN
        if(info.process_num == FIX_HEAD_CHAN)  info.head_channel = 1;
        else info.head_channel = 0;
#else
        // head switch block
        if(max_chan == info.process_num) {
            if(info.head_channel != 1) {
                skip++;
                vtun_syslog(LOG_INFO, "Switching head to 1 (ON)");
            }
            info.head_channel = 1;
        } else {
            if(info.head_channel != 0) {
                skip++;
                vtun_syslog(LOG_INFO, "Switching head to 0 (OFF)");
            }
            info.head_channel = 0;
        }
#endif
        // <<< DEAD DETECT and COPY HEAD from SHM
        


        // RSR section here >>>
        int32_t rtt_shift;
        if (info.head_channel) {
            //info.rsr = RSR_TOP;
            info.rsr = info.send_q_limit_cubic;
            info.send_q_limit_threshold = info.rsr / SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER;
        } else {
            if (shm_conn_info->stats[max_chan].ACK_speed < 1000) {
                shm_conn_info->stats[max_chan].ACK_speed = 1000;
            }
            
            if (shm_conn_info->stats[info.process_num].ACK_speed < 1000) {
                shm_conn_info->stats[info.process_num].ACK_speed = 1000;
            }
            
            
            //info.send_q_limit = (RSR_TOP * (shm_conn_info->stats[info.process_num].ACK_speed / 1000))
            int rsr_top = shm_conn_info->stats[max_chan].W_cubic;
            info.send_q_limit_threshold = rsr_top / SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER;
            // WARNING: TODO: speeds over 10MB/s will still cause overflow here!
            if(rsr_top > 500000) {
                info.send_q_limit = ( (rsr_top / 1000) * (shm_conn_info->stats[info.process_num].ACK_speed / 1000))
                                             / (shm_conn_info->stats[        max_chan].ACK_speed / 1000) * 1000;
            } else {
                info.send_q_limit = (rsr_top * (shm_conn_info->stats[info.process_num].ACK_speed / 1000))
                                             / (shm_conn_info->stats[        max_chan].ACK_speed / 1000);
            }
            
            
            rtt_shift = (shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[max_chan].exact_rtt) // dt in ms..
                                        * (shm_conn_info->stats[max_chan].ACK_speed / 1000); // convert spd from mp/s to mp/ms
            
            
            if(rtt_shift < info.send_q_limit) {
                info.send_q_limit -= rtt_shift;
            } else {
                info.send_q_limit = 0;
            }
            
            if (info.send_q_limit < SEND_Q_LIMIT_MINIMAL) {
                info.send_q_limit = SEND_Q_LIMIT_MINIMAL-1;
            }
            if (info.send_q_limit > RSR_TOP) {
                info.send_q_limit = RSR_TOP;
            }

            if(info.send_q_limit < info.send_q_limit_threshold) {
                info.send_q_limit = info.send_q_limit_threshold - 1;
            }
               
            
            timersub(&(info.current_time), &info.cycle_last, &t_tv);
            int32_t ms_passed = tv2ms(&t_tv);
            if(ms_passed > RSR_SMOOTH_GRAN) {
                if(ms_passed > RSR_SMOOTH_FULL) {
                    ms_passed = RSR_SMOOTH_FULL;
                }
                int rsr_shift;
                if( ((info.send_q_limit - info.rsr) >= (INT32_MAX/ms_passed-100)) || ( (info.send_q_limit - info.rsr) <= (-INT32_MAX/ms_passed+100) )) {
                    rsr_shift = ((info.send_q_limit - info.rsr) > 0 ? info.send_q_limit : -info.send_q_limit );
                } else {
                    rsr_shift = (info.send_q_limit - info.rsr) * ms_passed / RSR_SMOOTH_FULL;
                }
                info.rsr += rsr_shift;
                //vtun_syslog(LOG_INFO, "pnum %d, rsr += send_q_limit %d - info.rsr %d * ms_passed %d / 3000 ( = %d )",
                //           info.process_num, info.send_q_limit, info.rsr, ms_passed, rsr_shift);
                info.cycle_last = info.current_time;
            }
            
            //vtun_syslog(LOG_INFO, "rsr %"PRIu32" rtt_shift %"PRId32" info.send_q_limit %"PRIu32" rtt 0 - %d rtt my - %d speed 0 - %"PRId32" my - %"PRId32"", rsr, rtt_shift, info.send_q_limit, shm_conn_info->stats[0].rtt_phys_avg, shm_conn_info->stats[info.process_num].rtt_phys_avg, shm_conn_info->stats[0].ACK_speed, shm_conn_info->stats[info.process_num].ACK_speed);
        }
        // uint32_t tflush_counter_recv = shm_conn_info->tflush_counter_recv; // yes? it is transferred??
        
        if(!info.head_channel) {
            timersub(&(info.current_time), &loss_time, &t_tv);
            int t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
            t = t / CUBIC_T_DIV;
            t = t > CUBIC_T_MAX ? CUBIC_T_MAX : t; // 400s limit
            set_W_unsync(t);
        }

        int32_t send_q_limit_cubic_apply = (int32_t)info.send_q_limit_cubic;
        if (send_q_limit_cubic_apply < SEND_Q_LIMIT_MINIMAL) {
            send_q_limit_cubic_apply = SEND_Q_LIMIT_MINIMAL-1;
        }

        // calc send_q_limit_threshold
        if(info.send_q_limit_threshold < SEND_Q_LIMIT_MINIMAL) {
            info.send_q_limit_threshold = SEND_Q_LIMIT_MINIMAL-1;
        }
        // <<< END RSR section here


        // AG DECISION >>>
        ag_flag_local = ((    (info.rsr <= info.send_q_limit_threshold)  
                           || (send_q_limit_cubic_apply <= info.send_q_limit_threshold) 
                           //|| (send_q_limit_cubic_apply < info.rsr) // better w/o this one?!? // may re-introduce due to PESO!
                           || ( channel_dead )
                           || ( !check_rtt_latency_drop() )
                           || ( !shm_conn_info->dropping && !shm_conn_info->head_lossing )
                           /*|| (shm_conn_info->stats[max_chan].sqe_mean < SEND_Q_AG_ALLOWED_THRESH)*/ // TODO: use mean_send_q
                           ) ? R_MODE : AG_MODE);
        // logging part
        if(info.rsr <= info.send_q_limit_threshold) ag_stat.RT = 1;
        if(send_q_limit_cubic_apply <= info.send_q_limit_threshold) ag_stat.WT = 1;
        if(channel_dead) ag_stat.D = 1;
        if(!check_rtt_latency_drop()) ag_stat.CL = 1;
        if(!shm_conn_info->dropping && !shm_conn_info->head_lossing) ag_stat.DL = 1;
        //ag_flag_local = R_MODE;
        // now see if we are actually good enough to kick in AG?
        // see our RTT diff from head_channel
        // TODO: use max_ACS thru all chans
        //if(shm_conn_info->stats[max_chan].exact_rtt > shm_conn_info->stats[info.process_num].exact_rtt) {
        //    rtt_shift = shm_conn_info->stats[max_chan].exact_rtt - shm_conn_info->stats[info.process_num].exact_rtt;
        //} else {
        //    rtt_shift = shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[max_chan].exact_rtt;
        //}
        // if ( (rtt_shift*(max_speed/1000)) > MAX_BYTE_DELIVERY_DIFF) ag_flag_local = R_MODE; // unneeded check due to check_rtt_latency_drop() above
        shm_conn_info->stats[info.process_num].ag_flag_local = ag_flag_local;
        
        if(ag_flag_local == AG_MODE) {
            // check our protup against all other chans
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                    if( (shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[i].exact_rtt)*1000 > ((int)info.max_latency_drop.tv_usec) ) {
                        vtun_syslog(LOG_ERR, "WARNING: PROTUP condition detected on our channel: %d - %d > %u", shm_conn_info->stats[info.process_num].rtt2, shm_conn_info->stats[i].rtt2, ((int)info.max_latency_drop.tv_usec));
                        if(info.head_channel) {
                            vtun_syslog(LOG_ERR, "         ^^^ HEAD channel!");
                            redetect_head_unsynced(chan_mask, info.process_num);
                            // TODO: immediate action required!
                        }
                    }
                }
            }
        }
        
        
        // now calculate AGAG
        uint32_t dirty_seq = 0;
        if(ag_flag_local == AG_MODE) {
            if(ag_flag_local_prev != ag_flag_local) {
                agon_time = info.current_time;
                ag_flag_local_prev = ag_flag_local;
            }
            // first calculate agag
            timersub(&info.current_time, &agon_time, &tv_tmp);
            agag = tv2ms(&tv_tmp) / 10;
            if(agag > 255) agag = 255; // 2555 milliseconds for full AG (~1% not AG)
            for(int i=0; i<info.channel_amount; i++) {
                dirty_seq += info.channel[i].local_seq_num;
            }
            if(agag < 127) {
                ag_flag = ((dirty_seq % (128 - agag)) == 0) ? AG_MODE : R_MODE;
            } else {
                ag_flag = ((dirty_seq % (agag - 125)) == 0) ? R_MODE : AG_MODE;
            }
            // and finally re-set ag_flag_local since send packet part will use it to choose R/AG
        } else {
            agag = 0;
            if(ag_flag == AG_MODE) {
                vtun_syslog(LOG_INFO, "Dropping AG on Channel %s (head? %d) (idle? %d) (sqe %d) (rsr %d) (ACS %d) (PCS %d)", lfd_host->host, info.head_channel, shm_conn_info->idle, send_q_eff, info.rsr, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2);
                vtun_syslog(LOG_INFO, "       (rsr=%d)<=(THR=%d) || (W=%d)<=(THR=%d) || DEAD=%d || !CLD=%d || dropping=%d", info.rsr ,info.send_q_limit_threshold, send_q_limit_cubic_apply ,info.send_q_limit_threshold, channel_dead, ( !check_rtt_latency_drop() ), ( !shm_conn_info->dropping && !shm_conn_info->head_lossing ) );
            
            }
            ag_flag = R_MODE;
            ag_flag_local_prev = ag_flag_local;
        }
        // <<< END AG DECISION


        // HOLD/DROP setup >>>
        int hold_mode_previous = hold_mode;
        if(ag_flag_local == AG_MODE) {
            if(info.head_channel) {
                hold_mode = 0; // no hold whatsoever;
                drop_packet_flag = 0;
                if (send_q_eff > info.rsr) {
                    if(check_drop_period_unsync()) { // Remember to have large txqueue!
                        if(!shm_conn_info->hold_mask) drop_packet_flag = 1; // ^^ drop exactly one packet
                    } else {
                        hold_mode = 1;
                    }
                    //vtun_syslog(LOG_INFO, "AG_MODE DROP!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d (  %d)", send_q_eff, info.rsr, send_q_limit_cubic_apply,info.send_q_limit_cubic );
                }
            } else {
                drop_packet_flag = 0;
                if ( (send_q_eff > info.rsr) || (send_q_eff > send_q_limit_cubic_apply)) {
                    //vtun_syslog(LOG_INFO, "hold_mode!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d", send_q_eff, rsr, send_q_limit_cubic_apply);
                    hold_mode = 1;
                } else {
                    hold_mode = 0;
                }
            }
        } else { // R_MODE.. no intermediate modes.. yet ;-)
            hold_mode = 0;
            if(info.head_channel) {
                if(send_q_eff > info.rsr) { // no cubic control on max speed chan!
                    //vtun_syslog(LOG_INFO, "R_MODE DROP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    if(check_drop_period_unsync()) { // Remember to have large txqueue!
                        drop_packet_flag = 1;
                    } else {
                        hold_mode = 1;
                    }
                } else {
                    //vtun_syslog(LOG_INFO, "R_MODE NOOP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    drop_packet_flag = 0;
                }
            } else {
                if((send_q_eff > send_q_limit_cubic_apply) || (send_q_eff > info.rsr)) {
                    //vtun_syslog(LOG_INFO, "R_MODE DROP!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    drop_packet_flag = 0;
                    hold_mode = 1;
                } else {
                    //vtun_syslog(LOG_INFO, "R_MODE NOOP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    drop_packet_flag = 0;
                }
            }
        }

        if(hold_mode || info.head_channel) {
            shm_conn_info->hold_mask &= ~(1 << info.process_num); // set bin mask to zero (send not allowed)
        } else {
            shm_conn_info->hold_mask |= (1 << info.process_num); // set bin mask to 1 (free send allowed)
        }
        // << END HOLD/DROP setup
        
        
        // fast convergence to underlying encap flow >>> 
        if(drop_packet_flag) { // => we are HEAD, => rsr = W_cubic => need to shift W_cubic to send_q_eff
            //int slope = get_slope(&smalldata);
            int slope = 1; // disable by now
            if(slope > -100000) { // TODO: need more fine-tuning!
                    drop_packet_flag = 0;
                    // calculate old t
                    timersub(&(info.current_time), &loss_time, &t_tv);
                    int old_t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
                    old_t = old_t / CUBIC_T_DIV;
                    old_t = old_t > CUBIC_T_MAX ? CUBIC_T_MAX : old_t; // 400s limit

                    t = (int) t_from_W( send_q_eff + 2000, info.send_q_limit_cubic_max, info.B, info.C);
                    struct timeval new_lag;
                    //vtun_syslog(LOG_INFO,"Converging W to encap flow: W+1=%d, Wmax=%d, old t=%d, new t=%d, slope=%d/100", send_q_eff + 2000, info.send_q_limit_cubic_max, old_t, t, slope); // this log is MESS!
                    ms2tv(&new_lag, t * CUBIC_T_DIV); // multiply to compensate
                    timersub(&info.current_time, &new_lag, &loss_time); // set new loss time back in time
                    // now, we rely only on head_dropping in detection of congestion/speed reached AND switching on AG
                    set_W_unsync(t);
            } else {
                vtun_syslog(LOG_INFO, "Refusing to converge W due to negative slope=%d/100 rsr=%d sq=%d", slope, info.rsr, send_q_eff);
                // This is where we do not rely on reaching congestion anymore; we can say 'speed reached' before lossing! (& switch AG on!)
            }
        }

        // Push down envelope
        if(info.head_channel && (send_q_eff < (int32_t)info.send_q_limit_cubic)) {
            //set_W_to(send_q_eff, 30, &loss_time);
            set_W_to(send_q_eff, 1, &loss_time); // 1 means immediately!
        }
        // <<< END fast convergence to underlying encap flow
        

#ifdef NOCONTROL
        hold_mode = 0;
        drop_packet_flag = 0;
#endif
        
        shm_conn_info->stats[info.process_num].hold = hold_mode;
        sem_post(&(shm_conn_info->stats_sem));
        //vtun_syslog(LOG_INFO, "debug0: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
        if(hold_mode == 1) was_hold_mode = 1; // for JSON ONLY!
        
        /*
        if (fast_check_timer(packet_speed_timer, &info.current_time)) { // TODO: Disabled?! Incorrect operation - see code at JSON 0.5s
            gettimeofday(&info.current_time, NULL );
            uint32_t tv, max_packets=0;
            tv = get_difference_timer(packet_speed_timer, &info.current_time)->tv_sec * 1000
                    + get_difference_timer(packet_speed_timer, &info.current_time)->tv_usec / 1000;
            if (tv != 0) {
                for (i = 1; i < info.channel_amount; i++) {
                    info.channel[i].packet_download = ((info.channel[i].down_packets * 100000) / tv)*10;
                    //if (info.channel[i].down_packets > 0)
                        //vtun_syslog(LOG_INFO, "chan %d down packet speed %"PRIu32" packets %"PRIu32" time %"PRIu32" timer %"PRIu32"", i, info.channel[i].packet_download, info.channel[i].down_packets, tv, packet_speed_timer_time.tv_usec/1000);
                    if (max_packets<info.channel[i].down_packets) max_packets=info.channel[i].down_packets;
                    info.channel[i].down_packets = 0;
                }
                
                if (packet_speed_timer_time.tv_usec < 800000) packet_speed_timer_time.tv_usec += 20000;
                if (max_packets<50) {
                    set_timer(packet_speed_timer, &packet_speed_timer_time);
                } else if (max_packets>300) {
                    if (packet_speed_timer_time.tv_usec > 400000) packet_speed_timer_time.tv_usec -= 20000;
                    set_timer(packet_speed_timer, &packet_speed_timer_time);
                } else {
                    fast_update_timer(packet_speed_timer, &info.current_time);
                }
            }
        }
        */
        
       
        // JSON LOGS HERE
        timersub(&info.current_time, &json_timer, &tv_tmp_tmp_tmp);
        if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, 500000}), >=)) {

            //if( info.head_channel && (max_speed != shm_conn_info->stats[info.process_num].ACK_speed) ) {
            //    vtun_syslog(LOG_ERR, "WARNING head chan detect may be wrong: max ACS != head ACS");            
            //}
            if(buf != save_buf) {
                vtun_syslog(LOG_ERR,"ERROR: buf: CORRUPT!");
            }
            sem_wait(&(shm_conn_info->stats_sem));
                            
            timersub(&info.current_time, &shm_conn_info->drop_time, &tv_tmp_tmp_tmp);
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {DROPPING_LOSSING_DETECT_SECONDS, 0}), >=)) {
                shm_conn_info->dropping = 0;
            } else {
                shm_conn_info->dropping = 1;
            }
            
            if(info.head_channel) {
                timersub(&(info.current_time), &real_loss_time, &tv_tmp_tmp_tmp);
                if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {DROPPING_LOSSING_DETECT_SECONDS, 0}), >=)) {
                    shm_conn_info->head_lossing = 0;
                } else {
                    shm_conn_info->head_lossing = 1;
                }
            }

            // calc ACS2 and DDS detect
            int max_ACS2=0;
            for(int i=0; i<info.channel_amount; i++) {
                info.channel[i].ACS2 = (info.channel[i].packet_seq_num_acked - info.channel[i].old_packet_seq_num_acked) * 2 * info.eff_len;
                info.channel[i].old_packet_seq_num_acked = info.channel[i].packet_seq_num_acked;
                if(max_ACS2 < info.channel[i].ACS2) max_ACS2 = info.channel[i].ACS2;
            }
            
            // now put max_ACS2 and PCS2 to SHM:
            shm_conn_info->stats[info.process_num].max_PCS2 = PCS * 2 * info.eff_len;
            shm_conn_info->stats[info.process_num].max_ACS2 = max_ACS2;
            shm_conn_info->stats[info.process_num].ACK_speed= max_ACS2; // !
            miss_packets_max = shm_conn_info->miss_packets_max;
            sem_post(&(shm_conn_info->stats_sem));
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t AG_ready_flags_tmp = shm_conn_info->AG_ready_flag;
            sem_post(&(shm_conn_info->AG_flags_sem));
            
#if !defined(DEBUGG) && defined(JSON)
            start_json(js_buf, &js_cur);
            add_json(js_buf, &js_cur, "name", "\"%s\"", lfd_host->host);
            add_json(js_buf, &js_cur, "pnum", "%d", info.process_num);
            add_json(js_buf, &js_cur, "hd", "%d", info.head_channel);
            add_json(js_buf, &js_cur, "super", "%d", super);
            super = 0;
            add_json(js_buf, &js_cur, "hold", "%d", was_hold_mode); // TODO: remove
            was_hold_mode = 0; // TODO: remove
            //add_json(js_buf, &js_cur, "ag?", "%d", ag_flag_local);
            add_json(js_buf, &js_cur, "agag", "%d", agag);
            add_json(js_buf, &js_cur, "rtt", "%d", info.rtt);
            add_json(js_buf, &js_cur, "rtt2", "%d", info.rtt2);
            add_json(js_buf, &js_cur, "buf_len", "%d", my_miss_packets_max);
            add_json(js_buf, &js_cur, "buf_len_remote", "%d", miss_packets_max);
            add_json(js_buf, &js_cur, "rsr", "%d", info.rsr);
            add_json(js_buf, &js_cur, "W_cubic", "%d", info.send_q_limit_cubic);
            add_json(js_buf, &js_cur, "send_q", "%d", send_q_eff);
            add_json(js_buf, &js_cur, "sqe_mean", "%d", send_q_eff_mean);
            add_json(js_buf, &js_cur, "ACS", "%d", info.packet_recv_upload_avg);
            add_json(js_buf, &js_cur, "ACS2", "%d", max_ACS2);
            add_json(js_buf, &js_cur, "PCS2", "%d", shm_conn_info->stats[info.process_num].max_PCS2);
            add_json(js_buf, &js_cur, "PCS", "%d", PCS);
            add_json(js_buf, &js_cur, "upload", "%d", shm_conn_info->stats[info.process_num].speed_chan_data[my_max_send_q_chan_num].up_current_speed);
            add_json(js_buf, &js_cur, "dropping", "%d", (shm_conn_info->dropping || shm_conn_info->head_lossing));
            add_json(js_buf, &js_cur, "CLD", "%d", check_rtt_latency_drop());
            add_json(js_buf, &js_cur, "flush", "%d", shm_conn_info->tflush_counter);
            add_json(js_buf, &js_cur, "bsa", "%d", statb.bytes_sent_norm);
            add_json(js_buf, &js_cur, "bsr", "%d", statb.bytes_sent_rx);
            //add_json(js_buf, &js_cur, "skip", "%d", skip);
            add_json(js_buf, &js_cur, "eff_len", "%d", info.eff_len);
            add_json(js_buf, &js_cur, "max_chan", "%d", shm_conn_info->max_chan);
            add_json(js_buf, &js_cur, "frtt", "%d", shm_conn_info->forced_rtt);
            add_json(js_buf, &js_cur, "frtt_r", "%d", shm_conn_info->forced_rtt_recv);


            add_json(js_buf, &js_cur, "RT", "%d", ag_stat.RT);
            add_json(js_buf, &js_cur, "WT", "%d", ag_stat.WT);
            add_json(js_buf, &js_cur, "D", "%d", ag_stat.D);
            add_json(js_buf, &js_cur, "CL", "%d", ag_stat.CL);
            add_json(js_buf, &js_cur, "DL", "%d", ag_stat.DL);
            memset((void *)&ag_stat, 0, sizeof(ag_stat));
            skip=0;
            PCS = 0; // WARNING! chan amt=1 hard-coded here!
            // bandwidth utilization extimation experiment
            //add_json(js_buf, &js_cur, "bdp", "%d", tv2ms(&shm_conn_info->stats[info.process_num].bdp1));
            /*
            int exact_rtt = (info.rtt2 < info.rtt ? info.rtt2 : info.rtt);
            int rbu = -1;
            int rbu_s = -1;

            if(send_q_eff_mean != 0) {
                rbu = exact_rtt * (max_ACS2/10) / send_q_eff_mean;
                if(rbu != 0) {
                    rbu_s = max_ACS2 / rbu * 100;
                } 
            }*/
            
            //add_json(js_buf, &js_cur, "rbu", "%d", rbu);
            //add_json(js_buf, &js_cur, "rbu_s", "%d", rbu_s);

            uint32_t m_lsn = 0;
            int lmax = 0;
            for(int i=0; i<info.channel_amount; i++) {
                if(info.channel[i].packet_loss_counter < lmax) {
                    lmax = info.channel[i].packet_loss_counter;
                }
                if(m_lsn < info.channel[i].local_seq_num) {
                    m_lsn = info.channel[i].local_seq_num; 
                }
            }
            //add_json(js_buf, &js_cur, "m_lsn", "%ld", m_lsn);
            add_json(js_buf, &js_cur, "loss_in", "%d", lmax);
            
            lmax = 0;
            for(int i=0; i<info.channel_amount; i++) {
                if(info.channel[i].packet_loss < lmax) {
                    lmax = info.channel[i].packet_loss;
                }
            }                
            add_json(js_buf, &js_cur, "loss_out", "%d", lmax);
            int Ch = 0;
            int Cs = 0;
            sem_wait(&(shm_conn_info->stats_sem));
            max_chan = shm_conn_info->max_chan;
            if(shm_conn_info->stats[max_chan].srtt2_10 > 0 && shm_conn_info->stats[info.process_num].ACK_speed > 0) {
                Ch = 100*shm_conn_info->stats[info.process_num].srtt2_10/shm_conn_info->stats[max_chan].srtt2_10;
                Cs = 100*shm_conn_info->stats[max_chan].ACK_speed/shm_conn_info->stats[info.process_num].ACK_speed;
            }
            sem_post(&(shm_conn_info->stats_sem));
            
            add_json(js_buf, &js_cur, "Ch", "%d", Ch);
            add_json(js_buf, &js_cur, "Cs", "%d", Cs);

            // now get slope
            //int slope = get_slope(&smalldata);
            //add_json(js_buf, &js_cur, "slope", "%d", slope);
            add_json(js_buf, &js_cur, "sqn[1]", "%lu", shm_conn_info->seq_counter[1]);
            add_json(js_buf, &js_cur, "rsqn[?]", "%lu", seq_num);
            add_json(js_buf, &js_cur, "lsn[1]", "%lu", info.channel[1].local_seq_num);
            add_json(js_buf, &js_cur, "rlsn[1]", "%lu", info.channel[1].local_seq_num_recv);
            
            print_json(js_buf, &js_cur);
#endif

            #ifdef SEND_Q_LOG
            // now array
            print_json_arr(jsSQ_buf, &jsSQ_cur);
            start_json_arr(jsSQ_buf, &jsSQ_cur, "send_q");
            #endif
            
            json_timer = info.current_time;
            info.max_send_q_max = 0;
            info.max_send_q_min = 120000;
        }
        // <<< END JSON LOGS
        
        
        
        if (info.check_shm) { // impossible to work (remove!?)
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            if (shm_conn_info->need_to_exit & (1 << info.process_num)) {
                linker_term = TERM_NONFATAL;
                vtun_syslog(LOG_INFO, "Need to exit by peer");
            }
            sem_post(&(shm_conn_info->AG_flags_sem));
            for (uint32_t i = 0; i < 32; i++) {
                if (!(chan_mask & (1 << i))) {
                    if (last_channels_mask & (1 << i)) {
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "Sending FRAME_DEAD_CHANNEL for %i", i);
#endif
                        uint32_t i_n = htonl(i);
                        uint16_t flag_n = htons(FRAME_DEAD_CHANNEL);
                        memcpy(buf, &i_n, sizeof(uint32_t));
                        memcpy(buf, &flag_n, sizeof(uint16_t));
                        int len_ret = proto_write(info.channel[0].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send FRAME_DEAD_CHANNEL; exit");
                            linker_term = TERM_NONFATAL;
                        }
                    }
                }
            }
            last_channels_mask = chan_mask;
            if (shm_conn_info->session_hash_remote != info.session_hash_remote) {
                vtun_syslog(LOG_INFO, "Need to exit by hash compare; exit");
                linker_term = TERM_NONFATAL;
            }
        }


        // SEND FCI >>>
        int timer_result=0;
        if(shm_conn_info->dropping || shm_conn_info->head_lossing) {
            timer_result = fast_check_timer(recv_n_loss_send_timer, &info.current_time);
        } else {
            // idle timer? // TODO: don't we need to send FCI if not sending on top speed??
            // TODO: this may or even WILL result in jitter and speed degrade if congestion is e.g. not on the path
            // TODO: out-of path congestion detection!
            timersub(&info.current_time, &(recv_n_loss_send_timer->start_time), &(recv_n_loss_send_timer->tmp));
            timer_result = timercmp(&(recv_n_loss_send_timer->tmp), &((struct timeval) {60, 0}), >=); // send each 60 seconds?
        }
        for (i = 1; i < info.channel_amount; i++) {
            uint32_t tmp32_n;
            uint16_t tmp16_n;
            // split LOSS event generation and bytes-in-flight (LLRS)

            // FCI - LLRS: TODO: remove dup code below (FCI packet formation)
            if( ((info.channel[i].packet_recv_counter > FCI_P_INTERVAL) || timer_result || need_send_FCI) && select_net_write(i) ) {
                need_send_FCI = 0;
                fast_update_timer(recv_n_loss_send_timer, &info.current_time);
                tmp16_n = htons((uint16_t)info.channel[i].packet_recv_counter); // amt of rcvd packets
                memcpy(buf, &tmp16_n, sizeof(uint16_t)); // amt of rcvd packets
                tmp16_n = 0; // loss, we're not sending loss now, just general info
                memcpy(buf + sizeof(uint16_t), &tmp16_n, sizeof(uint16_t)); // loss
                tmp16_n = htons(FRAME_CHANNEL_INFO);  // flag
                memcpy(buf + 2 * sizeof(uint16_t), &tmp16_n, sizeof(uint16_t));
                tmp32_n = htonl(info.channel[i].local_seq_num_recv); // last received local seq_num
                memcpy(buf + 3 * sizeof(uint16_t), &tmp32_n, sizeof(uint32_t));
                tmp16_n = htons((uint16_t) i); // chan_num ?? not needed in fact TODO remove
                memcpy(buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), &tmp16_n, sizeof(uint16_t));
                tmp32_n = htonl(info.channel[i].packet_download);
                memcpy(buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // down speed per current chan
                struct timeval tmp_tv;
                // local_seq_num
                tmp32_n = htonl(info.channel[i].local_seq_num);
                memcpy(buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // local_seq_num
                uint16_t tmp16 = ((uint16_t) (-1));
                sem_wait(write_buf_sem);
                if ((unsigned int) shm_conn_info->forced_rtt < ((uint16_t) (-1))) {
                    tmp16 = shm_conn_info->forced_rtt;
                }
                sem_post(write_buf_sem);
                tmp16_n = htons(tmp16); //forced_rtt here
                memcpy(buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //forced_rtt

                        if(debug_trace) {
                vtun_syslog(LOG_ERR,
                        "FRAME_CHANNEL_INFO LLRS send chan_num %d packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" ",
                        i, info.channel[i].packet_recv_counter, info.channel[i].packet_loss_counter,
                        (int16_t)info.channel[i].local_seq_num_recv, (uint32_t) (tmp_tv.tv_sec * 1000000 + tmp_tv.tv_usec));
                        }
                // send FCI-LLRS
                int len_ret = udp_write(info.channel[i].descriptor, buf, ((5 * sizeof(uint16_t) + 3 * sizeof(uint32_t)) | VTUN_BAD_FRAME));
                info.channel[i].local_seq_num++;
                if (len_ret < 0) {
                    vtun_syslog(LOG_ERR, "Could not send FRAME_CHANNEL_INFO; reason %s (%d)", strerror(errno), errno);
                    linker_term = TERM_NONFATAL;
                    break;
                }
                info.channel[i].packet_recv_counter = 0;
                shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret; // WTF?? no sync / futex ??
                info.channel[0].up_len += len_ret;
            }

            // now check if we need to fire LOSS event - send and commit locally
            if(info.channel[i].local_seq_num_beforeloss != 0) { // we are in loss monitoring state..
                timersub(&info.current_time, &info.channel[i].loss_time, &tv_tmp);
                int timer_result2 = timercmp(&tv_tmp, &info.max_reorder_latency, >=);
                if ( ((info.channel[i].packet_recv_counter_afterloss > MAX_REORDER_PERPATH) || timer_result2) && select_net_write(i)) {
                    // now send and zero
                    tmp16_n = htons((uint16_t)info.channel[i].packet_recv_counter); // amt of rcvd packets
                    memcpy(buf, &tmp16_n, sizeof(uint16_t)); // amt of rcvd packets

                    // TODO: do we use local_seq_num difference or total packets receive count??
                    //if( (info.channel[i].local_seq_num_recv - info.channel[i].local_seq_num_beforeloss) > MAX_REORDER_PERPATH) {
                    if( info.channel[i].packet_recv_counter_afterloss > MAX_REORDER_PERPATH) {
                        vtun_syslog(LOG_INFO, "sedning loss by REORDER %hd lrs %d, llrs %d, lsnbl %d", info.channel[i].packet_loss_counter, shm_conn_info->write_buf[i].last_received_seq[info.process_num], info.channel[i].local_seq_num_recv, info.channel[i].local_seq_num_beforeloss);
                    } else {
                        vtun_syslog(LOG_INFO, "sedning loss by LATENCY %hd lrs %d, llrs %d, lsnbl %d", info.channel[i].packet_loss_counter, shm_conn_info->write_buf[i].last_received_seq[info.process_num], info.channel[i].local_seq_num_recv, info.channel[i].local_seq_num_beforeloss);
                    }

                    info.channel[i].local_seq_num_beforeloss = 0;
                    tmp16_n = htons((uint16_t)info.channel[i].packet_loss_counter); // amt of pkts lost till this moment
                    
                    info.channel[i].packet_loss_counter = 0;
                    
                    // inform here that we detected loss -->
                    sem_wait(&(shm_conn_info->write_buf_sem));
                    shm_conn_info->write_buf[i].last_received_seq[info.process_num] = shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num] - MAX_REORDER_PERPATH;
                    //shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num] = 0;
                    sem_post(&(shm_conn_info->write_buf_sem));

                    memcpy(buf + sizeof(uint16_t), &tmp16_n, sizeof(uint16_t)); // loss
                    tmp16_n = htons(FRAME_CHANNEL_INFO);  // flag
                    memcpy(buf + 2 * sizeof(uint16_t), &tmp16_n, sizeof(uint16_t)); // flag
                    tmp32_n = htonl(info.channel[i].local_seq_num_recv); // last received local seq_num
                    memcpy(buf + 3 * sizeof(uint16_t), &tmp32_n, sizeof(uint32_t));
                    tmp16_n = htons((uint16_t) i); // chan_num
                    memcpy(buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //chan_num
                    tmp32_n = htonl(info.channel[i].local_seq_num); // local_seq_num
                    memcpy(buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // local_seq_num
                    tmp32_n = htonl(info.channel[i].packet_download);
                    memcpy(buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // down speed per current chan
                    uint16_t tmp16 = ((uint16_t) (-1));
                    sem_wait(write_buf_sem);
                    if ((unsigned int) shm_conn_info->forced_rtt < ((uint16_t) (-1))) {
                        tmp16 = shm_conn_info->forced_rtt;
                    }
                    sem_post(write_buf_sem);
                    tmp16_n = htons(tmp16); //forced_rtt here
                    memcpy(buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //forced_rtt

                        if(debug_trace) {
                    vtun_syslog(LOG_ERR,
                            "FRAME_CHANNEL_INFO send chan_num %d packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" ",
                            i, info.channel[i].packet_recv_counter, info.channel[i].packet_loss_counter,
                            (int16_t)info.channel[i].local_seq_num_recv, (uint32_t) (tv_tmp.tv_sec * 1000000 + tv_tmp.tv_usec));
                        }
                    // send FCI
                    // TODO: select here ???
                    int len_ret = udp_write(info.channel[i].descriptor, buf, ((5 * sizeof(uint16_t) + 3 * sizeof(uint32_t)) | VTUN_BAD_FRAME));
                    info.channel[i].local_seq_num++;
                    if (len_ret < 0) {
                        vtun_syslog(LOG_ERR, "Could not send FRAME_CHANNEL_INFO; reason %s (%d)", strerror(errno), errno);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                    info.channel[i].packet_recv_counter = 0;
                    shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret; // WTF?? no sync / futex ??
                    info.channel[0].up_len += len_ret;                    
                }
            }

            /* TODO write function for lws sending*/
            sem_wait(&(shm_conn_info->write_buf_sem));
            uint32_t last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
            uint32_t last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
            sem_post(&(shm_conn_info->write_buf_sem));
            if ((last_written_seq_tmp > (last_last_written_seq[i] + LWS_NOTIFY_MAX_SUB_SEQ)) && select_net_write(i) ) {
                // TODO: DUP code!
                
                if(debug_trace) {
                    vtun_syslog(LOG_ERR, "Sending LWS...");
                }
                sem_wait(&(shm_conn_info->write_buf_sem));
                *((uint32_t *) buf) = htonl(shm_conn_info->write_buf[i].last_written_seq);
                last_last_written_seq[i] = shm_conn_info->write_buf[i].last_written_seq;
                shm_conn_info->write_buf[i].last_lws_notified = info.current_time.tv_sec;
                sem_post(&(shm_conn_info->write_buf_sem));
                *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_LAST_WRITTEN_SEQ);
                // send LWS. TODO: is it Ever needed?? -> retransmit_send and top_seq_num shifting (why neede too dunno)
                // TODO: select here!
                int len_ret = udp_write(info.channel[i].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                if (len_ret < 0) {
                    vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                    linker_term = TERM_NONFATAL;
                }
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                info.channel[i].up_len += len_ret;
            }
        } // for each chan_num loop end ([i])
        // <<< END SEND FCI

        
        
        // do an expensive thing
          timersub(&info.current_time, &last_timing, &tv_tmp);
          /**
           *
           *    ___________.__        __     
           *    \__    ___/|__| ____ |  | __ 
           *      |    |   |  |/ ___\|  |/ / 
           *      |    |   |  \  \___|    <  
           *      |____|   |__|\___  >__|_ \ 
           *                       \/     \/ 
           *                       u
           * This is the Tick module
           */
        if ( timercmp(&tv_tmp, &timer_resolution, >=)) {
            if ((info.current_time.tv_sec - last_net_read) > lfd_host->MAX_IDLE_TIMEOUT) {
                vtun_syslog(LOG_INFO, "Session %s network timeout", lfd_host->host);
                break;
            }

            sem_wait(&(shm_conn_info->stats_sem));
            timersub(&info.current_time, &shm_conn_info->last_switch_time, &tv_tmp_tmp_tmp);
            if( (send_q_eff_mean < SEND_Q_IDLE) && !(shm_conn_info->idle)) {
                shm_conn_info->idle = 1;
            }
            sem_post(&(shm_conn_info->stats_sem));
            // head detect code
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) SPEED_REDETECT_TV), >=)) {
                sem_wait(&(shm_conn_info->stats_sem));
                redetect_head_unsynced(chan_mask, -1);
                sem_post(&(shm_conn_info->stats_sem));
            }
            if (info.just_started_recv == 1) {
                uint32_t time_passed = tv_tmp.tv_sec * 1000 + tv_tmp.tv_usec / 1000;
                if (time_passed == 0)
                    time_passed = 1;
                info.speed_efficient = info.byte_efficient / time_passed;
                info.speed_r_mode = info.byte_r_mode / time_passed;
                info.speed_resend = info.byte_resend / time_passed;
                info.byte_efficient = 0;
                info.byte_resend = 0;
                info.byte_r_mode = 0;
                for (int i = 0; i < info.channel_amount; i++) {
                    // speed(kb/s) calculation
                    sem_wait(&(shm_conn_info->stats_sem));
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed =
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt / time_passed;
                    sem_post(&(shm_conn_info->stats_sem));
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt = 0;
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed =
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt / (time_passed);
                    info.channel[i].download = shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed;
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt = 0;
#ifdef TRACE
                    vtun_syslog(LOG_INFO, "upload speed %"PRIu32" kb/s physical channel %d logical channel %d",
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed, info.process_num, i);
                    vtun_syslog(LOG_INFO, "download speed %"PRIu32" kb/s physical channel %d logical channel %d",
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed, info.process_num, i);
#endif
                    // speed in packets/sec calculation
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packet_speed =
                            (shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets / tv_tmp.tv_sec);
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets = 0;
#ifdef TRACE
                    vtun_syslog(LOG_INFO, "download speed %"PRIu32" packet/s physical channel %d logical channel %d lport %d rport %d",
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packet_speed, info.process_num, i, info.channel[i].lport, info.channel[i].rport);
#endif
                }
                //github.com - Issue #11
                int time_lag_cnt = 0, time_lag_sum = 0;
                for (int i = 0; i < MAX_TCP_LOGICAL_CHANNELS; i++) {
                    if (time_lag_info_arr[i].time_lag_cnt != 0) {
                        time_lag_cnt++;
                        time_lag_sum += time_lag_info_arr[i].time_lag_sum / time_lag_info_arr[i].time_lag_cnt;
                        time_lag_info_arr[i].time_lag_sum = 0;
                        time_lag_info_arr[i].time_lag_cnt = 0;
                    }
                }
                time_lag_local.time_lag = time_lag_cnt != 0 ? time_lag_sum / time_lag_cnt : 0;
                sem_wait(&(shm_conn_info->stats_sem));
                shm_conn_info->stats[info.process_num].time_lag_remote = time_lag_local.time_lag;
                sem_post(&(shm_conn_info->stats_sem));

                //todo send time_lag for all process(PHYSICAL CHANNELS)
                uint32_t time_lag_remote;
                uint16_t pid_remote;
                if(send_q_eff_mean > 1000) { // TODO: invent a more neat way to start sending buf_len (>0? changed?)
                    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                        if(buf_len_sent == my_miss_packets_max) continue;
                        buf_len_sent[i] = my_miss_packets_max;
                        sem_wait(&(shm_conn_info->stats_sem));
                        /* If pid is null --> link didn't up --> continue*/
                        if (shm_conn_info->stats[i].pid == 0) {
                            sem_post(&(shm_conn_info->stats_sem));
                            continue;
                        }
                        if (debug_trace) {
                            vtun_syslog(LOG_INFO, "Sending time lag (now buf_len) for %i buf_len %i.", i, my_miss_packets_max);
                        }
                        time_lag_remote = shm_conn_info->stats[i].time_lag_remote;
                        /* we store my_miss_packet_max value in 12 upper bits 2^12 = 4096 mx is 4095*/
                        time_lag_remote &= 0xFFFFF; // shrink to 20bit
                        time_lag_remote = shm_conn_info->stats[i].time_lag_remote | (my_miss_packets_max << 20);
                        pid_remote = shm_conn_info->stats[i].pid_remote;
                        uint32_t tmp_host = shm_conn_info->miss_packets_max_send_counter++;
                        tmp_host &= 0xFFFF;
    //vtun_syslog(LOG_ERR, "DEBUGG tmp_host %"PRIu32"", tmp_host); //?????
                        sem_post(&(shm_conn_info->stats_sem));
                        sem_wait(write_buf_sem);
                        tmp_host |= shm_conn_info->tflush_counter << 16;
                        shm_conn_info->tflush_counter = 0;
                        sem_post(write_buf_sem);
    //                    vtun_syslog(LOG_ERR, "DEBUGG tmp_host packed %"PRIu32"", tmp_host); //?????
                        uint32_t time_lag_remote_h = htonl(time_lag_remote); // we have two values in time_lag_remote(_h)
                        memcpy(buf, &time_lag_remote_h, sizeof(uint32_t));
                        uint16_t FRAME_TIME_LAG_h = htons(FRAME_TIME_LAG);
                        memcpy(buf + sizeof(uint32_t), &FRAME_TIME_LAG_h, sizeof(uint16_t));
                        uint16_t pid_remote_h = htons(pid_remote);
                        memcpy(buf + sizeof(uint32_t) + sizeof(uint16_t), &pid_remote_h, sizeof(uint16_t));
                        uint32_t miss_packet_counter_h = htonl(tmp_host);
                        memcpy(buf + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t), &miss_packet_counter_h, sizeof(uint32_t));
                        int len_ret = proto_write(info.channel[0].descriptor, buf,
                                ((sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send time_lag + pid pkt; exit"); //?????
                            linker_term = TERM_NONFATAL; //?????
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret;
                        info.channel[0].up_len += len_ret;
                    }
                }
                my_miss_packets_max = 0;
                if (delay_cnt == 0)
                    delay_cnt = 1;
                mean_delay = (delay_acc / delay_cnt);
#ifdef DEBUGG
                //vtun_syslog(LOG_INFO, "tick! cn: %s; md: %d, dacq: %d, w: %d, isl: %d, bl: %d, as: %d, bsn: %d, brn: %d, bsx: %d, drop: %d, rrqrx: %d, rxs: %d, ms: %d, rxmntf: %d, rxm_notf: %d, chok: %d, info.rtt: %d, lkdf: %d, msd: %d, ch: %d, chsdev: %d, chrdev: %d, mlh: %d, mrh: %d, mld: %d", lfd_host->host, channel_mode, dev_my_cnt, weight, incomplete_seq_len, buf_len, shm_conn_info->normal_senders, statb.bytes_sent_norm, statb.bytes_rcvd_norm, statb.bytes_sent_rx, statb.pkts_dropped, statb.rxmit_req_rx, statb.rxmits, statb.mode_switches, statb.rxm_ntf, statb.rxmits_notfound, statb.chok_not, info.info.rtt, (info.current_time.tv_sec - shm_conn_info->lock_time), mean_delay, info.channel_amount, std_dev(statb.bytes_sent_chan, info.channel_amount), std_dev(&statb.bytes_rcvd_chan[1], (info.channel_amount-1)), statb.max_latency_hit, statb.max_reorder_hit, statb.max_latency_drops);
                //vtun_syslog(LOG_INFO, "ti! s/r %d %d %d %d %d %d / %d %d %d %d %d %d", statb.bytes_rcvd_chan[0],statb.bytes_rcvd_chan[1],statb.bytes_rcvd_chan[2],statb.bytes_rcvd_chan[3],statb.bytes_rcvd_chan[4],statb.bytes_rcvd_chan[5], statb.bytes_sent_chan[0],statb.bytes_sent_chan[1],statb.bytes_sent_chan[2],statb.bytes_sent_chan[3],statb.bytes_sent_chan[4],statb.bytes_sent_chan[5] );
#endif
                dev_my_cnt = 0;
                last_tick = info.current_time.tv_sec;
                shm_conn_info->alive = info.current_time.tv_sec;
                delay_acc = 0;
                delay_cnt = 0;

                for (i = 1; i < info.channel_amount; i++) {
                    sem_wait(&(shm_conn_info->write_buf_sem));
                    uint32_t last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
                    uint32_t last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
                    sem_post(&(shm_conn_info->write_buf_sem));
                    if (((info.current_time.tv_sec - last_lws_notified_tmp) > LWS_NOTIFY_PEROID) && (last_written_seq_tmp > last_last_written_seq[i])) {
                        if(!select_net_write(i)) continue;
                        // TODO: DUP code!
                        if(debug_trace) {
                            vtun_syslog(LOG_ERR, "Sending LWS...");
                        }
                        sem_wait(&(shm_conn_info->write_buf_sem));
                        *((uint32_t *) buf) = htonl(shm_conn_info->write_buf[i].last_written_seq);
                        last_last_written_seq[i] = shm_conn_info->write_buf[i].last_written_seq;
                        shm_conn_info->write_buf[i].last_lws_notified = info.current_time.tv_sec;
                        sem_post(&(shm_conn_info->write_buf_sem));
                        *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_LAST_WRITTEN_SEQ);
                        // send LWS
                        int len_ret = udp_write(info.channel[i].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                            linker_term = TERM_NONFATAL;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                        info.channel[i].up_len += len_ret;
                    }
                }
            
            
            
            
             // do llist checks
            
            int alive_physical_channels = 0;
            int check_result=0;
            
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            sem_post(&(shm_conn_info->AG_flags_sem));
            
            
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) { 
                if (chan_mask & (1 << i)) {
                    alive_physical_channels++;
                }
            }
            if (alive_physical_channels == 0) {
                vtun_syslog(LOG_ERR, "ASSERT All physical channels dead!!!");
                alive_physical_channels = 1;
            }
            
            
            //sem_wait(&(shm_conn_info->write_buf_sem));
            //check_result = check_consistency_free(FRAME_BUF_SIZE, info.channel_amount, shm_conn_info->write_buf, &shm_conn_info->wb_free_frames, shm_conn_info->frames_buf);
            //sem_post(&(shm_conn_info->write_buf_sem));
            //if(check_result < 0) {
            //    vtun_syslog(LOG_ERR, "CHECK FAILED: write_buf broken: error %d", check_result);
            //}
            
               last_timing.tv_sec = info.current_time.tv_sec;
               last_timing.tv_usec = info.current_time.tv_usec;
          }
        }
        // <<< END TICK
        


        /* Detect that we need to enter retransmit_send as soon as possible 
            (some packets left unsent AND we're not holding) */
        int need_retransmit = 0;
        if( (ag_flag == R_MODE) && (hold_mode == 0) ) { // WARNING: if AG_MODE? or of DROP mode?
            sem_wait(&(shm_conn_info->common_sem));
            for (int i = 1; i < info.channel_amount; i++) {
                if(shm_conn_info->seq_counter[i] > last_sent_packet_num[i].seq_num) {
                    need_retransmit = 1;
                    break;
                }
            }
            sem_post(&(shm_conn_info->common_sem));
            if( (shm_conn_info->dropping || shm_conn_info->head_lossing) && (!info.head_channel) ) { // semi-atomic, no need to sync, TODO: can optimize with above
                need_retransmit = 1; // flood not-head to top for 'dropping time'
            }
        }
        // gettimeofday(&info.current_time, NULL); // TODO: required??
        
        

                    /*
                     *
                        _____         .__                   
                      /     \ _____  |__| ____             
                     /  \ /  \\__  \ |  |/    \            
                    /    Y    \/ __ \|  |   |  \           
                    \____|__  (____  /__|___|  /           
                            \/     \/        \/            
                                  .__                 __   
                      ______ ____ |  |   ____   _____/  |_ 
                     /  ___// __ \|  | _/ __ \_/ ___\   __\
                     \___ \\  ___/|  |_\  ___/\  \___|  |  
                    /____  >\___  >____/\___  >\___  >__|  
                         \/     \/          \/     \/      
                     * Now do a select () from all devices and channels
                     */
        sem_wait(write_buf_sem);
        if((shm_conn_info->forced_rtt_recv + MAX_LATENCY_DROP_SHIFT) > (MAX_LATENCY_DROP_USEC/1000)) {
            ms2tv(&info.max_latency_drop, shm_conn_info->forced_rtt_recv + MAX_LATENCY_DROP_SHIFT); // also set at FCI recv
        } else {
            info.max_latency_drop.tv_sec = 0;
            info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC;
        }

        FD_ZERO(&fdset_w);
        if (get_write_buf_wait_data() || need_retransmit || check_fast_resend()) { // TODO: need_retransmit here is because we think that it does continue almost immediately on select
            pfdset_w = &fdset_w;
            FD_SET(info.tun_device, pfdset_w);
        } else {
            pfdset_w = NULL;
        }
        sem_post(write_buf_sem);
        FD_ZERO(&fdset);
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
#endif
        if (((hold_mode == 0) || (drop_packet_flag == 1)) && (info.just_started_recv == 1)) {
            FD_SET(info.tun_device, &fdset);
            tv.tv_sec = 0;
            tv.tv_usec = SELECT_SLEEP_USEC;
        } else {
            tv.tv_sec = get_info_time.tv_sec;
            tv.tv_usec = get_info_time.tv_usec;
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "tun read select skip");
            vtun_syslog(LOG_INFO, "debug: HOLD_MODE");
#endif
        }
        for (i = 0; i < info.channel_amount; i++) {
            FD_SET(info.channel[i].descriptor, &fdset);
        }

#ifdef DEBUGG
        struct timeval work_loop1, work_loop2;
        gettimeofday(&work_loop1, NULL );
#endif
        len = select(maxfd + 1, &fdset, pfdset_w, NULL, &tv);
#ifdef DEBUGG
if(drop_packet_flag) {
        //gettimeofday(&work_loop2, NULL );
        vtun_syslog(LOG_INFO, "First select time: us descriptors num: %i", len);
}
#endif

        gettimeofday(&old_time, NULL);

        if (len < 0) { // selecting from multiple processes does actually work...
            // errors are OK if signal is received... TODO: do we have any signals left???
            if( errno != EAGAIN && errno != EINTR ) {
                vtun_syslog(LOG_INFO, "eagain select err; exit");
                break;
            } else {
                //vtun_syslog(LOG_INFO, "else select err; continue norm");
                continue;
            }
        }

        gettimeofday(&info.current_time, NULL); // current time may be ruined by select... TODO: this is expensive call -> optimize by timeradd?

        if( !len ) {
            /* We are idle, lets check connection */
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "idle...");
#endif
                /* Send ECHO request */
                if((info.current_time.tv_sec - last_action) > lfd_host->PING_INTERVAL) {
                    if(ping_rcvd) {
                         ping_rcvd = 0;
                         last_ping = info.current_time.tv_sec;
                         vtun_syslog(LOG_INFO, "PING ...");
                         // ping ALL channels! this is required due to 120-sec limitation on some NATs
                    for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                        if(!select_net_write(i)) continue;
                        ping_req_tv[i] = info.current_time;
                        int len_ret;
                        if (i == 0) {
                            len_ret = proto_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                        } else {
                            // send PING request
                            len_ret = udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                        }
                        if (len_ret < 0) {
                                 vtun_syslog(LOG_ERR, "Could not send echo request chan %d reason %s (%d)", i, strerror(errno), errno);
                                 linker_term = TERM_NONFATAL;
                                 break;
                             }
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                        info.channel[i].up_len += len_ret;
                         }
                         last_action = info.current_time.tv_sec; // TODO: clean up last_action/or/last_ping wtf.
                    }
                }
            continue;
        }

        /*
             *
             *

            _   _  _____ _____ _    _  ___________ _   __
           | \ | ||  ___|_   _| |  | ||  _  | ___ \ | / /
           |  \| || |__   | | | |  | || | | | |_/ / |/ / 
           | . ` ||  __|  | | | |/\| || | | |    /|    \ 
           | |\  || |___  | | \  /\  /\ \_/ / |\ \| |\  \
           \_| \_/\____/  \_/  \/  \/  \___/\_| \_\_| \_/
                                                         
                                                         
           ______ _____  ___ ______                      
           | ___ \  ___|/ _ \|  _  \                     
           | |_/ / |__ / /_\ \ | | |                     
           |    /|  __||  _  | | | |                     
           | |\ \| |___| | | | |/ /                      
           \_| \_\____/\_| |_/___/                       
                                                         
                                                 
             *
             * Read frames from network(service_channel), decode and pass them to
             * the local device (tun_device)
             *
             *
             *
             *
             * */
        int alive_physical_channels = 0;
        if (FD_ISSET(info.tun_device, &fdset_w)) {
            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            sem_post(&(shm_conn_info->AG_flags_sem));
            for (int i = 0; i < 32; i++) {
                if (chan_mask & (1 << i)) {
                    alive_physical_channels++;
                }
            }
            if (alive_physical_channels == 0) {
                vtun_syslog(LOG_ERR, "ASSERT All physical channels dead!!!");
                alive_physical_channels = 1;
            }
        }
        //check all chans for being set..
        for (chan_num = 0; chan_num < info.channel_amount; chan_num++) {
            if (FD_ISSET(info.tun_device, &fdset_w)) {
                sem_wait(write_buf_sem);
                if (write_buf_check_n_flush(chan_num)) { //double flush if possible
                    write_buf_check_n_flush(chan_num);
                }
                sem_post(write_buf_sem);
            }
            fd0 = -1;
            if(FD_ISSET(info.channel[chan_num].descriptor, &fdset)) {
                sem_wait(write_buf_sem);
                fprev = shm_conn_info->write_buf[chan_num_virt].frames.rel_head;
                if(fprev == -1) { // don't panic ;-)
                     shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = info.current_time.tv_sec;
                     shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = info.current_time.tv_usec;
                }
                sem_post(write_buf_sem);
                fd0=info.channel[chan_num].descriptor; // TODO Why this need????

                //net_counter++; // rxmit mode
                last_action = info.current_time.tv_sec;
                if (chan_num == 0) {
                    len = tcp_read(fd0, buf);
                } else {
                    len = udp_read(fd0, buf);
                }

#ifdef DEBUGG
if(drop_packet_flag) {
                vtun_syslog(LOG_INFO, "data on net... chan %d", chan_num);
}
#endif
                if( len<= 0 ) {
                    if (len == 0) {
                        vtun_syslog(LOG_INFO, "proto_read return 0, the peer with %d has performed an orderly shutdown. TERM_NONFATAL", chan_num);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                    if(len < 0) {
                         vtun_syslog(LOG_INFO, "sem_post! proto read <0; reason %s (%d)", strerror(errno), errno);
                         linker_term = TERM_NONFATAL;
                         break;
                    }
                    if(proto_err_cnt > 5) { // TODO XXX whu do we need this?? why doesnt proto_read just return <0???
                             vtun_syslog(LOG_INFO, "MAX proto read len==0 reached; exit!");
                             linker_term = TERM_NONFATAL;
                             break;
                    }
                    proto_err_cnt++;
                    continue;
                }
                proto_err_cnt = 0;
                /* Handle frame flags module */

                fl = len & ~VTUN_FSIZE_MASK;
                len = len & VTUN_FSIZE_MASK;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "data on net... chan %d len %i", chan_num, len);
#endif
                if(debug_trace) {
                    vtun_syslog(LOG_INFO, "data on net... chan %d len %i", chan_num, len);
                }
                shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].down_data_len_amt += len;
                if( fl ) {
                    if( fl==VTUN_BAD_FRAME ) {
                        flag_var = ntohs(*((uint16_t *)(buf+(sizeof(uint32_t)))));
                        if(flag_var == FRAME_MODE_NORM) {
                            vtun_syslog(LOG_ERR, "ASSERT FAILED! received FRAME_MODE_NORM flag while not in MODE_RETRANSMIT mode!");
                            continue;
                        } else if (flag_var == FRAME_MODE_RXMIT) {
                            // okay
                        } else if (flag_var == FRAME_JUST_STARTED) {
                            // the opposite end has zeroed counters; zero mine!
                            uint32_t session_hash_remote = ntohl(*((uint32_t *) (buf)));
                            vtun_syslog(LOG_INFO, "received FRAME_JUST_STARTED; receive remote hash - %u", session_hash_remote);
                            info.just_started_recv = 1;
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            if (shm_conn_info->session_hash_remote != session_hash_remote) {
                                shm_conn_info->session_hash_remote = session_hash_remote;
                                uint32_t chan_mask = shm_conn_info->channels_mask;
                                vtun_syslog(LOG_INFO, "zeroing counters old - %u new remote hash - %u",shm_conn_info->session_hash_remote, session_hash_remote );
                                sem_post(&(shm_conn_info->AG_flags_sem));
                                info.session_hash_remote = session_hash_remote;
                                for (int i = 0; i < 32; i++) {
                                    if ((i == info.process_num) || (!(chan_mask & (1 << i)))) {
                                        continue;
                                    }
                                    sem_wait(&(shm_conn_info->stats_sem));
                                    pid_t pid = shm_conn_info->stats[i].pid;
                                    sem_post(&(shm_conn_info->stats_sem));
                                }
                                sem_wait(&(shm_conn_info->write_buf_sem));
                                for (i = 0; i < info.channel_amount; i++) {
                                    shm_conn_info->seq_counter[i] = SEQ_START_VAL;
                                    shm_conn_info->write_buf[i].last_written_seq = SEQ_START_VAL;
                                    shm_conn_info->write_buf[i].remote_lws = SEQ_START_VAL;
                                    frame_llist_init(&(shm_conn_info->write_buf[i].frames));
                                    frame_llist_fill(&(shm_conn_info->wb_free_frames), shm_conn_info->frames_buf, FRAME_BUF_SIZE);
                                }
                                sem_post(&(shm_conn_info->write_buf_sem));
                                sem_wait(&(shm_conn_info->resend_buf_sem));
                                for (i = 0; i < RESEND_BUF_SIZE; i++) {
                                    if (shm_conn_info->resend_frames_buf[i].chan_num == chan_num)
                                        shm_conn_info->resend_frames_buf[i].seq_num = 0;
                                }
                                memset(shm_conn_info->resend_frames_buf, 0, sizeof(struct frame_seq) * RESEND_BUF_SIZE);
                                memset(shm_conn_info->fast_resend_buf, 0, sizeof(struct frame_seq) * MAX_TCP_PHYSICAL_CHANNELS);
                                shm_conn_info->resend_buf_idx = 0;
                                shm_conn_info->fast_resend_buf_idx = 0;
                                sem_post(&(shm_conn_info->resend_buf_sem));
                            } else {
                                sem_post(&(shm_conn_info->AG_flags_sem));
                            }
                            continue;
                        } else if (flag_var == FRAME_PRIO_PORT_NOTIFY) {
                            /*
                                
                    ______     _                     _   _  __       
                    | ___ \   (_)                   | | (_)/ _|      
                    | |_/ / __ _  ___    _ __   ___ | |_ _| |_ _   _ 
                    |  __/ '__| |/ _ \  | '_ \ / _ \| __| |  _| | | |
                    | |  | |  | | (_) | | | | | (_) | |_| | | | |_| |
                    \_|  |_|  |_|\___/  |_| |_|\___/ \__|_|_|  \__, |
                                                                __/ |
                                                               |___/  
                            */
                            // connect to port specified
                            if (server_addr(&rmaddr, lfd_host) < 0) {
                                vtun_syslog(LOG_ERR, "Could not set server address!");
                                linker_term = TERM_FATAL;
                                break;
                            }
                            inet_ntop(AF_INET, &rmaddr.sin_addr, ipstr, sizeof ipstr);
                            vtun_syslog(LOG_INFO, "Channels connecting to %s to create %d channels", ipstr, lfd_host->TCP_CONN_AMOUNT);
                            usleep(500000);

                            for (i = 1; i <= lfd_host->TCP_CONN_AMOUNT; i++) {
                                errno = 0;
                                if ((info.channel[i].descriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                                    vtun_syslog(LOG_ERR, "Can't create CHAN socket. %s(%d) chan %d", strerror(errno), errno, i);
                                    linker_term = TERM_FATAL;
                                    break;
                                }
#ifndef W_O_SO_MARK
                                if (lfd_host->RT_MARK != -1) {
                                    if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_MARK, &lfd_host->RT_MARK, sizeof(lfd_host->RT_MARK))) {
                                        vtun_syslog(LOG_ERR, "Client CHAN socket rt mark error %s(%d)", strerror(errno), errno);
                                        break_out = 1;
                                        break;
                                    }
                                }
#endif
                                sendbuff = RCVBUF_SIZE;
                                // WARNING! This should be on sysadmin's duty to optimize!
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &sendbuff, sizeof(int)) == -1) {
                                    vtun_syslog(LOG_ERR, "WARNING! Can not set rmem (SO_RCVBUF) size. Performance will be poor.");
                                }


                                rmaddr.sin_port = htons(info.channel[i].rport);
                                connect(info.channel[i].descriptor, (struct sockaddr *)&rmaddr, sizeof(rmaddr));
                                // send PING request
                                udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                                usleep(500000);
                            }
                            if (i < lfd_host->TCP_CONN_AMOUNT) {
                                vtun_syslog(LOG_ERR, "Could not connect all requested tuns; exit");
                                linker_term = TERM_NONFATAL;
                                break;
                            }
                            info.channel_amount = i;
                            maxfd = info.tun_device;
                            for (int i = 0; i < info.channel_amount; i++) {
                                if (maxfd < info.channel[i].descriptor) {
                                    maxfd = info.channel[i].descriptor;
                                }
                            }
                            //double call for getcockname beacause frst call returned ZERO in addr
                            laddrlen = sizeof(localaddr);
                            if (getsockname(info.channel[0].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                                vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                linker_term = TERM_NONFATAL;
                                break;
                            }
                            for (i = 0; i < info.channel_amount; i++) {
                                memset(&rmaddr, 0, sizeof(rmaddr));
                                memset(&localaddr, 0, sizeof(localaddr));
                                rmaddrlen = sizeof(rmaddr);
                                laddrlen = sizeof(localaddr);
                                if (getsockname(info.channel[i].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                                    vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                info.channel[i].lport = ntohs(localaddr.sin_port);
                                if (getpeername(info.channel[i].descriptor, (struct sockaddr *) (&rmaddr), &rmaddrlen) < 0) {
                                    vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                info.channel[i].rport = ntohs(rmaddr.sin_port);
                                vtun_syslog(LOG_INFO, "Client descriptor - %i logical channel - %i lport - %i rport - %i",info.channel[i].descriptor, i, info.channel[i].lport, info.channel[i].rport);
                            }
                            for(i = 1; i < info.channel_amount; i++) {
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
                                    vtun_syslog(LOG_ERR, "setsockopt failed");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_SNDTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
                                    vtun_syslog(LOG_ERR, "setsockopt failed");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                            }
                            vtun_syslog(LOG_INFO,"Successfully set up %d connection channels", info.channel_amount);
                            continue;
                        } else if(flag_var == FRAME_LAST_WRITTEN_SEQ) {
#ifdef DEBUGG
                            vtun_syslog(LOG_INFO, "received FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", ntohl(*((uint32_t *)buf)), chan_num);
#endif
                            if(debug_trace) {
                                vtun_syslog(LOG_INFO, "received FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", ntohl(*((uint32_t *)buf)), chan_num);
                            }
                            // TODO: no sync here!!?!?!
                            if( ntohl(*((uint32_t *)buf)) > shm_conn_info->write_buf[chan_num].remote_lws) shm_conn_info->write_buf[chan_num].remote_lws = ntohl(*((uint32_t *)buf));
                            continue;
						} else if (flag_var == FRAME_TIME_LAG) {
						    int recv_lag = 0;
							/* Get time_lag and miss_packet_max for some pid from net here */
						    uint32_t time_lag_and_miss_packets;
						    memcpy(&time_lag_and_miss_packets, buf, sizeof(uint32_t));
						    time_lag_and_miss_packets = ntohl(time_lag_and_miss_packets);
							uint16_t miss_packets_max_tmp = time_lag_and_miss_packets >> 20;
							time_lag_local.time_lag = time_lag_and_miss_packets & 0xFFFFF;
							memcpy(&(time_lag_local.pid), buf + sizeof(uint32_t) + sizeof(uint16_t), sizeof(time_lag_local.pid));
						    time_lag_local.pid = ntohs(time_lag_local.pid);
						    uint32_t tmp_n, tmp_h;
						    uint32_t miss_packets_max_recv_counter;
                            memcpy(&tmp_n, buf + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t), sizeof(uint32_t));
                            tmp_h = ntohl(tmp_n);
                            miss_packets_max_recv_counter = tmp_h & 0xFFFF;
							sem_wait(&(shm_conn_info->stats_sem));
                            shm_conn_info->tflush_counter_recv = tmp_h >> 16;
#ifdef DEBUGG
                            vtun_syslog(LOG_INFO, "recv pid - %i packet_miss - %"PRIu32" tmp_h %"PRIu32"",time_lag_local.pid, miss_packets_max_tmp, tmp_h);
							vtun_syslog(LOG_INFO, "Miss packet counter was - %"PRIu32" recv - %"PRIu32"",shm_conn_info->miss_packets_max_recv_counter, miss_packets_max_recv_counter);
#endif
                            if ((miss_packets_max_recv_counter > shm_conn_info->miss_packets_max_recv_counter)) {
                                miss_packets_max = miss_packets_max_tmp;
                                shm_conn_info->miss_packets_max = miss_packets_max;
                                shm_conn_info->miss_packets_max_recv_counter = miss_packets_max_recv_counter;
#ifdef DEBUGG
                                vtun_syslog(LOG_INFO, "Miss packets(buf_len) for counter %u is %u apply", miss_packets_max_recv_counter, miss_packets_max_tmp);
#endif
                            }
                            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                if (time_lag_local.pid == shm_conn_info->stats[i].pid) {
                                    shm_conn_info->stats[i].time_lag = time_lag_local.time_lag;
                                    recv_lag = 1;
                                    break;
                                }
                            }

                            if (debug_trace) {
                                vtun_syslog(LOG_INFO, "Time lag for pid: %i is %u", time_lag_local.pid, time_lag_local.time_lag);
                            }

							time_lag_local.time_lag = shm_conn_info->stats[info.process_num].time_lag;
							time_lag_local.pid = shm_conn_info->stats[info.process_num].pid;
							sem_post(&(shm_conn_info->stats_sem));
							continue;
                        } else if (flag_var == FRAME_DEAD_CHANNEL) {
                            uint32_t chan_mask_h;
                            memcpy(&chan_mask_h, buf, sizeof(uint32_t));
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            shm_conn_info->channels_mask = ntohl(chan_mask_h);
                            sem_post(&(shm_conn_info->AG_flags_sem));
                        } else if (flag_var == FRAME_CHANNEL_INFO) {
                            uint32_t tmp32_n;
                            uint16_t tmp16_n;
                            int chan_num;
                            memcpy(&tmp16_n, buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint16_t));
                            chan_num = (int)ntohs(tmp16_n);
                            gettimeofday(&info.current_time, NULL);
                            memcpy(&info.channel[chan_num].send_q_time, &info.current_time, sizeof(struct timeval));
                            memcpy(&tmp16_n, buf, sizeof(uint16_t));
                            info.channel[chan_num].packet_recv = ntohs(tmp16_n); // unused 
                            memcpy(&tmp16_n, buf + sizeof(uint16_t), sizeof(uint16_t));
                            info.channel[chan_num].packet_loss = ntohs(tmp16_n); // FCI-only data only on loss
                            memcpy(&tmp32_n, buf + 3 * sizeof(uint16_t), sizeof(uint32_t));
                            info.channel[chan_num].packet_seq_num_acked = ntohl(tmp32_n); // each packet data here
                            //vtun_syslog(LOG_ERR, "local seq %"PRIu32" recv seq %"PRIu32" chan_num %d ",info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked, chan_num);
                            memcpy(&tmp16_n, buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), sizeof(uint16_t)); //forced_rtt
                            
                            sem_wait(write_buf_sem);
                            shm_conn_info->forced_rtt_recv = (int) ntohs(tmp16_n);
                            if((shm_conn_info->forced_rtt_recv + MAX_LATENCY_DROP_SHIFT) > (MAX_LATENCY_DROP_USEC/1000)) {
                                ms2tv(&info.max_latency_drop, shm_conn_info->forced_rtt_recv + MAX_LATENCY_DROP_SHIFT); // also set at select
                            } else {
                                info.max_latency_drop.tv_sec = 0;
                                info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC;
                            }
                            sem_post(write_buf_sem);
                            //vtun_syslog(LOG_INFO, "Received forced_rtt: %d; my forced_rtt: %d", shm_conn_info->forced_rtt_recv, shm_conn_info->forced_rtt);
                            
                            info.channel[chan_num].send_q =
                                    info.channel[chan_num].local_seq_num > info.channel[chan_num].packet_seq_num_acked ?
                                            1000 * (info.channel[chan_num].local_seq_num - info.channel[chan_num].packet_seq_num_acked) : 0;
                            if (info.max_send_q < info.channel[chan_num].send_q) {
                                info.max_send_q = info.channel[chan_num].send_q;
                            }
                            //vtun_syslog(LOG_INFO, "FCI send_q %d", info.channel[chan_num].send_q);
                            //if (info.channel[chan_num].send_q > 90000)
                            //    vtun_syslog(LOG_INFO, "channel %d mad_send_q %"PRIu32" local_seq_num %"PRIu32" packet_seq_num_acked %"PRIu32"",chan_num, info.channel[chan_num].send_q,info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked);

                            if(debug_trace) {
                                vtun_syslog(LOG_ERR, "FCI local seq %"PRIu32" recv seq %"PRIu32" chan_num %d ",info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked, chan_num);
                            }
                            //vtun_syslog(LOG_INFO, "FRAME_CHANNEL_INFO: Calculated send_q: %d, chan %d, pkt %d, drops: %d", info.channel[chan_num].send_q, chan_num, info.channel[chan_num].packet_seq_num_acked, drop_counter);
                            uint32_t my_max_send_q = 0;
                            for (int i = 1; i < info.channel_amount; i++) {
                                if (my_max_send_q < info.channel[i].send_q) {
                                    my_max_send_q = info.channel[i].send_q;
                                    my_max_send_q_chan_num = i;
                                }
                            }
                            if (info.channel[chan_num].packet_loss > 0 && timercmp(&loss_immune, &info.current_time, <=)) {
                                vtun_syslog(LOG_ERR, "RECEIVED approved loss %"PRId16" chan_num %d send_q %"PRIu32"", info.channel[chan_num].packet_loss, chan_num,
                                        info.channel[chan_num].send_q);
                                loss_time = info.current_time; // received loss event time
                                real_loss_time = info.current_time; // received loss event time
                                if(info.head_channel) {
                                    sem_wait(&(shm_conn_info->stats_sem));
                                    if(shm_conn_info->idle) {
                                        // first check if we are really head
                                        // find max ACS 
                                        int ch_max_ACS = -1;
                                        int ch_max_ACS_ch = -1;
                                        int ch_max_ACS_W = -1;
                                        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                            if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != info.process_num)) { // hope this works..
                                                if(shm_conn_info->stats[i].ACK_speed > ch_max_ACS) {
                                                    ch_max_ACS = shm_conn_info->stats[i].ACK_speed;
                                                    ch_max_ACS_ch = i;
                                                    ch_max_ACS_W = shm_conn_info->stats[i].W_cubic;
                                                }
                                            }
                                        }
                                        if(ch_max_ACS != -1) {
                                            // check if we are the best from all other
                                            if(!percent_delta_equal(shm_conn_info->stats[info.process_num].ACK_speed, ch_max_ACS, 10)
                                                    && (shm_conn_info->stats[info.process_num].ACK_speed < ch_max_ACS)) {
                                                vtun_syslog(LOG_INFO, "Head changed to %d due to ACS>ACSh: %d > %d", ch_max_ACS_ch, ch_max_ACS, shm_conn_info->stats[info.process_num].ACK_speed);
                                                shm_conn_info->max_chan = ch_max_ACS_ch; // we found chan with better ACS (10% corridor)
                                            } else if ( percent_delta_equal(shm_conn_info->stats[info.process_num].ACK_speed, ch_max_ACS, 10)
                                                    && (ch_max_ACS_W > shm_conn_info->stats[info.process_num].W_cubic)) {
                                                // check Wh/Wi here
                                                // our process has smaller window with same speed; assume we're not the best now
                                                vtun_syslog(LOG_INFO, "Head changed to %d due to W>Wh: %d > %d", ch_max_ACS_ch, ch_max_ACS_W, shm_conn_info->stats[info.process_num].W_cubic);
                                                shm_conn_info->max_chan = ch_max_ACS_ch;
                                            } else {
                                                vtun_syslog(LOG_INFO, "Head (real) lossing after idle");
                                                shm_conn_info->idle = 0;
                                                shm_conn_info->head_lossing = 1;
                                            }
                                        } else {
                                            // we are the ONLY channel, drop flags
                                            vtun_syslog(LOG_INFO, "Head (only) lossing after idle");
                                            shm_conn_info->idle = 0;
                                            shm_conn_info->head_lossing = 1;
                                        }
                                    } else {
                                       // vtun_syslog(LOG_INFO, "Head lossing");
                                        shm_conn_info->head_lossing = 1;
                                    }
                                    sem_post(&(shm_conn_info->stats_sem));
                                }
                                ms2tv(&loss_tv, info.rtt / 2);
                                timeradd(&info.current_time, &loss_tv, &loss_immune);
                                if(info.head_channel) {
                                    info.send_q_limit_cubic_max = info.max_send_q; // fast-converge to flow (head now always converges!)
                                } else {
                                    if (info.channel[my_max_send_q_chan_num].send_q >= info.send_q_limit_cubic_max) {
                                        //info.send_q_limit_cubic_max = info.channel[my_max_send_q_chan_num].send_q;
                                        info.send_q_limit_cubic_max = info.max_send_q; // WTF? why not above? TODO undefined behaviour here
                                    } else {
                                        //info.send_q_limit_cubic_max = (int) ((double)info.channel[my_max_send_q_chan_num].send_q * (2.0 - info.B) / 2.0);
                                        info.send_q_limit_cubic_max = (int) ((double)info.max_send_q * (2.0 - info.B) / 2.0);
                                    }
                                }
                                t = 0;
                                info.max_send_q = 0;
                                sem_wait(&(shm_conn_info->stats_sem));
                                set_W_unsync(t);
                                sem_post(&(shm_conn_info->stats_sem));

                            } else {
                                timersub(&(info.current_time), &loss_time, &t_tv);
                                t = t_tv.tv_sec * 1000 + t_tv.tv_usec / 1000;
                                t = t / CUBIC_T_DIV;
                                t = t > CUBIC_T_MAX ? CUBIC_T_MAX : t; // 200s limit
                            }
                            sem_wait(&(shm_conn_info->stats_sem));
                            // set_W_unsync(t); // not required to recalculate here; will be more predictable
                            shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].send_q_loss = info.channel[chan_num].send_q; // never ever used!! TODO remove
                            sem_post(&(shm_conn_info->stats_sem));
                            //if (my_max_send_q < info.rsr) {
                            //    drop_packet_flag = 0;
                            //}
                            sem_wait(&(shm_conn_info->stats_sem));
                            shm_conn_info->stats[info.process_num].my_max_send_q_chan_num = my_max_send_q_chan_num;
                            sem_post(&(shm_conn_info->stats_sem));
                            info.max_send_q_avg = (uint32_t) ((int32_t) info.max_send_q_avg  // unused
                                    - ((int32_t) info.max_send_q_avg - (int32_t) my_max_send_q) / 4);

#if !defined(DEBUGG)
                            info.max_send_q_max = my_max_send_q > info.max_send_q_max ? my_max_send_q : info.max_send_q_max;
                            info.max_send_q_min = my_max_send_q < info.max_send_q_min ? my_max_send_q : info.max_send_q_min;
#endif
                            // local seq_num
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint32_t));
                            uint32_t local_seq_tmp = ntohl(tmp32_n); 
                            if (local_seq_tmp > info.channel[chan_num].local_seq_num_recv) {
                                info.channel[chan_num].local_seq_num_recv = local_seq_tmp;
                            }
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), sizeof(uint32_t)); // dn speed
#ifdef DEBUGG

                            int show_speed=0;
                            if (ntohl(tmp32_n) != info.channel[chan_num].packet_recv_upload) {
                                show_speed=1;
                            }
#endif
                            info.channel[chan_num].packet_recv_upload = ntohl(tmp32_n); // each packet data
                            info.channel[chan_num].packet_recv_upload_avg =
                                    info.channel[chan_num].packet_recv_upload > info.channel[chan_num].packet_recv_upload_avg ?
                                            (info.channel[chan_num].packet_recv_upload - info.channel[chan_num].packet_recv_upload_avg) / 4
                                                    + info.channel[chan_num].packet_recv_upload_avg :
                                            info.channel[chan_num].packet_recv_upload_avg
                                                    - (info.channel[chan_num].packet_recv_upload_avg - info.channel[chan_num].packet_recv_upload) / 4;
#ifdef DEBUGG
                            if(show_speed){
                                vtun_syslog(LOG_INFO, "channel %d speed %"PRIu32" Speed_avg %"PRIu32"",chan_num, info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);
                            }
#endif
                            //vtun_syslog(LOG_INFO, "FCI spd %d %d", info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);
                            sem_wait(&(shm_conn_info->stats_sem));
                            /* store in shm */
                            shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_recv_speed = // TODO: remove! never used
                                    info.channel[chan_num].packet_recv_upload;
                            if (my_max_send_q_chan_num == chan_num) {
                                //shm_conn_info->stats[info.process_num].ACK_speed = info.channel[chan_num].packet_recv_upload_avg == 0 ? 1 : info.channel[chan_num].packet_recv_upload_avg;
                                info.packet_recv_upload_avg = shm_conn_info->stats[info.process_num].ACK_speed;
                            }
                            shm_conn_info->stats[info.process_num].max_send_q = my_max_send_q;
                            shm_conn_info->stats[info.process_num].max_send_q_avg = info.max_send_q_avg; // unused
                            sem_post(&(shm_conn_info->stats_sem));
                            info.channel[chan_num].bytes_put = 0; // bytes_put reset for modeling
#ifdef DEBUGG
                            vtun_syslog(LOG_ERR,
                                    "FRAME_CHANNEL_INFO recv chan_num %d send_q %"PRIu32" packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" recv upload %"PRIu32" send_q %"PRIu32"",
                                    chan_num, info.channel[chan_num].send_q, info.channel[chan_num].packet_recv, (int16_t)info.channel[chan_num].packet_loss,
                                    info.channel[chan_num].packet_seq_num_acked, info.channel[chan_num].packet_recv_period, info.channel[chan_num].packet_recv_upload, info.channel[chan_num].send_q);
#endif
                            continue;
                        } else {
							vtun_syslog(LOG_ERR, "WARNING! unknown frame mode received: %du, real flag - %u!", (unsigned int) flag_var, ntohs(*((uint16_t *)(buf+(sizeof(uint32_t)))))) ;
					}
                        vtun_syslog(LOG_ERR, "Cannot resend frame %"PRIu32"; chan %d coz remomed api", ntohl(*((uint32_t *)buf)), chan_num);
                        continue;

                    } // bad frame end
                    if( fl==VTUN_ECHO_REQ ) {
                        /* Send ECHO reply */
                        if(!select_net_write(chan_num)) {
                            vtun_syslog(LOG_ERR, "Could not send echo reply due to net not selecting");
                            continue;
                        }
                        last_net_read = info.current_time.tv_sec;
                        if(debug_trace) {
                            vtun_syslog(LOG_INFO, "sending PONG...");
                        }
                        int len_ret;
                        if (chan_num == 0) {
                            len_ret = proto_write(info.channel[chan_num].descriptor, buf, VTUN_ECHO_REP);
                        } else {
                            // send pong reply
                            len_ret = udp_write(info.channel[chan_num].descriptor, buf, VTUN_ECHO_REP);
                        }
                        if ( len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send echo reply");
                            linker_term = TERM_NONFATAL;
                            break;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_data_len_amt += len_ret;
                        info.channel[chan_num].up_len += len_ret;
                        continue;
                    }
                    if( fl==VTUN_ECHO_REP ) {
                        /* Just ignore ECHO reply */
                        if(debug_trace) {
                            vtun_syslog(LOG_INFO, "... was echo reply");
                        }
                        
                        if(chan_num == 0) ping_rcvd = 1;
                        last_net_read = info.current_time.tv_sec;
                        gettimeofday(&info.current_time, NULL);

                        if (chan_num == my_max_send_q_chan_num) {
                            timersub(&info.current_time, &ping_req_tv[chan_num], &tv_tmp);
                            info.rtt = tv2ms(&tv_tmp);
                            sem_wait(&(shm_conn_info->stats_sem));
                            shm_conn_info->stats[info.process_num].rtt_phys_avg += (info.rtt - shm_conn_info->stats[info.process_num].rtt_phys_avg) / 2;
                            if(shm_conn_info->stats[info.process_num].rtt_phys_avg <= 0) {
                                shm_conn_info->stats[info.process_num].rtt_phys_avg = 1;
                            }
                            info.rtt = shm_conn_info->stats[info.process_num].rtt_phys_avg;
                            // now update max_reorder_latency
                            if(info.rtt >= (MAX_REORDER_LATENCY_MAX/1000)) {
                                info.max_reorder_latency.tv_sec = 0;
                                info.max_reorder_latency.tv_usec = MAX_REORDER_LATENCY_MAX;
                            } else if (info.rtt == 1) {
                                info.max_reorder_latency.tv_sec = 0;
                                info.max_reorder_latency.tv_usec = MAX_REORDER_LATENCY_MIN; // NOTE possible problem here? 
                            } else {
                                info.max_reorder_latency.tv_sec = 0;
                                info.max_reorder_latency.tv_usec = info.rtt * 1000;
                            }
                            
                            sem_post(&(shm_conn_info->stats_sem));
                        }

                        continue; 
                    }
                    if( fl==VTUN_CONN_CLOSE ) {
                        vtun_syslog(LOG_INFO,"Connection closed by other side");
                        vtun_syslog(LOG_INFO, "sem_post! conn closed other");
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                } else {
                    
                    /*

                    __________               .__                    .___
                    \______   \_____  ___.__.|  |   _________     __| _/
                     |     ___/\__  \<   |  ||  |  /  _ \__  \   / __ | 
                     |    |     / __ \\___  ||  |_(  <_> ) __ \_/ /_/ | 
                     |____|    (____  / ____||____/\____(____  /\____ | 
                                    \/\/                     \/      \/ 
                    __________                __           __           
                    \______   \_____    ____ |  | __ _____/  |_         
                     |     ___/\__  \ _/ ___\|  |/ // __ \   __\        
                     |    |     / __ \\  \___|    <\  ___/|  |          
                     |____|    (____  /\___  >__|_ \\___  >__|          
                                    \/     \/     \/    \/              
                    payload packet
                     */
                    
                    gettimeofday(&info.current_time, NULL);
                    info.channel[chan_num].down_packets++; // accumulate number of packets
                    PCS++; // TODO: PCS is sent and then becomes ACS. it is calculated above. This is DUP for local use. Need to refine PCS/ACS calcs!
                    last_net_read = info.current_time.tv_sec;
                    statb.bytes_rcvd_norm+=len;
                    statb.bytes_rcvd_chan[chan_num] += len;
                    out = buf; // wtf?
                    uint32_t local_seq_tmp;
                    uint16_t mini_sum;
                    uint32_t last_recv_lsn;
                    uint32_t packet_recv_spd;
                    len = seqn_break_tail(out, len, &seq_num, &flag_var, &local_seq_tmp, &mini_sum, &last_recv_lsn, &packet_recv_spd);
                    
                    // rtt calculation
                    if( (info.rtt2_lsn[chan_num] != 0) && (last_recv_lsn > info.rtt2_lsn[chan_num])) {
                        timersub(&info.current_time, &info.rtt2_tv[chan_num], &tv_tmp);
                        info.rtt2 = tv2ms(&tv_tmp);
                        info.rtt2_lsn[chan_num] = 0;
                        info.srtt2_10 += (info.rtt2*10 - info.srtt2_10) / 7;
                        if (info.rtt2 <= 0) info.rtt2 = 1;

                    }

                    if ((start_of_train != 0) && (chan_num == 1)) {

                        if (last_recv_lsn >= end_of_train) {
                            uint32_t packet_lag = last_recv_lsn - start_of_train;
                            start_of_train = 0;
                            //if(packet_lag > (TRAIN_PKTS + TRAIN_PKTS/2)) {
                            //    vtun_syslog(LOG_ERR, "WARNING Train calc wrong! packet_lag %d need train restart ASAP", packet_lag);
                            //    sem_wait(&(shm_conn_info->common_sem));
                            //    shm_conn_info->last_flood_sent.tv_sec = 0;
                            //    sem_post(&(shm_conn_info->common_sem));
                            //} else {
                                timersub(&info.current_time, &flood_start_time, &info.bdp1);
                            //}

                            // Now set max_chan -->
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            uint32_t chan_mask = shm_conn_info->channels_mask;
                            sem_post(&(shm_conn_info->AG_flags_sem));
                            sem_wait(&(shm_conn_info->stats_sem));
                            //shm_conn_info->bdp1[info.process_num] = info.bdp1;
                            shm_conn_info->stats[info.process_num].bdp1 = info.bdp1;
                            // now find max_chan
                            set_max_chan(chan_mask);
                            sem_post(&(shm_conn_info->stats_sem));
                            // <-- end max_chan set
                            
                            vtun_syslog(LOG_INFO, "%s paket_lag %"PRIu32" bdp %"PRIu32"%"PRIu32"us %"PRIu32"ms",  lfd_host->host, packet_lag, info.bdp1.tv_sec,
                                    info.bdp1.tv_usec, tv2ms(&info.bdp1));
                        }
                    }

                    // calculate send_q and speed
                    // send_q
                    if(info.channel[chan_num].packet_seq_num_acked != last_recv_lsn) {
                        info.channel[chan_num].send_q_time = info.current_time;
                        info.channel[chan_num].bytes_put = 0; // bytes_put reset for modeling
                    }
                    info.channel[chan_num].packet_seq_num_acked = last_recv_lsn;
                    info.channel[chan_num].send_q =
                                    info.channel[chan_num].local_seq_num > info.channel[chan_num].packet_seq_num_acked ?
                                            1000 * (info.channel[chan_num].local_seq_num - info.channel[chan_num].packet_seq_num_acked) : 0;
                    if(info.max_send_q < info.channel[chan_num].send_q) {
                        info.max_send_q = info.channel[chan_num].send_q;
                    }
                    if( (last_recv_lsn - peso_old_last_recv_lsn) > PESO_STAT_PKTS) {
                        // TODO: multi-channels broken here!
                        timersub(&info.current_time, &peso_lrl_ts, &tv_tmp);
                        // TODO: check for overflow here? -->
                        if(tv2ms(&tv_tmp) > 3) { // TODO: what to do if < 3ms?? 3ms is 333p/s
                            int ACS2 = (last_recv_lsn - peso_old_last_recv_lsn) * info.eff_len / tv2ms(&tv_tmp) * 1000;
                            int s_q_idx = send_q_eff / info.eff_len / SD_PARITY;
                            if(s_q_idx < (MAX_SD_W / SD_PARITY)) {
                                smalldata.ACS[s_q_idx] = ACS2;
                                smalldata.rtt[s_q_idx] = info.rtt2;
                                smalldata.ts[s_q_idx] = info.current_time;
                            }
                        }
                        peso_lrl_ts = info.current_time;
                        peso_old_last_recv_lsn = last_recv_lsn;
                    }
#ifdef DEBUGG
if(drop_packet_flag) {
                    vtun_syslog(LOG_INFO, "PKT send_q %d:.local_seq_num=%d, last_recv_lsn=%d", info.channel[chan_num].send_q, info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked);
}
#endif
                    // the following is to calculate my_max_send_q_chan_num only
                    uint32_t my_max_send_q = 0;
                    for (int i = 1; i < info.channel_amount; i++) {
                        if (my_max_send_q < info.channel[i].send_q) {
                            my_max_send_q = info.channel[i].send_q;
                            my_max_send_q_chan_num = i;
                        }
                    }

                    // ACS
                    info.channel[chan_num].packet_recv_upload = packet_recv_spd; // each packet data
                    info.channel[chan_num].packet_recv_upload_avg =
                            info.channel[chan_num].packet_recv_upload > info.channel[chan_num].packet_recv_upload_avg ?
                                    (info.channel[chan_num].packet_recv_upload - info.channel[chan_num].packet_recv_upload_avg) / 4
                                            + info.channel[chan_num].packet_recv_upload_avg :
                                    info.channel[chan_num].packet_recv_upload_avg
                                            - (info.channel[chan_num].packet_recv_upload_avg - info.channel[chan_num].packet_recv_upload) / 4;

                    sem_wait(&(shm_conn_info->stats_sem));
                    if (my_max_send_q_chan_num == chan_num) {
                        //shm_conn_info->stats[info.process_num].ACK_speed = info.channel[chan_num].packet_recv_upload_avg == 0 ? 1 : info.channel[chan_num].packet_recv_upload_avg;
                        info.packet_recv_upload_avg = shm_conn_info->stats[info.process_num].ACK_speed;
                    }
                    shm_conn_info->stats[info.process_num].max_send_q = my_max_send_q;
                    shm_conn_info->stats[info.process_num].rtt2 = info.rtt2; // TODO: do this copy only if RTT2 recalculated (does not happen each frame)
                    shm_conn_info->stats[info.process_num].srtt2_10 = info.srtt2_10; // TODO: do this copy only if RTT2 recalculated (does not happen each frame)
                    sem_post(&(shm_conn_info->stats_sem));

                    //vtun_syslog(LOG_INFO, "PKT spd %d %d", info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);

                    /* Accumulate loss packet*/
                    uint16_t mini_sum_check = (uint16_t)(seq_num + local_seq_tmp + last_recv_lsn);
                    
                    if(mini_sum != mini_sum_check) { // TODO: remove!
                        vtun_syslog(LOG_ERR, "PACKET CHECKSUM ERROR chan %d, seq_num %lu, %"PRId16" != %"PRId16"", chan_num, seq_num, ntohs(mini_sum), mini_sum_check);
                        continue;
                    }
                    
                    // this is loss detection -->
                    // TODO: DUPs detect! +loss/DUP mess?? need a small buffer of received pkts?
                    if (local_seq_tmp > (info.channel[chan_num].local_seq_num_recv + 1)) {                        
                        // increment packet_loss_counter unconditionally
                        info.channel[chan_num].packet_loss_counter += (((int32_t) local_seq_tmp)
                                - ((int32_t) (info.channel[chan_num].local_seq_num_recv + 1)));
                        // if this is first(?) loss, restart counters
                        if(info.channel[chan_num].local_seq_num_beforeloss == 0) {
                            info.channel[chan_num].local_seq_num_beforeloss = info.channel[chan_num].local_seq_num_recv;
                            info.channel[chan_num].loss_time = info.current_time;
                            info.channel[chan_num].packet_recv_counter_afterloss = 0;
                        }
//#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "loss +%d calced seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", 
                            (((int32_t) local_seq_tmp) - ((int32_t) (info.channel[chan_num].local_seq_num_recv + 1))),
                                    info.channel[chan_num].local_seq_num_recv, local_seq_tmp, info.channel[chan_num].packet_loss_counter, seq_num);
//#endif
                        if (local_seq_tmp > (info.channel[chan_num].local_seq_num_recv + 1000)) {
                            vtun_syslog(LOG_ERR, "BROKEN PKT TYPE 2 RECEIVED: seq was %"PRIu32" now %"PRIu32" loss is %"PRId16"", info.channel[chan_num].local_seq_num_recv,
                                local_seq_tmp, info.channel[chan_num].packet_loss_counter);
                        }
                    } else if ( (local_seq_tmp < info.channel[chan_num].local_seq_num_recv) && (local_seq_tmp > info.channel[chan_num].local_seq_num_beforeloss)) {
                        // SOME dup protection exists here... but not full
                        if(info.channel[chan_num].local_seq_num_beforeloss > 0) {
                            info.channel[chan_num].packet_loss_counter--;
                            if(info.channel[chan_num].packet_loss_counter < 0) {
                                info.channel[chan_num].packet_loss_counter = 0;
                                info.channel[chan_num].loss_time = info.current_time;
                            }
                        } else {
                            vtun_syslog(LOG_INFO, "DUP +1 calced NO REORDER local seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", info.channel[chan_num].local_seq_num_recv,
                                local_seq_tmp, (int)info.channel[chan_num].packet_loss_counter, seq_num);
                        }
//#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "loss -1 calced local seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", info.channel[chan_num].local_seq_num_recv,
                                local_seq_tmp, (int)info.channel[chan_num].packet_loss_counter, seq_num);
//#endif
                    } else if ((local_seq_tmp == info.channel[chan_num].local_seq_num_recv) || (local_seq_tmp <= info.channel[chan_num].local_seq_num_beforeloss)) {
                        if(info.channel[chan_num].local_seq_num_beforeloss > 0) {
                            vtun_syslog(LOG_INFO, "DUP +1 +REORDER calced local seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", info.channel[chan_num].local_seq_num_recv,
                                    local_seq_tmp, (int)info.channel[chan_num].packet_loss_counter, seq_num);
                        } else {
                            vtun_syslog(LOG_INFO, "DUP +1 calced local seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", info.channel[chan_num].local_seq_num_recv,
                                    local_seq_tmp, (int)info.channel[chan_num].packet_loss_counter, seq_num);
                        }
                    } //else { } // OK, we're in order

                    sem_wait(write_buf_sem);
                    if(info.channel[chan_num].local_seq_num_beforeloss != 0) {
                        if(info.channel[chan_num].packet_loss_counter == 0) { // situation normalized, all packets received
                            info.channel[chan_num].local_seq_num_beforeloss = 0;
                            shm_conn_info->write_buf[chan_num].last_received_seq[info.process_num] = shm_conn_info->write_buf[chan_num].last_received_seq_shadow[info.process_num] - MAX_REORDER_PERPATH;
                            //shm_conn_info->write_buf[chan_num].last_received_seq_shadow[info.process_num] = 0;
                        } else {
                            // TODO: why this? -->
                            if(local_seq_tmp == (info.channel[chan_num].local_seq_num_beforeloss + 1)) { // we received last lost pkt
                                info.channel[chan_num].packet_recv_counter_afterloss--; // one packet less
                                info.channel[chan_num].local_seq_num_beforeloss = local_seq_tmp;
                                // TODO: info.channel[chan_num].loss_time = info.current_time; // <- here??
                            } else {
                                info.channel[chan_num].packet_recv_counter_afterloss++; 
                            }
                        }
                        shm_conn_info->write_buf[chan_num].last_received_seq_shadow[info.process_num] = seq_num;
                    } else {
                        shm_conn_info->write_buf[chan_num].last_received_seq[info.process_num] = seq_num - MAX_REORDER_PERPATH;
                    }

                    // this is normal operation -->
                    if (local_seq_tmp > info.channel[chan_num].local_seq_num_recv) {
                        info.channel[chan_num].local_seq_num_recv = local_seq_tmp;
                    }

                    info.channel[chan_num].packet_recv_counter++;
#ifdef DEBUGG
if(drop_packet_flag) {
                    vtun_syslog(LOG_INFO, "Receive frame ... chan %d local seq %"PRIu32" seq_num %"PRIu32" recv counter  %"PRIu16" len %d loss is %"PRId16"", chan_num, info.channel[chan_num].local_seq_num_recv,seq_num, info.channel[chan_num].packet_recv_counter, len, (int16_t)info.channel[chan_num].packet_loss_counter);
}
#endif
                    if(debug_trace) {
                        vtun_syslog(LOG_INFO, "Receive frame ... chan %d local seq %"PRIu32" seq_num %"PRIu32" recv counter  %"PRIu16" len %d loss is %"PRId16"", chan_num, info.channel[chan_num].local_seq_num_recv,seq_num, info.channel[chan_num].packet_recv_counter, len, (int16_t)info.channel[chan_num].packet_loss_counter);
                    }
                    // HOLY CRAP! remove this! --->>>
                    // introduced virtual chan_num to be able to process
                    //    congestion-avoided priority resend frames
                    if(chan_num == 0) { // reserved aux channel
                         if(flag_var == 0) { // this is a workaround for some bug... TODO!!
                              vtun_syslog(LOG_ERR,"BUG! flag_var == 0 received on chan 0! sqn %"PRIu32", len %d. DROPPING",seq_num, len);
                              sem_post(write_buf_sem);
                              continue;
                         } 
                         chan_num_virt = flag_var - FLAGS_RESERVED;
                    } else {
                         chan_num_virt = chan_num;
                    }
#ifdef DEBUGG
                    struct timeval work_loop1, work_loop2;
                    gettimeofday(&work_loop1, NULL );
#endif
                    uint16_t my_miss_packets = 0;
                    info.channel[chan_num].last_recv_time = info.current_time;
                    succ_flag = 0;
                    incomplete_seq_len = write_buf_add(chan_num_virt, out, len, seq_num, incomplete_seq_buf, &buf_len, info.pid, &succ_flag);
                    my_miss_packets = buf_len;
                    my_miss_packets_max = my_miss_packets_max < buf_len ? buf_len : my_miss_packets_max;
                    if(succ_flag == -2) statb.pkts_dropped++; // TODO: optimize out to wba
                    if(buf_len == 1) { // to avoid dropping first out-of order packet in sequence
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = info.current_time.tv_sec;
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = info.current_time.tv_usec;
                    }
                    sem_post(write_buf_sem);
#ifdef DEBUGG
                    gettimeofday(&work_loop2, NULL );
                    vtun_syslog(LOG_INFO, "write_buf_add time: %"PRIu32" us", (long int) ((work_loop2.tv_sec - work_loop1.tv_sec) * 1000000 + (work_loop2.tv_usec - work_loop1.tv_usec)));
#endif
                    if(incomplete_seq_len == -1) {
                        vtun_syslog(LOG_ERR, "ASSERT FAILED! free write buf assert failed on chan %d", chan_num_virt);
                        buf_len = 100000; // flush the sh*t
                    }

                    if(buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) {
                        vtun_syslog(LOG_ERR, "WARNING! MAX_ALLOWED_BUF_LEN reached! Flushing... chan %d", chan_num_virt);
                    }
                    sem_wait(write_buf_sem);
                    struct timeval last_write_time_tmp = shm_conn_info->write_buf[chan_num_virt].last_write_time;
                    sem_post(write_buf_sem);

                    // check for initialization
                    if (!info.just_started_recv) {
                        continue;
                    }

                    if (FD_ISSET(info.tun_device, &fdset_w)) {
                        int write_out_max = buf_len / alive_physical_channels;
                        if(write_out_max > WRITE_OUT_MAX) write_out_max = WRITE_OUT_MAX;
                        if(write_out_max < 2) write_out_max = 2;
                        sem_wait(write_buf_sem);
                        for (int i = 0; i < write_out_max; i++) {
                            if (!write_buf_check_n_flush(chan_num_virt)) {
                                break;
                            }
                        }
                        sem_post(write_buf_sem);
                    }
                    // send lws(last written sequence number) to remote side
                    sem_wait(write_buf_sem);
                    int cond_flag = shm_conn_info->write_buf[chan_num_virt].last_written_seq > (last_last_written_seq[chan_num_virt] + lfd_host->FRAME_COUNT_SEND_LWS) ? 1 : 0;
                    sem_post(write_buf_sem);
                    if(cond_flag && select_net_write(chan_num_virt)) {
                        sem_wait(write_buf_sem);
                        if(debug_trace) {
                            vtun_syslog(LOG_INFO, "sending FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", shm_conn_info->write_buf[chan_num_virt].last_written_seq, chan_num_virt);
                        }
                        *((uint32_t *)buf) = htonl(shm_conn_info->write_buf[chan_num_virt].last_written_seq);
                        last_last_written_seq[chan_num_virt] = shm_conn_info->write_buf[chan_num_virt].last_written_seq;
                        shm_conn_info->write_buf[chan_num_virt].last_lws_notified = info.current_time.tv_sec;
                        sem_post(write_buf_sem);
                        *((uint16_t *)(buf+sizeof(uint32_t))) = htons(FRAME_LAST_WRITTEN_SEQ);
                        // send LWS - 2
                        int len_ret = udp_write(info.channel[chan_num_virt].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                            linker_term = TERM_NONFATAL;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num_virt].up_data_len_amt += len_ret;
                        info.channel[chan_num_virt].up_len += len_ret;
                        // TODO: introduce periodic send via each channel. On channel use stop some of resend_buf will remain locked
                        continue;
                    }

                    lfd_host->stat.byte_in += len; // the counter became completely wrong

                } // end load frame processing

            } // if fd0>0

        // if we could not create logical channels YET. We can't send data from tun to net. Hope to create later...
            if ((info.channel_amount <= 1) || (info.just_started_recv == 0)) { // only service channel available
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "Logical channels have not created. Hope to create later... ");
#endif
            continue;
        }
        /* Pass data from write_buff to TUN device */

        // I suspect write_buf_sem race condition here... double-check!
        int wbs_val;
        sem_getvalue(write_buf_sem, &wbs_val);
        if ( wbs_val > 1 ) {
            sem_wait(write_buf_sem);
            vtun_syslog(LOG_INFO, "ASSERT FAILED! write_buf_sem value is %d! fixed.", wbs_val);
        }

        } // for chans..

// TODO HERE: do not fall down if network is not selected for writing!

            /* Read data from the local device(tun_device), encode and pass it to
             * the network (service_channel)
             *

                .___         _________                  .___
              __| _/____    /   _____/ ____   ____    __| _/
             / __ |/  _ \   \_____  \_/ __ \ /    \  / __ | 
            / /_/ (  <_> )  /        \  ___/|   |  \/ /_/ | 
            \____ |\____/  /_______  /\___  >___|  /\____ | 
                 \/                \/     \/     \/      \/ 
                                 __           __            
            ___________    ____ |  | __ _____/  |_          
            \____ \__  \ _/ ___\|  |/ // __ \   __\         
            |  |_> > __ \\  \___|    <\  ___/|  |           
            |   __(____  /\___  >__|_ \\___  >__|           
            |__|       \/     \/     \/    \/               
             *
             * ****************************************************************************************
             *
             *
             * */
      //  if (hold_mode) continue;
        sem_wait(&shm_conn_info->hard_sem);
        if (ag_flag == R_MODE) {
            int lim = (((uint32_t)info.rsr < info.send_q_limit_cubic) ? info.rsr : info.send_q_limit_cubic);
            int n_to_send = (lim - send_q_eff) / 1000;
            if(n_to_send < 0) {
                n_to_send = 0;
            }
            len = retransmit_send(out2, n_to_send);
            if (len == CONTINUE_ERROR) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "debug: R_MODE continue err");
#endif
                len = 0;
            } else if (len == BREAK_ERROR) {
                vtun_syslog(LOG_INFO, "retransmit_send() BREAK_ERROR");
                linker_term = TERM_NONFATAL;
//            break;
            } else if ((len == LASTPACKETMY_NOTIFY) | (len == HAVE_FAST_RESEND_FRAME)) { // if this physical channel had sent last packet
#ifdef DEBUGG
                    vtun_syslog(LOG_INFO, "debug: R_MODE main send");
#endif
                if( (drop_packet_flag == 1) && (drop_counter > 0) ) {
                    len = 0; // shittyhold - should never kick in again!
                    vtun_syslog(LOG_INFO, "shit! hold!");
                } else {
                len = select_devread_send(buf, out2);
                }
                
                if (len > 0) {
                } else if (len == BREAK_ERROR) {
                    vtun_syslog(LOG_INFO, "select_devread_send() R_MODE BREAK_ERROR");
                    linker_term = TERM_NONFATAL;
//                break;
                } else if (len == CONTINUE_ERROR) {
                    len = 0;
                } else if (len == TRYWAIT_NOTIFY) {
                    len = 0; //todo need to check resend_buf for new packet again ????
                }
            }
        } else { // this is AGGREGATION MODE(AG_MODE) we jump here if all channels ready for aggregation. It very similar to the old MODE_NORMAL ...
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: AG_MODE");
#endif
            if( (drop_packet_flag == 1) && (drop_counter > 0) ) {
                    len = 0; // shittyhold // never
                    vtun_syslog(LOG_INFO, "shit! hold!");
            } else {
            len = select_devread_send(buf, out2);
            }
            if (len > 0) {
                dirty_seq_num++;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "Dirty seq_num - %u", dirty_seq_num);
#endif
            } else if (len == BREAK_ERROR) {
                vtun_syslog(LOG_INFO, "select_devread_send() AG_MODE BREAK_ERROR");
                linker_term = TERM_NONFATAL;
                break;
            } else if (len == CONTINUE_ERROR) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "select_devread_send() CONTINUE");
#endif
                len = 0;
            } else if (len == TRYWAIT_NOTIFY) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "select_devread_send() TRYWAIT_NOTIFY");
#endif
                len = 0;
            } else if (len == NET_WRITE_BUSY_NOTIFY) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "select_devread_send() NET_WRITE_BUSY_NOTIFY");
#endif
                len = 0;
            } else if (len == SEND_Q_NOTIFY) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "select_devread_send() SEND_Q_NOTIFY");
#endif
                len = 0;
            }
        }

        //todo #flood_code need to move
        int flood_flag = 0;
        sem_wait(&(shm_conn_info->common_sem));
        if (shm_conn_info->flood_flag[info.process_num])
            flood_flag = TRAIN_PKTS;
        shm_conn_info->flood_flag[info.process_num] = 0;
//        tmp_seq_counter = shm_conn_info->seq_counter[1];
        sem_post(&(shm_conn_info->common_sem));
        uint32_t local_seq_num_p;
        uint16_t tmp_flag=0, gg1;
        uint32_t  gg2, gg3;
        if (flood_flag > 0 && linker_term != TERM_NONFATAL) {
            gettimeofday(&flood_start_time, NULL );
            start_of_train = info.channel[1].local_seq_num;
            end_of_train = start_of_train + flood_flag;
            sem_wait(&(shm_conn_info->resend_buf_sem));
            uint32_t seq_tmp;
            get_last_packet_seq_num(1, &seq_tmp);
            int sender_pid;
            char *out;
            int len = get_resend_frame(1, &seq_tmp, &out, &sender_pid );
            if (len == -1) {
                len = get_last_packet(1, &last_sent_packet_num[1].seq_num, &out, &sender_pid);
            }
            if (len == -1) {
                vtun_syslog(LOG_ERR, "WARNING Cannot send train");
            } else {
                memcpy(buf, out, len);
            }
            if(len < 900) {
                vtun_syslog(LOG_ERR, "WARNING Train car too small to load track!");
            }
            sem_post(&(shm_conn_info->resend_buf_sem));
            for (; flood_flag > 0; flood_flag--) {
                len = seqn_break_tail(buf, len, &seq_tmp, &tmp_flag, &local_seq_num_p, &gg1, &gg2, &gg3); // last four unused
                len = pack_packet(1, buf, len, seq_tmp, info.channel[1].local_seq_num, 0);
                info.channel[1].packet_recv_counter = 0;
                // send DATA
                int len_ret = udp_write(info.channel[1].descriptor, buf, len);
//                vtun_syslog(LOG_INFO, "send train process %i packet num %i local_seq %"PRIu32"", info.process_num, flood_flag,
//                        info.channel[1].local_seq_num);
                info.channel[1].local_seq_num++;
            }
        }
        sem_post(&shm_conn_info->hard_sem);

            //Check time interval and ping if need.
        if (((info.current_time.tv_sec - last_ping) > lfd_host->PING_INTERVAL) && (len <= 0) ) {
				gettimeofday(&info.current_time, NULL); // WTF?

				// ping ALL channels! this is required due to 120-sec limitation on some NATs
            for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                if(!select_net_write(i)) continue;
				last_ping = info.current_time.tv_sec;
				ping_rcvd = 0;
                ping_req_tv[i] = info.current_time;
                int len_ret;
                if (i == 0) {
                    len_ret = proto_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                    if(debug_trace) {
                        vtun_syslog(LOG_INFO, "PING2 chan_num %d", i);
                    }
                } else {
                    // send ping request - 2
                    len_ret = udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                    if(debug_trace) {
                        vtun_syslog(LOG_INFO, "PING2 chan_num %d", i);
                    }
                }
                if (len_ret < 0) {
						vtun_syslog(LOG_ERR, "Could not send echo request 2 chan %d reason %s (%d)", i, strerror(errno), errno);
						break;
					}
					shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
					info.channel[i].up_len += len_ret;
				}
			}

            gettimeofday(&info.current_time, NULL);
            last_action = info.current_time.tv_sec;
            lfd_host->stat.comp_out += len;
    }

    free_timer(recv_n_loss_send_timer);

    sem_wait(&(shm_conn_info->AG_flags_sem));
    shm_conn_info->channels_mask &= ~(1 << info.process_num); // del channel num from binary mask
    shm_conn_info->need_to_exit &= ~(1 << info.process_num);
    shm_conn_info->hold_mask &= ~(1 << info.process_num); // set bin mask to zero (send not allowed)
    sem_post(&(shm_conn_info->AG_flags_sem));
#ifdef JSON
    vtun_syslog(LOG_INFO,"{\"name\":\"%s\",\"exit\":1}", lfd_host->host);
#endif

    vtun_syslog(LOG_INFO, "process_name - %s p_chan_num : %i,  exiting linker loop TERM=%i", lfd_host->host, info.process_num, linker_term);
    if( !linker_term && errno )
        vtun_syslog(LOG_INFO,"Reason: %s (%d)", strerror(errno), errno);

    if (linker_term == VTUN_SIG_TERM) {
        lfd_host->persist = 0;
    }
    if(channel_mode == MODE_NORMAL) { // may quit with different mode
        shm_conn_info->normal_senders--; // TODO HERE: add all possible checks for sudden deaths!!!
    }

    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].pid = 0;
    shm_conn_info->stats[info.process_num].weight = 0;
    shm_conn_info->stats[info.process_num].max_send_q = 0;
    shm_conn_info->stats[info.process_num].max_send_q_avg = 0;
    sem_post(&(shm_conn_info->stats_sem));

    /* Notify other end about our close */
    proto_write(service_channel, buf, VTUN_CONN_CLOSE);
    
    for (i = 0; i < info.channel_amount; i++) {
        close(info.channel[i].descriptor);
    }
    close(prio_s);

    if(linker_term == TERM_NONFATAL) linker_term = 0; // drop nonfatal flag

    /*struct sigaction sa;
    memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_sigaction;
    sa.sa_flags   = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    */
    if(buf != save_buf) {
        vtun_syslog(LOG_ERR,"ERROR: cannot free buf: CORRUPT!");
        lfd_free(save_buf);
    } else {
        lfd_free(buf);
    }
    if(save_out_buf != out_buf) {
        vtun_syslog(LOG_ERR,"ERROR: cannot free out_buf: CORRUPT!");
        lfd_free(save_out_buf);
    } else {
        lfd_free(out_buf);
    }
    free(js_buf);
    #ifdef SEND_Q_LOG
        free(jsSQ_buf);
    #endif

    /*memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = SIG_DFL;
    //sa.sa_flags   = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);*/

    return 0;
}

/**
 *
___________       __                    _____       
\_   _____/ _____/  |________ ___.__. _/ ____\____  
 |    __)_ /    \   __\_  __ <   |  | \   __\/    \ 
 |        \   |  \  |  |  | \/\___  |  |  | |   |  \
/_______  /___|  /__|  |__|   / ____|  |__| |___|  /
        \/     \/             \/                 \/

 *  Link remote and local file descriptors.
 *  We should initialize all global variable here if it possible.
 */
int linkfd(struct vtun_host *host, struct conn_info *ci, int ss, int physical_channel_num)
{
    shm_conn_info = ci;
    memset(last_sent_packet_num, 0, sizeof(struct last_sent_packet) * MAX_TCP_LOGICAL_CHANNELS);
    memset(&info, 0, sizeof(struct phisical_status));
    rxmt_mode_request = 0; // flag
    weight = 0; // bigger weight more time to wait(weight == penalty)
    weight_cnt = 0;
    acnt = 0; // assert variable

    closelog();
    char process_string[100];
    sprintf(process_string, "vtrunkd %s", host->host);
    vtun_syslog(LOG_ERR, "Change title with: %s", process_string);
    openlog(process_string, LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
    // these are for retransmit mode... to be removed
    retransmit_count = 0;
    channel_mode = MODE_NORMAL;
    hold_mode = 0; // 1 - hold 0 - normal
    force_hold_mode = 1;
    incomplete_seq_len = 0;
    rtt_shift=0;
    my_miss_packets_max = 0; // in ms; calculated here
    miss_packets_max = 0; // get from another side
    proto_err_cnt = 0;
    my_max_send_q_chan_num = 0;
    my_max_send_q = 0;
    max_reorder_byte = 0;
    last_channels_mask = 0;
    info.C = C_LOW;
    info.B = 0.2;
    /*Variables for the exact way of measuring speed*/
    send_q_read_timer = (struct timeval) {0, 0};
    send_q_read_drop_time = (struct timeval) {0, 100000};
    send_q_mode_switch_time = (struct timeval) {0, 0};
    ACK_coming_speed_avg = 0;
    send_q_limit = 7000;
    magic_rtt_avg = 0;

    /* Host we are working with.
     * Used by signal handlers that's why it is global.
     */

    lfd_mod_head = NULL;
    lfd_mod_tail = NULL;
    chan_info = NULL;
    info.max_send_q_max = 0;
    info.max_send_q_min = 120000;
    sem_wait(&shm_conn_info->common_sem);
    if (shm_conn_info->eff_len.sum == 0) {
        shm_conn_info->eff_len.sum = 1000;
    }
    sem_post(&shm_conn_info->common_sem);
    info.check_shm = 1;
    struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup, sa_oldusr1;
    int old_prio;
    /** Global initialization section for variable and another things*/

    lfd_host = host;
    info.srv = ss;
    info.pid = getpid();
    info.process_num = physical_channel_num;
    info.mode = R_MODE;
    if (info.srv) {
        info.channel_amount = 0; // first time for server, later server is getting it from client through net
    } else {
        info.channel_amount = lfd_host->TCP_CONN_AMOUNT + 1; // current here number of channels include service_channel
        info.channel = calloc(info.channel_amount, sizeof(*(info.channel)));
        if (info.channel == NULL) {
            vtun_syslog(LOG_ERR, "Cannot allocate memory for info.channel, process - %i, pid - %i",info.process_num, info.pid);
            return 0;
        }
        if (info.channel_amount > MAX_TCP_LOGICAL_CHANNELS) {
            vtun_syslog(LOG_ERR, "ASSERT! channel amount corrupt %i channels. Exit ", info.channel_amount);
            info.channel_amount = MAX_TCP_LOGICAL_CHANNELS;
            linker_term = TERM_NONFATAL;
            return 0;
        }
        chan_info = (struct channel_info *) calloc(info.channel_amount, sizeof(struct channel_info));
        if (chan_info == NULL ) {
            vtun_syslog(LOG_ERR, "Can't allocate array for struct chan_info for the linker");
            return 0;
        }
        info.channel[0].descriptor = host->rmt_fd; // service channel
        gettimeofday(&info.current_time, NULL );
        for (int i = 0; i < info.channel_amount; i++) {
            memcpy(&(info.channel[i].get_tcp_info_time_old), &info.current_time, sizeof(info.channel[i].get_tcp_info_time_old));
            memcpy(&(info.channel[i].send_q_time), &info.current_time, sizeof(info.channel[i].send_q_time));
        }
    }
    info.tun_device = host->loc_fd; // virtual tun device
    sem_wait(&(shm_conn_info->AG_flags_sem));
    shm_conn_info->channels_mask |= (1 << info.process_num); // add channel num to binary mask
    shm_conn_info->hold_mask |= (1 << info.process_num); // set bin mask to 1 (free send allowed)
    shm_conn_info->need_to_exit &= ~(1 << info.process_num);
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: new channel_mask %xx0 add channel - %u", shm_conn_info->channels_mask, info.process_num);
#endif
    sem_post(&(shm_conn_info->AG_flags_sem));

    /* Create pid directory if need */
    if (mkdir(LINKFD_PID_DIR, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
        if (errno == EEXIST) {
            vtun_syslog(LOG_INFO, "%s already  exists :)", LINKFD_PID_DIR);
        } else {
            vtun_syslog(LOG_ERR, "Can't create lock directory %s: %s (%d)", LINKFD_PID_DIR, strerror(errno), errno);
        }
    }

    /* Write my pid into file */
    char pid_file_str[200], pid_str[20];
    sprintf(pid_file_str, "%s/%s", LINKFD_PID_DIR, lfd_host->host);
    int pid_file_fd = open(pid_file_str, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (pid_file_fd < 0) {
        vtun_syslog(LOG_ERR, "Can't create temp lock file %s", pid_file_str);
    }
    int len = sprintf(pid_str, "%d\n", info.pid);
    if (write(pid_file_fd, pid_str, len) != len) {
        vtun_syslog(LOG_ERR, "Can't write PID %d to %s", info.pid, pid_file_str);
    }
    close(pid_file_fd);

    old_prio=getpriority(PRIO_PROCESS,0);
    setpriority(PRIO_PROCESS,0,LINKFD_PRIO);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_term;
    sigaction(SIGTERM,&sa,&sa_oldterm);
    sigaction(SIGINT,&sa,&sa_oldint);
    sa.sa_handler=sig_hup;
    sigaction(SIGHUP,&sa,&sa_oldhup);
    sa.sa_handler=sig_usr1;
    sigaction(SIGUSR1,&sa,&sa_oldusr1);

    //sa.sa_handler=sig_usr2;
    //sigaction(SIGUSR2,&sa,NULL);

    sa.sa_handler=sig_alarm;
    sigaction(SIGALRM,&sa,NULL);

    /* Initialize statstic dumps */
    if( host->flags & VTUN_STAT ) {
        char file[40];
        sprintf(file,"%s/%.20s", VTUN_STAT_DIR, host->host);
        if( (host->stat.file=fopen(file, "a")) ) {
            setvbuf(host->stat.file, NULL, _IOLBF, 0);
            //alarm(VTUN_STAT_IVAL);
        } else
            vtun_syslog(LOG_ERR, "Can't open stats file %s", file);
    }

    io_init();

    lfd_linker();

    io_init();

    remove(pid_file_str); // rm file with my pid
    free(info.channel);
    free(chan_info);

    if( host->flags & VTUN_STAT ) {
        alarm(0);
        if (host->stat.file)
            fclose(host->stat.file);
    }
    // I'm saying that I'm dead
    sem_wait(&(shm_conn_info->AG_flags_sem));
    uint32_t chan_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
    for (int i = 0; i < 32; i++) {
        if ((i == info.process_num) || (!(chan_mask & (1 << i)))) {
            continue;
        }
        sem_wait(&(shm_conn_info->stats_sem));
        pid_t pid = shm_conn_info->stats[i].pid;
        sem_post(&(shm_conn_info->stats_sem));
    }

    sigaction(SIGTERM,&sa_oldterm,NULL);
    sigaction(SIGINT,&sa_oldint,NULL);
    sigaction(SIGHUP,&sa_oldhup,NULL);
    sigaction(SIGUSR1,&sa_oldusr1,NULL);

    setpriority(PRIO_PROCESS,0,old_prio);

    return linker_term;
}
