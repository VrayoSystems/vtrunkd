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
 *

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
#include <sys/mman.h>
#ifdef PROF
#include <dlfcn.h>
#endif

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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#endif

#include "udp_states.h"
#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "log.h"
#include "driver.h"
#include "net_structs.h"
#include "netlib.h"
#include "netlink_socket_info.h"
#include "speed_algo.h"
#include "timer.h"
#include "pid.h"

#ifdef TESTING
#include "testing.h"
#endif

#include "packet_code.h"
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
#define SPEED_MINIMAL 100000.0 // 100kb/s minimal speed
#define SENQ_Q_LIMIT_THRESHOLD_MIN 13000 // the value with which that AG starts
//#define SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER 10 // send_q AG allowed threshold = RSR / SENQ_Q_LIMIT_THRESHOLD_MULTIPLIER
#define RATE_THRESHOLD_MULTIPLIER 5 // cut-off by speed only
#define RTT_THRESHOLD_MULTIPLIER 3 // cut-off by RTT only
#define RTT_THRESHOLD_GOOD 50 // cut-off by RTT ms
#define SEND_Q_EFF_WORK 10000 // value for send_q_eff to detect that channel is in use
#define ACS_NOT_IDLE 50000 // ~50pkts/sec ~= 20ms rtt2 accuracy
#define LOSS_SEND_Q_MAX 1000 // maximum send_q allowed is now 1000 (for head?)
#define LOSS_SEND_Q_UNKNOWN -1 // unknown value
#define MIN_SEND_Q_BESTGUESS_3G_PKT 150 // packets best-guess for 3G
// TODO: use mean send_q value for the following def
#define SEND_Q_AG_ALLOWED_THRESH 25000 // depends on RSR_TOP and chan speed. TODO: refine, Q: understand if we're using more B/W than 1 chan has?
//#define MAX_LATENCY_DROP { 0, 550000 }
#define MAX_NETWORK_STALL_MS 250 // 50ms maximum network stall
#define MAX_NETWORK_STALL { 0, MAX_NETWORK_STALL_MS*1000 } // 50ms maximum network stall
#define MAX_LATENCY_DROP_USEC 200000 // typ. is 204-250 upto 450 max RTO at CUBIC
#define MAX_LATENCY_DROP_SHIFT 100 // ms. to add to forced_rtt - or use above
//#define MAX_REORDER_LATENCY { 0, 50000 } // is rtt * 2 actually, default. ACTUALLY this should be in compliance with TCP RTO
#define MAX_REORDER_LATENCY_MAX 499999 // usec
#define MAX_REORDER_LATENCY_MIN 200 // usec
#define MAX_REORDER_PERPATH 8// was 4
// TODO HERE: TCP Model requried ---vvv
#define PLP_UNRECOVERABLE_CUTOFF 10000 // in theory about 50 mbit/s at 20ms  // was 1000 - 1000 is okay for like rtt 20ms but not for 100ms
#define PSL_RECOVERABLE 2 // we can recover this amount of loss
#define L_PBL_JOIN_EVENTS 50 // join all events within this PBL
#define DROPPING_LOSSING_DETECT_SECONDS 7 // seconds to pass after drop or loss to say we're not lossing or dropping anymore
//#define MAX_BYTE_DELIVERY_DIFF 100000 // what size of write buffer pumping is allowed? -> currently =RSR_TOP
#define SELECT_SLEEP_USEC 50000 // crucial for mean sqe calculation during idle
#define SUPERLOOP_MAX_LAG_USEC 5000 // 15ms max superloop lag allowed! // cpu lag
#define FCI_P_INTERVAL 3 // interval in packets to send ACK if ACK is not sent via payload packets
#define CUBIC_T_DIV 50
#define TMRTTA 25 // alpha coeff. for RFC6298 for tcp model rtt avg.
#define SKIP_SENDING_CLD_DIV 2
#define MSBL_PUSHDOWN_K 30
#define MSBL_PUSHUP_K 80
#define MAX_STUB_JITTER 1 // maximum packet jitter that we allow on buffer to happen
#define AGAG_MAX 255
#define SLOW_START_MAX_RUN {5, 500000} // max slow_start runtime after idle
#define SLOW_START_IMMUNE  {10, 100000} // no SS allowed within this period after previous SS
#define SLOW_START_INCINT 10 // amount of packets to increase MSBL by 1 after
#define TOKENBUF_ADD_BURST 7 // amount of tokens to wait before adding to reduce integer error in add_token

// PLOSS is a "probable loss" event: it occurs if PSL=1or2 for some amount of packets AND we detected probable loss (possible_seq_lost)
// this LOSS detect method uses the fact that we never push the network with 1 or 2 packets; we always push 5+ (TODO: make sure it is true!)
#define PLOSS_PSL 2 // this is '1or2'
#define PLOSS_CHECK_PKTS 15 // how many packets to check for sequential loss to detect PLOSS TODO: find correct value. speed dependent??

#define MAX_SD_W 1700 // stat buf max send_q (0..MAX_SD_W)
#define SD_PARITY 2 // stat buf len = MAX_SD_W / SD_PARITY
#define SLOPE_POINTS 30 // how many points ( / SD_PARITY ) to make linear fit from
#define ZERO_W_THR 2000.0 // ms. when to consider weight of point =0 (value outdated)
#define SPEED_REDETECT_TV {2,0} // timeval (interval) for chan speed redetect
#define HEAD_REDETECT_HYSTERESIS_TV {0,800000} // timeval (interval) for chan speed redetect
#define HEAD_HYSTERESIS_MIN_MS 800 // this replaced the above one
#define HEAD_TRANSITION_DELAY {0, 400}
#define SPEED_REDETECT_IMMUNE_SEC 5 // (interval seconds) before next auto-redetection can occur after PROTUP - added to above timer!

#define LIN_RTT_SLOWDOWN 70 // Grow rtt 40x slower than real-time
#define LIN_FORCE_RTT_GROW 0 // ms // TODO: need to find optimal value for required performance region
#define FORCE_RTT_JITTER_THRESH_MS 30 // ms of jitter to start growing rtt (subbing?)

#define DEAD_RTT 1500 // ms. RTT to consider chan dead
#define DEAD_RSR_USG 40 // %. RSR utilization to consider chan dead if ACS=0
#define DEAD_CHANNEL_RSR 40000 // fixed RSR for dead channel

#define RSR_SMOOTH_GRAN 10 // ms granularity
#define RSR_SMOOTH_FULL 500 // ms for full convergence
#define TRAIN_PKTS 80
#define WRITE_OUT_MAX 30 // write no more than 30 packets at once
//#define NOCONTROL
//#define NO_ACK

#define FAST_PCS_PACKETS_CAN_CALC_SPEED 200 // packets count to calculate PCS speed statistically correct
#define FAST_PCS_MINIMAL_INTERVAL 50 // ms minimal interval

#define RCVBUF_SIZE 1048576
#define WHO_LOST 1
#define WHO_LAGGING 2

// #define TIMEWARP

#ifdef TIMEWARP
    #define TW_MAX 10000000

    char *timewarp;
    int tw_cur;
#endif


#define PUSH_TO_TOP 2 // push Nth packet, 0 to disable


#define get_ds_ts(x) ((x.tv_sec - x.tv_sec / 10000000 * 10000000) * 100 + x.tv_usec / 10000)


#ifdef CPULAGCHK
    #define CHKCPU(x) gettimeofday(&cpulag_tmp, NULL);timersub(&cpulag_tmp, &old_time, &tv_tmp_tmp_tmp);if(tv_tmp_tmp_tmp.tv_usec > SUPERLOOP_MAX_LAG_USEC) vlog(LOG_ERR,"WARNING! CPU deficiency detected! Cycle lag: %ld.%06ld place %d", tv_tmp_tmp_tmp.tv_sec, tv_tmp_tmp_tmp.tv_usec, x);
    struct timeval cpulag_tmp;
#else
    #define CHKCPU {}
#endif

char lossLog[JS_MAX] = { 0 }; // for send_q compressor
int lossLog_cur = 0;

// flags:
uint8_t time_lag_ready;
int ptt_allow_once = 0; // allow to push-to-top single packet
int skip=0;
int forced_rtt_reached=1;
int select_check=0;

sigset_t block_mask, unblock_mask;

char rxmt_mode_request = 0; // flag
long int weight = 0; // bigger weight more time to wait(weight == penalty)
long int weight_cnt = 0;
int acnt = 0; // assert variable
char *out_buf;
uint16_t dirty_seq_num;
int sendbuff;
#define START_SQL 5000
struct udp_stats udp_struct[1];

int drop_packet_flag = 0, drop_counter=0;
int skip_write_flag = 0;
// these are for retransmit mode... to be removed
short retransmit_count = 0;
char channel_mode = MODE_NORMAL;
int hold_mode = 0; // 1 - hold 0 - normal
int force_hold_mode = 1;
int buf_len, incomplete_seq_len = 0;
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
char *buf2;
int buf_len_real=0;

int need_send_loss_FCI_flag = 0;
#define WB_1MS_SIZE 500
int wb_1ms[WB_1MS_SIZE] = { 0 };
int wb_1ms_idx = 2, start_print = 0;
char wb_1ms_str[5000] = { '\0' };

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
    int packet_sent_ag;
    int packet_sent_rmit;
    int byte_sent_ag_full;
    int byte_sent_rmit_full;
    int bytes_rcvd_norm;
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
    int tokens_max;
    int maw;
    int mar;
    int skip_new_h; // skipping and sending new as we are heading
    int skip_new_d; // skipping and sending new as we can deliver in time and we have no more packets
    int skip_r; // skipping as a result of all computations
    int skip_no; // skipping without sending
    int skip_l; // skipping by getting last packet
    int p_tooold;
    int p_expnum;
    int p_tooearly;
    int web_surf_optimization;
} statb;


struct {
    int expiration_ms_fromnow;
    int expnum;
} log_tmp;

struct {
    int v_min;
    int v_avg;
    int v_max;
} v_mma;


struct mini_path_desc
{
    int process_num;
    int rtt;
    int packets_between_loss;
};

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


//
//  Declarations.
//
int check_delivery_time_path_unsynced(int pnum, int mld_divider);
int check_delivery_time_unsynced(int mld_divider);
int check_rtt_latency_drop_chan(int chan_num);
int get_rto_usec();
int lost_buf_exists(uint32_t seq_num);
int plp_avg_pbl_unrecoverable(int pnum);




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

int frame_llist_getLostPacket_byRange(struct frame_llist *l, struct frame_llist *l_jw, struct frame_seq *flist, struct packet_sum *packet_sum) {
    int index = l_jw->rel_head;
    int prevIndex = -1;

    packet_sum->lostAmount = packet_sum->stop_seq - packet_sum->start_seq + 1;
#ifdef CODE_LOG
    vlog(LOG_INFO, "jwb %d wb %d",l_jw->length, l->length);
#endif
    uint32_t lostSeq = packet_sum->start_seq;

    //search lost packet in wb_just_write_frames
    while (index > -1) {
#ifdef CODE_LOG
        vlog(LOG_INFO, "jwb iterate idx %d lost amount %d seq_num %"PRIu32" lost seq %"PRIu32"", index, packet_sum->lostAmount, flist[index].seq_num, lostSeq);
#endif
        if ((flist[index].seq_num >= packet_sum->start_seq) && (flist[index].seq_num <= packet_sum->stop_seq)) {
            packet_sum->lostAmount--;
            if (lostSeq == flist[index].seq_num) {
                lostSeq++;
            }
        } else if (flist[index].seq_num > packet_sum->stop_seq) {
            return lostSeq;
        }
        index = flist[index].rel_next;
    }

    //search lost packet in write buf
    index = l->rel_head;
    while (index > -1) {
#ifdef CODE_LOG
        vlog(LOG_INFO, "wb iterate idx %d lost amount %d seq_num %"PRIu32" lost seq %"PRIu32"", index, packet_sum->lostAmount, flist[index].seq_num, lostSeq);
#endif
        if ((flist[index].seq_num >= packet_sum->start_seq) && (flist[index].seq_num <= packet_sum->stop_seq)) {
            packet_sum->lostAmount--;
            if (lostSeq == flist[index].seq_num) {
                lostSeq++;
            }
        } else if (flist[index].seq_num > packet_sum->stop_seq) {
            return lostSeq;
        }
        index = flist[index].rel_next;
    }
    return lostSeq;
}

int frame_llist_check_index_range(int index, int memory_size) {
    if ((index < 0) || (index >= memory_size)) {
        return 1;
    }
    return 0;
}



#define IF_WRITE_CONDITION timersub(&info.current_time, &shm_conn_info->frames_buf[shm_conn_info->write_buf[logical_channel].frames.rel_head].time_stamp, &packet_wait_tv); \
        timersub(&info.current_time, &shm_conn_info->write_buf[logical_channel].last_write_time, &since_write_tv); \
        forced_rtt_reached=check_tokens(logical_channel); \
        cond_flag = ((shm_conn_info->frames_buf[shm_conn_info->write_buf[logical_channel].frames.rel_head].seq_num == (shm_conn_info->write_buf[logical_channel].last_written_seq + 1))) ? 1 : 0; \
        buf_len = shm_conn_info->frames_buf[shm_conn_info->write_buf[logical_channel].frames.rel_tail].seq_num - shm_conn_info->write_buf[logical_channel].last_written_seq; \
        if ( shm_conn_info->is_single_channel \
             || (forced_rtt_reached && ( \
                        cond_flag \
                      || (buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) \
                      || timercmp(&packet_wait_tv, &((struct timeval) MAX_PACKET_WAIT), >=) \
                      || (    timercmp(&packet_wait_tv, &max_latency_drop, >=) \
                           && timercmp(&since_write_tv, &shm_conn_info->max_network_stall, >=) ) \
                      || (shm_conn_info->frames_buf[shm_conn_info->write_buf[logical_channel].frames.rel_head].seq_num < shm_conn_info->seq_num_unrecoverable_loss) \
                )) \
           )

int update_prev_flushed(int logical_channel, int fprev) {
    if(shm_conn_info->prev_flushed) {
        info.flush_sequential += 
            shm_conn_info->frames_buf[fprev].seq_num - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
    } else {
        // TODO: write avg stats here?
        info.flush_sequential = 
            shm_conn_info->frames_buf[fprev].seq_num - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
    }
    shm_conn_info->prev_flushed = 1;
}

// return who is lagging. 
// NOTE: Need to ensure that we have a missing packet at LWS+1 prior to calling this!
int flush_reason_chan(int status, int logical_channel, char *pname, int chan_mask, int *who_lost_pnum) {
    // we let that next seq_num to LWS is lost
    uint32_t lost_seq_num = shm_conn_info->write_buf[logical_channel].last_written_seq + 1;
    int lrq = 0;
    int lagging = 0;
    *who_lost_pnum = -1;
    // find possible processes
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if (chan_mask & (1 << i) && (!shm_conn_info->stats[i].channel_dead) && check_rtt_latency_drop_chan(i)) {
            if( (status == WHO_LAGGING) && ( (shm_conn_info->write_buf[logical_channel].last_received_seq[i]) < lost_seq_num)) {
                if( (shm_conn_info->write_buf[logical_channel].last_received_seq[i]) > lrq) { // we find the most recent one that fulfills the conditions
                    strcpy(pname, shm_conn_info->stats[i].name); 
                    *who_lost_pnum = i;
                    lrq = shm_conn_info->write_buf[logical_channel].last_received_seq[i];
                }
            }
            if( (status == WHO_LOST) && (lost_seq_num <= shm_conn_info->write_buf[logical_channel].possible_seq_lost[i])) {
                if(shm_conn_info->write_buf[logical_channel].possible_seq_lost[i] > lrq) {
                    strcpy(pname, shm_conn_info->stats[i].name); 
                    *who_lost_pnum = i;
                    lrq = shm_conn_info->write_buf[logical_channel].possible_seq_lost[i];
                }
            }

        }
    }
    // now count only
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if (chan_mask & (1 << i)) {
            if( (status == WHO_LAGGING) && ( (shm_conn_info->write_buf[logical_channel].last_received_seq[i]) < lost_seq_num)) {
                lagging++;
            }
            if( (status == WHO_LOST) && (lost_seq_num <= shm_conn_info->write_buf[logical_channel].possible_seq_lost[i])) {
                lagging++;
            }
        }
    }

    if(lagging == 0 && status == WHO_LOST) { // fixing WHO_LOST only
        // could not detect who lost directly(for example, no seq_num has arrived yet on lossing chan [loss detected by FCI]), doing 'possible' mode
        pname[0]='L';
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if (chan_mask & (1 << i)) {
                if( (status == WHO_LOST) && shm_conn_info->write_buf[logical_channel].packet_lost_state[i]) {
                    strcpy(pname+1, shm_conn_info->stats[i].name);
                    *who_lost_pnum = i;
                    lagging++;
                }
            }
        }
    }
    
    if(lagging == 0 && status == WHO_LOST) { // fixing WHO_LOST only
        // now find last one who lost by possible_seq_lost
        pname[0]='p';
        unsigned int highest_psl = 0;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if (chan_mask & (1 << i)) {
                if(shm_conn_info->write_buf[logical_channel].possible_seq_lost[i] > highest_psl) {
                    highest_psl = shm_conn_info->write_buf[logical_channel].possible_seq_lost[i];
                    strcpy(pname+1, shm_conn_info->stats[i].name);
                    *who_lost_pnum = i;
                    lagging++;
                }
            }
        }
    }

    return lagging;
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
    //vlog(LOG_INFO, "Get sig_term");
    //vlog(LOG_ERR, "Closing connection");
    io_cancel();
    linker_term = VTUN_SIG_TERM;
}

static void sig_hup(int sig)
{
    vlog(LOG_INFO, "Get sig_hup");
    vlog(LOG_INFO, "Reestablishing connection");
    io_cancel();
    linker_term = VTUN_SIG_HUP;
}

static void sig_usr1(int sig)
{
    if(!select_check) {
        vlog(LOG_ERR, "ASSERT FAILED! SIGUSR1 not in select region!");
    }
    //vlog(LOG_INFO, "Get sig_usr1, check_shm UP");
    //info.check_shm = 1;
}

void sig_send1() {
    uint32_t chan_mask = shm_conn_info->channels_mask;
    pid_t pid;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((i == info.process_num) || (!(chan_mask & (1 << i)))) {
            continue;
        }
        sem_wait(&(shm_conn_info->stats_sem));
        pid = shm_conn_info->stats[i].pid;
        sem_post(&(shm_conn_info->stats_sem));
        if (pid != 0 && shm_conn_info->max_chan == i && shm_conn_info->stats[i].hold) {
            vlog(LOG_INFO, "Sending signal to unhold HEAD");
            kill(pid, SIGUSR1);
        }
    }
}

/**
 * колличество отставших пакетов
 * buf[] - номера пакетов
 */
int missing_resend_buffer (int chan_num, uint32_t buf[], int *buf_len, uint32_t seq_limit) {
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
        vlog(LOG_ERR, "WARNING: frame difference too high: last w seq: %"PRIu32" fbhead: %"PRIu32" . FIXED. chs %d<->%d lws cn %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->write_buf[chan_num].frames_buf[i].seq_num, chs, lws, chan_num);
        shm_conn_info->write_buf[chan_num].last_written_seq = shm_conn_info->frames_buf[i].seq_num-1;
    }

    // fix for diff btw start
    for(k=1; k<(shm_conn_info->frames_buf[i].seq_num - shm_conn_info->write_buf[chan_num].last_written_seq); k++) {
        buf[idx] = shm_conn_info->write_buf[chan_num].last_written_seq + k;
        idx++;
        //vlog(LOG_INFO, "MRB: found in start : tot %d", idx);
        if(idx >= FRAME_BUF_SIZE) {
            vlog(LOG_ERR, "WARNING: MRB2 frame difference too high: last w seq: %"PRIu32" fbhead: %"PRIu32" . FIXED. chs %d<->%d lws ch %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->frames_buf[i].seq_num, chs, lws, chan_num);
            shm_conn_info->write_buf[chan_num].last_written_seq = shm_conn_info->frames_buf[i].seq_num-1;
            idx=0;
            break;
        }
    }
    while(i > -1) {
        n = shm_conn_info->frames_buf[i].rel_next;
        //vlog(LOG_INFO, "MRB: scan1");
        if( n > -1 ) {

            isq = shm_conn_info->frames_buf[i].seq_num;
            nsq = shm_conn_info->frames_buf[n].seq_num;
            if(nsq > seq_limit) {
                break;
            }
            //vlog(LOG_INFO, "MRB: scan2 %"PRIu32" > %"PRIu32" +1 ?", nsq, isq);
            if(nsq > (isq+1)) {
                //vlog(LOG_INFO, "MRB: scan2 yes!");
                for(k=1; k<=(nsq-(isq+1)); k++) {
                    if(idx >= FRAME_BUF_SIZE) {
                        vlog(LOG_ERR, "WARNING: frame seq_num diff in write_buf > FRAME_BUF_SIZE");
                        *buf_len = blen;
                        return idx;
                    }

                    buf[idx] = isq+k;
                    idx++;
                    //vlog(LOG_INFO, "MRB: found in middle : tot %d", idx);
                }
            }
        }
        i = n;
        blen++;
    }
    //vlog(LOG_INFO, "missing_resend_buf called and returning %d %d ", idx, blen);
    *buf_len = blen;
    return idx;
}

int discard_packets(int chan_num, uint32_t stop_sqn) {
    int fprev = shm_conn_info->write_buf[chan_num].frames.rel_head;
    uint32_t sqn = shm_conn_info->frames_buf[fprev].seq_num;
    int idx = fprev;
    int n_idx, cnt=0;
    while(sqn < stop_sqn) {
        // now jsut discard the packet
        cnt++;
        vlog(LOG_INFO, "Discarding seq_num %ld cnt %d", sqn, cnt);
        shm_conn_info->w_stream_pkts[shm_conn_info->frames_buf[idx].shash % W_STREAMS_AMT]--;
        n_idx = shm_conn_info->frames_buf[idx].rel_next;
        if(frame_llist_pull(&shm_conn_info->write_buf[chan_num].frames, shm_conn_info->frames_buf, &idx) < 0) {
            vlog(LOG_ERR, "WARNING! discard_packets tried to pull from empty write_buf 2!");
            return -1;
        }
        frame_llist_append(&shm_conn_info->wb_free_frames, idx, shm_conn_info->frames_buf);
        idx = n_idx;
        if(idx == -1) {
            vlog(LOG_ERR, "ASSERT FAILED: discard_packets did not find stop_sqn in buffer! %ld", stop_sqn);
            return -2;
        }
        sqn = shm_conn_info->frames_buf[idx].seq_num;
    }
    return 0;
}


/**
 * get how many percent to push every 50ms
 * 
 */
 
int calculate_hsqs_percents(int max, int percent_fill) {
    return max * percent_fill * percent_fill * percent_fill / 100000;
}

/*
 * count amount of packets lost sequentially and evenly
 *
 * return -1 if packets loss is uneven (like 0 1 1 0 0 1 1 1) or in any other case we will need to wait
 * or return amount of packets lost
 * TODO: can be optimized by using stored buf_len counter and not running this until buf_len reaches PLOSS_CHECK_PKTS
 *
 */
int count_sequential_loss_unsync(int chan_num) {
    int i = shm_conn_info->write_buf[chan_num].frames.rel_head, n;
    int isq, nsq;
    int beg_lost = 0;
    int packets_checked = 0;

    // count lost at beginning
    beg_lost = shm_conn_info->frames_buf[i].seq_num - shm_conn_info->write_buf[chan_num].last_written_seq-1;

    if(beg_lost > PLOSS_PSL) return beg_lost; // optimization: no need to calculate further as we already lost too much
    
    if(beg_lost == 0) {
        vlog(LOG_ERR, "ASSERT FAILED! beg_lost == 0: should never happen; invoke with packet loss only!");
    }
    // now count losses over N packets
    while((i > -1) && (packets_checked < PLOSS_CHECK_PKTS)) {
        n = shm_conn_info->frames_buf[i].rel_next;
        if( n > -1 ) {
            isq = shm_conn_info->frames_buf[i].seq_num;
            nsq = shm_conn_info->frames_buf[n].seq_num;
            if(nsq > (isq+1)) {
                return -1; // means loss not sequential; need to wait further
            }
        }
        i = n;
        packets_checked++;
    }

    if( packets_checked < PLOSS_CHECK_PKTS ) { // we assume that we've been invoked with at least one packet missing
        return -1; // this means packets lost AND checked is not enough to make decision yet
        // need to wait further..
    }

    return beg_lost; // now all checks done, return what we've got
}

int fire_event(int *ecount) {
    (*ecount)++;
    shm_conn_info->event_mask |= (1 << info.process_num); // warning! some events may not be fired immediately as we may race here
    sem_post(&(shm_conn_info->event_sem));
}
    

int get_wb_oldest_ts_unsync(struct timeval *min_tv) {
    int i = shm_conn_info->write_buf[1].frames.rel_head, n;
    int packets_checked = 0;
    *min_tv = info.current_time;

    while((i > -1) && (packets_checked < 100)) {
        n = shm_conn_info->frames_buf[i].rel_next;
        if( n > -1  && timercmp(&shm_conn_info->frames_buf[n].time_stamp, min_tv, <)) {
            *min_tv = shm_conn_info->frames_buf[n].time_stamp;
        }
        i = n;
        packets_checked++;
    }

    return 0;
}

/* check if we are allowed to drop packet again  */
int check_drop_period_unsync() {
    struct timeval tv_tm, tv_rtt;
    timersub(&info.current_time, &shm_conn_info->drop_time, &tv_tm);
    //ms2tv(&tv_rtt, shm_conn_info->stats[info.process_num].exact_rtt);
    ms2tv(&tv_rtt, DROP_TIME_IMMUNE/1000); // TODO: unnessessary calculation
    if(timercmp(&tv_tm, &tv_rtt, >=)) {
        //vlog(LOG_ERR, "Last drop passed: %d ms > rtt %d ms", tv2ms(&tv_tm), tv2ms(&tv_rtt));
        return 1;
    }
    // else
    return 0;
}

/* Check if the packet sent right now will be delivered in time */
int check_delivery_time(int mld_divider) {
    // RTT-only for now..
    //    struct timeval max_latency_drop = MAX_LATENCY_DROP;
    if(info.head_channel) return 1; // this is required! beware when refactoring!
    sem_wait(&(shm_conn_info->stats_sem));
    int ret = check_delivery_time_unsynced(mld_divider);
    sem_post(&(shm_conn_info->stats_sem));
    return ret;
}

// this method is crutial as it controls AG/R_MODE operation while in R_MODE
int check_delivery_time_unsynced(int mld_divider) {
    return check_delivery_time_path_unsynced(info.process_num, mld_divider);
}

int check_delivery_time_path_unsynced(int pnum, int mld_divider) {
    struct timeval max_latency_drop = info.max_latency_drop;
    // check for dead channel
    if(shm_conn_info->stats[pnum].channel_dead && (shm_conn_info->max_chan != pnum)) {
        // vlog(LOG_ERR, "WARNING check_delivery_time DEAD and not HEAD"); // TODO: out-once this!
        return 0;
    }
    // TODO: re-think this!
    if( ( (info.rsr < info.send_q_limit_threshold) || (info.send_q_limit_cubic < info.send_q_limit_threshold)) && (shm_conn_info->max_chan != pnum)) {
        vlog(LOG_INFO, "WARNING check_delivery_time RSR %d < THR || CUBIC %d < THR=%d", info.rsr, (int32_t)info.send_q_limit_cubic, info.send_q_limit_threshold);
        return 0;
    }
    if( ((shm_conn_info->stats[pnum].exact_rtt + shm_conn_info->stats[pnum].rttvar) - shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt) > ((int32_t)(tv2ms(&max_latency_drop)/mld_divider + shm_conn_info->forced_rtt)) ) {
        // no way to deliver in time
        //vlog(LOG_ERR, "WARNING check_delivery_time %d + %d - %d > %d + %d", shm_conn_info->stats[pnum].exact_rtt,  shm_conn_info->stats[pnum].rttvar, shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt, (int32_t)(tv2ms(&max_latency_drop)/mld_divider), shm_conn_info->forced_rtt);
        return 0;
    }
    //vlog(LOG_ERR, "CDT OK");
    return 1;
}

int check_rtt_latency_drop() { // TODO: remove this dumb method (refactor some code)
    return check_rtt_latency_drop_chan(info.process_num);
}

/*
    This method allows AG or disallows AG based on latency
*/
int check_rtt_latency_drop_chan(int chan_num) {
    struct timeval max_latency_drop = info.max_latency_drop;
    if(shm_conn_info->stats[chan_num].channel_dead && (shm_conn_info->max_chan != chan_num)) {
        return 0;
    }
    
    if(shm_conn_info->stats[chan_num].exact_rtt < RTT_THRESHOLD_GOOD) {
        return 1;
    }
    
    //int my_rtt = (int)(shm_conn_info->stats[chan_num].exact_rtt + shm_conn_info->stats[chan_num].rttvar);
    //int min_rtt = (int)shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt;
    
    
    if(shm_conn_info->max_allowed_rtt != 0) {
        if(info.exact_rtt > (shm_conn_info->max_allowed_rtt + shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt)) {
            return 0;
        }
    } else {
        //if(my_rtt > min_rtt * RTT_THRESHOLD_MULTIPLIER) {
            return 0;
        //}
    }
    
    return 1;
}

    
static inline int add_tokens(int chan_num, int *next_token_ms) {
    //shm_conn_info->tokens_in_out = 0;
    //int tokens_in_out = 0;
    // TODO: may be sync on write_buf is required??
    if(shm_conn_info->tokens < 0) {
        shm_conn_info->tokens = 0;
    }
    if(chan_num != 1) {
        return 1; // for all other chans (e.g. 0-service channel) return drop allowed
    }
    int ms_for_token = 1; 
    //int full_rtt = ((shm_conn_info->forced_rtt_recv > shm_conn_info->frtt_local_applied) ? shm_conn_info->forced_rtt_recv : shm_conn_info->frtt_local_applied);
    //int tail_idx = shm_conn_info->write_buf[chan_num].frames.rel_tail;
    //int buf_len = shm_conn_info->frames_buf[tail_idx].seq_num - shm_conn_info->write_buf[chan_num].last_written_seq;
    //int buf_len = shm_conn_info->write_buf[chan_num].last_received_seq[shm_conn_info->remote_head_pnum] - shm_conn_info->write_buf[chan_num].last_written_seq;
    //int tokens_above_thresh = shm_conn_info->tokenbuf - MAX_STUB_JITTER;
    //if(tokens_above_thresh < 0) tokens_above_thresh = 0;
    int buf_len_real = shm_conn_info->write_buf[chan_num].frames.length + shm_conn_info->write_buf[chan_num].frames.stub_total;
    //buf_len = buf_len_real; 
    //struct timeval packet_dtv;
    //int BPCS = 0;
    //int head_idx = shm_conn_info->write_buf[chan_num].frames.rel_head;
    //struct timeval packet_wait_tv;

    /*
    int pktdiff = buf_len_real; // current diff is just the real buf_len
    // now check rtt
    timersub(&info.current_time, &shm_conn_info->frames_buf[head_idx].time_stamp, &packet_wait_tv);

    // detect stuck condition
    // stuck means that we are not allowed to drop due to packet not available
    // whenever we have no packet to drop - we are stuck - even if it is not the time to drop yet
    
    int max_total_rtt = (shm_conn_info->total_max_rtt+shm_conn_info->total_max_rtt_var) - (shm_conn_info->total_min_rtt - shm_conn_info->total_min_rtt_var); 
    if (shm_conn_info->frames_buf[shm_conn_info->write_buf[chan_num].frames.rel_head].seq_num
            != (shm_conn_info->write_buf[chan_num].last_written_seq + 1)) {
        int packet_lag = tv2ms(&packet_wait_tv);
        // TODO: unused as this method resulted to failure
        // we should rather use this info to continue to smoothly push up the value
        //if(shm_conn_info->max_stuck_rtt < packet_lag && packet_lag < max_total_rtt){
        //    shm_conn_info->max_stuck_rtt = packet_lag;
        //}
        //if(shm_conn_info->max_stuck_buf_len < pktdiff) shm_conn_info->max_stuck_buf_len = pktdiff;
    }
    */
        
    //int pktdiff = shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_tail].seq_num - shm_conn_info->write_buf[i].last_written_seq;
    //int packet_rtt = tv2ms(&packet_wait_tv) + shm_conn_info->frames_buf[head_idx].current_rtt;
    /*
    if(packet_rtt < shm_conn_info->max_stuck_rtt) {
        shm_conn_info->tokens = 0;
        if(shm_conn_info->max_stuck_buf_len < pktdiff) shm_conn_info->max_stuck_buf_len = pktdiff; // TODO: use unconditoinal set or not??
        *next_token_ms = shm_conn_info->max_stuck_rtt - packet_rtt;
        return 0;
    }
    */
    //int max_msbl = max_msrt_mul * rtt_min * smooth_ACPS;
    // TOP the MSBL TODO: move out of HERE 
    int max_msbl = MSBL_LIMIT;
    if(shm_conn_info->max_stuck_buf_len > max_msbl) {
        shm_conn_info->max_stuck_buf_len = max_msbl;
    }
    /*
    if(buf_len_real >= 10) {
        timersub(&shm_conn_info->frames_buf[tail_idx].time_stamp, &shm_conn_info->frames_buf[head_idx].time_stamp, &packet_dtv);
        int pdms = tv2ms(&packet_dtv);
        if(pdms > 50) { // TODO: is it required??
            BPCS = buf_len_real * 1000 / pdms;
            shm_conn_info->write_speed_b = BPCS;
        }
    }
    */
    
    int APCS = shm_conn_info->APCS * 8 / 10; // 0.7 of APCS to add to tokenbuf
    
    // now do add some tokens ?
    
    struct timeval passed_tv;
    timersub(&info.current_time, &shm_conn_info->tokens_lastadd_tv, &passed_tv);
    int ms_passed = tv2ms(&passed_tv);
    int tokens_to_add = APCS * ms_passed / 1000;
    // if(buf_len_real > 0 && tokens_to_add > TOKENBUF_ADD_BURST) {
    //     shm_conn_info->tokens_lastadd_tv = info.current_time;
    //     shm_conn_info->tokenbuf += tokens_to_add;
    // }
    if(buf_len_real == 0) {
        shm_conn_info->tokens_lastadd_tv = info.current_time;
    } else if (tokens_to_add > TOKENBUF_ADD_BURST) { // TODO: prevent too high jitter by limiting available tokens?
        shm_conn_info->tokens += tokens_to_add;
        shm_conn_info->tokens_lastadd_tv = info.current_time;
    } // else wait ...
    // if(shm_conn_info->tokenbuf - MAX_STUB_JITTER > shm_conn_info->max_stuck_buf_len) { // no need for tokenbuf larger than MSBL
    //     shm_conn_info->tokenbuf = shm_conn_info->max_stuck_buf_len + MAX_STUB_JITTER;
    // }
    
    if(shm_conn_info->max_stuck_buf_len > TOKENS_MAXWAIT && shm_conn_info->tokens > shm_conn_info->max_stuck_buf_len) {
    // if(shm_conn_info->tokens > shm_conn_info->max_stuck_buf_len) { // no need for tokenbuf larger than MSBL
        shm_conn_info->tokens = shm_conn_info->max_stuck_buf_len;
    }
 
    // if(shm_conn_info->slow_start_recv) {
    //     ms_for_token = 1;
    //     *next_token_ms = 1;
    // }
    if(shm_conn_info->tokens > 0) {
        // no need to set ms_for_token as get_write_buf_wait_data will shoot anyways
        return 1;
    } else {
        //if(!shm_conn_info->slow_start_recv) {
        if(APCS == 0) { // i=n caseof ss
            ms_for_token = 50; // ms before packet drop? (zero speed)
        } else {
            ms_for_token = 1000 / APCS * TOKENBUF_ADD_BURST;
        }
        //}
        if(ms_for_token < 1) ms_for_token = 1; // TODO: is this correct?
        *next_token_ms = ms_for_token;
        return 0;
    }
}

int check_tokens(int chan_num) {
    if(shm_conn_info->avg_len_in <= AVG_LEN_IN_ACK_THRESH) {
        shm_conn_info->max_stuck_buf_len = 0;
        statb.web_surf_optimization |= 1;
        return 1; 
    }
    // if(shm_conn_info->slow_start_recv) {
    //     return 1; // the hope that this will actually help gain back ss
    //     //struct timeval since_write_tv;
    //     //timersub(&info.current_time, &shm_conn_info->write_buf[chan_num].last_write_time, &since_write_tv);
    //     //if(since_write_tv.tv_usec < 1000) {
    //     //    return 0;
    //     //}
    // }
        
    if(shm_conn_info->tokens > 0) return 1;
    int tokens_above_thresh = shm_conn_info->tokenbuf - MAX_STUB_JITTER;
    if(tokens_above_thresh < 0) tokens_above_thresh = 0;
    int buf_len_real = shm_conn_info->write_buf[chan_num].frames.length + shm_conn_info->write_buf[chan_num].frames.stub_total + tokens_above_thresh;
    if(buf_len_real > shm_conn_info->max_stuck_buf_len) { // support for flushing packets w/o packets coming in
        return 1;
    }
    int head_idx = shm_conn_info->write_buf[chan_num].frames.rel_head;
    if(shm_conn_info->frames_buf[head_idx].len < 100) { // flush ACK immediately
        return 1;
    }
    return 0; 
}

int DL_flag_drop_allowed_unsync_stats(uint32_t chan_mask) {
    // calculate if ag-send speed is greater than one of the channels self speed. 
    // Return 0 if greater, 1 otherwise (allowed to drop)
    int ag_speed_total = 0;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
            ag_speed_total += shm_conn_info->stats[i].packet_speed_ag;
        }
    }
    // now dubl 2
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
            if( (ag_speed_total < shm_conn_info->stats[i].ACK_speed/info.eff_len) && !percent_delta_equal(ag_speed_total, shm_conn_info->stats[i].ACK_speed/info.eff_len, 10) ) {
                //vlog(LOG_INFO, "Allowing to drop flag: as we can send everything thru one chan: total: %d, chan %d ACS: %d", ag_speed_total, i, shm_conn_info->stats[i].ACK_speed);
                return 1; // allow to drop AG flag as we can send everything thru one chan
            }
        }
    }
    return 0;
}

int get_write_buf_wait_data(uint32_t chan_mask, int *next_token_ms) {
    // TODO WARNING: is it synchronized? stats_sem! write_buf sem!? TODO! bug #189
    //struct timeval max_latency_drop = MAX_LATENCY_DROP;
    // TODO WARNING i do not know why we are still checking packets if we see no rel_head
    
    int buf_latency_ms;
    int buf_len;
    int cond_flag;
    struct timeval max_latency_drop;
    int rtou = get_rto_usec();
    max_latency_drop.tv_sec = rtou / 1000000;
    max_latency_drop.tv_usec = rtou % 1000000;
    struct timeval tv_tmp;
    int head_lrx = 0, seq_loss = 0;
    struct timeval packet_wait_tv, since_write_tv;
    info.ploss_event_flag = 0; // TODO: remove ploss event check
    int logical_channel = 1; // warning! fixed stream/channel here for IF_WRITE_CONDITION
    for (int i = 1; i < info.channel_amount; i++) { // chan 0 is service only
    #ifdef FRTTDBG
                vlog(LOG_INFO, "get_write_buf_wait_data(), for chan: %d", i);
    #endif
        info.least_rx_seq[i] = UINT32_MAX;
        timersub(   
                    &shm_conn_info->write_buf[i].last_write_time,
                    &shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].time_stamp, 
                    &packet_wait_tv);
        buf_latency_ms = tv2ms(&packet_wait_tv);
        if(buf_latency_ms < 0) buf_latency_ms = 0;
        /*
        seq_loss = 0;
        if(shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].seq_num > (shm_conn_info->write_buf[i].last_written_seq + 1)){
            // means we're waiting for packet. Now check if it is lost!
            // TODO: optimize here by checking buf_len >= PLOSS_CHECK_PKTS before doing this check!
            seq_loss = count_sequential_loss_unsync(i); 
            if(seq_loss > 0 && seq_loss < PLOSS_PSL) {
                // means we detected PLOSS event
                //seq_loss = 1; // re-use variable
                // TODO rewrite this if
                info.ploss_event_flag = 1;
            } else {
                seq_loss = 0;
                info.ploss_event_flag = 0;
            }
        }
        */
        for(int p=0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
            if (chan_mask & (1 << p)) {
                if((head_lrx < shm_conn_info->write_buf[i].last_received_seq[p]) && (shm_conn_info->stats[p].remote_head_channel)) { // TODO: two heads possible?
                    head_lrx = shm_conn_info->write_buf[i].last_received_seq[p];
                }
                if(seq_loss && (shm_conn_info->write_buf[i].possible_seq_lost[p] > (shm_conn_info->write_buf[i].last_written_seq + seq_loss)) 
                && (shm_conn_info->write_buf[i].possible_seq_lost[p] < (shm_conn_info->write_buf[i].last_written_seq + PLOSS_CHECK_PKTS))) {
                    // means we received a local loss with this global seq
                    // and write buf says it is likely a loss
                    // TODO: we have a slight chance of doing this by mistake
                    //.    think how to deal with.. UPDATE: it is already dealt with by writing late packets
                    // TODO TODO: NOT JUST BIGGER SEQ NUM BUT SOME RANGE TO DETECT WITHIN
                    info.least_rx_seq[i] = shm_conn_info->write_buf[i].last_received_seq[p];
                } else {
                    if(    shm_conn_info->stats[p].channel_dead 
                       //|| ((shm_conn_info->stats[p].exact_rtt - shm_conn_info->stats[shm_conn_info->remote_head_pnum].exact_rtt) > (buf_latency_ms + (MAX_LATENCY_DROP_USEC / 1000)))
                       ) { // do not wait for late packet only if drtt is > MLD or DEAD
                    //        || ((shm_conn_info->stats[p].recv_mode == 0)
                    //        && timercmp(&info.current_time, &shm_conn_info->stats[p].agoff_immunity_tv, >=))
                    //  ) { 
                        // vlog(LOG_ERR, "get_write_buf_wait_data(), detected dead channel dead %d, p %d - ertt %d rhd %d - ertt %d, blm %d mld %d",
                        //                 shm_conn_info->stats[p].channel_dead, p, shm_conn_info->stats[p].exact_rtt, shm_conn_info->remote_head_pnum, shm_conn_info->stats[shm_conn_info->remote_head_pnum].exact_rtt, buf_latency_ms, (MAX_LATENCY_DROP_USEC / 1000));
                        continue;
                    }
                    if (shm_conn_info->write_buf[i].last_received_seq[p] < info.least_rx_seq[i]) {
                        info.least_rx_seq[i] = shm_conn_info->write_buf[i].last_received_seq[p];
                    }
                }
            }
        }
        if(info.least_rx_seq[i] == UINT32_MAX) { // we did not find any alive channel. Just consider any LRX
            //vlog(LOG_ERR, "Warning! Could not detect any alive chan; using head_lrx !");
            info.least_rx_seq[i] = head_lrx; // do not detect any loss if head is unknown?
            //info.least_rx_seq[i] = 0; // do not detect any loss
            // init least_rx_seq with max value of current chans
            /* // TODO for #395
            for(int p=0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
                if ((chan_mask & (1 << p)) && (!shm_conn_info->stats[p].channel_dead)) {
                    if (shm_conn_info->write_buf[i].last_received_seq[p] > info.least_rx_seq[i]) {
                        info.least_rx_seq[i] = shm_conn_info->write_buf[i].last_received_seq[p];
                    }
                }
            }
            */
        }
        if (shm_conn_info->write_buf[i].frames.rel_head != -1) {
            // check if we can write these packets
            IF_WRITE_CONDITION 
            {
                return 1;
            }
        } else {
            if(shm_conn_info->write_buf[i].frames.length != 0) {
                // vlog(LOG_ERR, "ASSERT FAILED: get_write_buf_wait_data() detected length incosistency %d should be 0.", shm_conn_info->write_buf[i].frames.length);
                //shm_conn_info->write_buf[i].frames.length = 0; // fix if it becomes broken for any reason
            }
        }
    }
    if(shm_conn_info->tokens > TOKENS_MAXWAIT) shm_conn_info->tokens = TOKENS_MAXWAIT; // zero tokens and retry again...
    // shm_conn_info->tokens = 0; // needed to ensure that we only have tokens when we can write
    return 0;
}


// get next frame that need to be sent
// it is either the seq_num referenced as input argument (usually last_sent+1)
// or oldest non-expired seq_num frame
int get_resend_frame(int chan_num, uint32_t *seq_num, char **out, int *sender_pid) {
    int i, j, len = -1;
    int top_seq_num = shm_conn_info->seq_counter[chan_num];
    struct timeval expiration_date;
    struct timeval continuum_date = info.current_time;
    struct timeval max_latency;
    struct timeval min_latency;
    struct timeval hold_period;
    int expnum = 0;

    int mrl_ms, drtt_ms, expiration_ms_fromnow;

    drtt_ms = shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt;
    // TODO what time is the expiration time? MLD diff or MAR?
    //mrl_ms = MAX_LATENCY_DROP_USEC / 1000 / 2;
    //mrl_ms = shm_conn_info->stats[shm_conn_info->max_chan].rttvar;
    mrl_ms = 100; // 20 ms lag // should be zero
    expiration_ms_fromnow = mrl_ms - drtt_ms; // we're OK to be late up to MLD? ms, but we're already drtt ms late!
    if(expiration_ms_fromnow < 0) { 
        //vlog(LOG_INFO, "get_resend_frame can't get packets: expiration_ms_fromnow < 0: %d", expiration_ms_fromnow);
        return -1; // we can get no frames; handle this above
    }
    ms2tv(&max_latency, expiration_ms_fromnow);
    timersub(&info.current_time, &max_latency, &expiration_date);
   
    // I am commenting-out this block as we are OBLIGED to deliver packets ASAP in R_MODE (as in AG_MODE, too)
    // we should take care of MLDs caused by too fast packets at receiver side
    //if(drtt_ms < 0) {  // need to set expiration date
    //    ms2tv(&min_latency, (-drtt_ms)); // we are not allowed to be any faster unlike in 'later' scenario
    //    timersub(&info.current_time, &min_latency, &continuum_date);
    //}
   
    //find start point
    j = shm_conn_info->resend_buf_idx - 1 < 0 ? RESEND_BUF_SIZE - 1 : shm_conn_info->resend_buf_idx - 1; // correct: the idx is incremented AFTER write
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
//        vlog(LOG_INFO, "look for %"PRIu32" start point step - j %i chan_num %i seq_num %"PRIu32" ",*seq_num, j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            break;
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }

    // now find expiration type II - not too old (by num) to be still able to send up to top within MLD
    timersub(&info.current_time, &info.hold_time, &hold_period);
    if((hold_period.tv_sec * 1000 + hold_period.tv_usec / 1000) <= info.exact_rtt) { // if we have been pressed lately, we have topped our real speed
        // TODO: need info.ACK_speed_correct flag
        // this will work just because hold is not likely to kick in before ACS is recalculated
        expnum = (mrl_ms - drtt_ms) * (shm_conn_info->stats[info.process_num].ACK_speed / info.eff_len) / 1000; // send them all to top within MLD!
    }
    log_tmp.expiration_ms_fromnow = expiration_ms_fromnow;
    log_tmp.expnum = expnum;
    
    // clamp to high end, clamp to low end AND respect seq_num that we want - otherwise return oldest that we can afford
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {// TODO need to reduce search depth 100 200 1000 ??????
//                vlog(LOG_INFO, "j %i chan_num %i seq_num %"PRIu32" ", j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if ((shm_conn_info->resend_frames_buf[j].chan_num == chan_num) && (shm_conn_info->resend_frames_buf[j].len != 0)) {
            if( shm_conn_info->resend_frames_buf[j].seq_num = *seq_num ) { // AND is the one we're seeking for
                if(!timercmp(&expiration_date, &shm_conn_info->resend_frames_buf[j].time_stamp, <)) { // packet is not too old
                    statb.p_tooold++;
                }
                if( !((top_seq_num - shm_conn_info->resend_frames_buf[j].seq_num) < expnum ))  { 
                  // AND we can send it and all of the rest to top in MLD time in case of DDS
                    statb.p_expnum++;
                }
                if(!timercmp(&continuum_date, &shm_conn_info->resend_frames_buf[j].time_stamp, >=))  { // AND packet is not too early
                  statb.p_tooearly++;
                }
            }
            if (   
                      timercmp(&expiration_date, &shm_conn_info->resend_frames_buf[j].time_stamp, <) // packet is not too old
                      && ( (top_seq_num - shm_conn_info->resend_frames_buf[j].seq_num) < expnum ) // AND we can send it and all of the rest to top in MLD time in case of DDS
                      && timercmp(&continuum_date, &shm_conn_info->resend_frames_buf[j].time_stamp, >=) // AND packet is not too early
                      && ( shm_conn_info->resend_frames_buf[j].seq_num = *seq_num ) // AND is the one we're seeking for
            ) {
                *seq_num = shm_conn_info->resend_frames_buf[j].seq_num;
                len = shm_conn_info->resend_frames_buf[j].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j].sender_pid;
//                vlog(LOG_INFO, "previous j %i chan_num %i seq_num %"PRIu32" ", j_previous, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j_previous].seq_num );
                return len;
            } 
            if( (timercmp(&expiration_date, &shm_conn_info->resend_frames_buf[j].time_stamp, >=) // packet is too old, return it
                    || ( (top_seq_num - shm_conn_info->resend_frames_buf[j].seq_num) >= expnum )) // or the packet is the one from which later on we cannot send in MLD all to top
                    && timercmp(&continuum_date, &shm_conn_info->resend_frames_buf[j].time_stamp, >=) ) { // AND packet is still not too early
                *seq_num = shm_conn_info->resend_frames_buf[j].seq_num;
                len = shm_conn_info->resend_frames_buf[j].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j].sender_pid;
                return len;
            }
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }
    // last packet could only be possible in case of uninitailized buffer (at start)
    
    vlog(LOG_INFO, "WARNING: get_resend_frame can't get packets: expiration_ms_fromnow= %d, expnum=%d", expiration_ms_fromnow, expnum);
    return -1;// means we have not found the most recent frame in resend_buf
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
//                vlog(LOG_INFO, "j %i chan_num %i seq_num %"PRIu32" ", j, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j].seq_num);
        if ((shm_conn_info->resend_frames_buf[j].chan_num == chan_num) || (shm_conn_info->resend_frames_buf[j].chan_num == 0)) {
            if (shm_conn_info->resend_frames_buf[j].seq_num == *seq_num) {
                j_previous = j;
                *seq_num = shm_conn_info->resend_frames_buf[j_previous].seq_num;
                len = shm_conn_info->resend_frames_buf[j_previous].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j_previous].sender_pid;
//                vlog(LOG_INFO, "bottom ret j %i chan_num %i seq_num %"PRIu32" ", j_previous, shm_conn_info->resend_frames_buf[j].chan_num, shm_conn_info->resend_frames_buf[j_previous].seq_num );
                return len;
            } else {
                j_previous = j;
            }
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }

    return len;
}

// the same GRF but no expiration
int get_resend_frame_local_sqn(int chan_num, int process_num, uint32_t local_seq_num, uint32_t *seq_num, char **out, int *sender_pid, int *idx) {
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
        if ((shm_conn_info->resend_frames_buf[j].chan_num == chan_num) || (shm_conn_info->resend_frames_buf[j].chan_num == 0)) {
            if (shm_conn_info->resend_frames_buf[j].local_seq_num[process_num] == local_seq_num) {
                j_previous = j;
                *seq_num = shm_conn_info->resend_frames_buf[j_previous].seq_num;
                len = shm_conn_info->resend_frames_buf[j_previous].len;
                *((uint16_t *) (shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
                *out = shm_conn_info->resend_frames_buf[j_previous].out + LINKFD_FRAME_RESERV;
                *sender_pid = shm_conn_info->resend_frames_buf[j_previous].sender_pid;
                *idx = j_previous;
                return len;
            } else {
                j_previous = j;
            }
        }
        j--;
        if (j == -1) {
            j = RESEND_BUF_SIZE - 1;
        }
    }

    return len;
}

int is_priority_packet(char *buf) {
    struct my_ip *ip;
    ip = (struct my_ip*) (buf);
    if (ip->ip_p == 1) { // ICMP
        return 1;
    }
    if(ip->ip_p == 6 && getTcpSeq(buf) == 0) {
        return 1;
    }
    return 0;
}

unsigned int get_l4_hash(char *buf, unsigned int *tcp_seq) {
    struct my_ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    ip = (struct my_ip*) (buf);
    unsigned int hash = (unsigned int) (ip->ip_src.s_addr);
    hash += (unsigned int) (ip->ip_dst.s_addr);
    hash += ip->ip_p;
    // WARNING: do we have to ntohl() here #856?
    if (ip->ip_p == 6) { // TCP...
        tcp = (struct tcphdr*) (buf + sizeof(struct my_ip));
        hash += tcp->source;
        hash += tcp->dest;
        *tcp_seq = ntohl(tcp->seq);
    }
    if (ip->ip_p == 17) { // UDP...
        udp = (struct udphdr*) (buf + sizeof(struct my_ip));
        hash += udp->source;
        hash += udp->dest;
    }
    if (ip->ip_p == 1) { // ICMP
        struct icmphdr *icmp = (struct icmphdr*) (buf + sizeof(struct my_ip));
        hash += icmp->un.echo.id;
    }
    
    return hash;
}

// cycle resend buffer from top down to old to get any packet
int get_last_packet_seq_num(int chan_num, uint32_t *seq_num) {
    int j = shm_conn_info->resend_buf_idx-1;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {
        if ( (shm_conn_info->resend_frames_buf[j].chan_num == chan_num)
         && (shm_conn_info->resend_frames_buf[j].len != 0)) {
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
    // there are two cases: we are unable to send packets either because they are too late or too early(which is unlikely) so we will be sending most early
    int j = get_last_packet_seq_num(chan_num, seq_num);
    if(j == -1) return -1;
    int len = shm_conn_info->resend_frames_buf[j].len;
    *((uint16_t *) (shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV+ (len+sizeof(uint32_t)))) = (uint16_t)htons(chan_num +FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
    *out = shm_conn_info->resend_frames_buf[j].out + LINKFD_FRAME_RESERV;
    *sender_pid = shm_conn_info->resend_frames_buf[j].sender_pid;
    return len;
}

int seqn_break_tail(char *out, int len, uint32_t *seq_num, uint16_t *flag_var, uint32_t *local_seq_num, uint16_t *mini_sum, uint32_t *last_recv_lsn, uint32_t *packet_recv_spd) {
    uint32_t local_seq_num_n, last_recv_lsn_n, packet_recv_spd_n;
    if (*flag_var == FRAME_REDUNDANCY_CODE) {
        memcpy(&local_seq_num_n, out + len - (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t)), sizeof(uint32_t));
        memcpy(&last_recv_lsn_n, out + len - (sizeof(uint32_t) + sizeof(uint32_t)), sizeof(uint32_t));
        memcpy(&packet_recv_spd_n, out + len - sizeof(uint32_t), sizeof(uint32_t));
        *local_seq_num = ntohl(local_seq_num_n);
        *last_recv_lsn = ntohl(last_recv_lsn_n);
        *packet_recv_spd = ntohl(packet_recv_spd_n);
        return len - (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t));
    }
    *seq_num = ntohl(*((uint32_t *) (&out[len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t)
                        - sizeof(uint32_t)])));
    *flag_var = ntohs(*((uint16_t *) (&out[len - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t)])));
    *local_seq_num = ntohl(*((uint32_t *) (&out[len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t)])));
    *mini_sum = ntohs(*((uint16_t *) (&out[len - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t)])));
    *last_recv_lsn = ntohl(*((uint32_t *) (&out[len - sizeof(uint32_t) - sizeof(uint32_t)])));
    *packet_recv_spd = ntohl(*((uint32_t *) (&out[len - sizeof(uint32_t)])));
    return len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t);
}

/**
 * Function for add flag and seq_num to packet
 */
int pack_packet(int chan_num, char *buf, int len, uint32_t seq_num, uint32_t local_seq_num, int flag) {
    uint16_t flag_n = htons(flag);
    
    uint32_t local_seq_num_n = htonl(local_seq_num);
    uint16_t mini_sum = htons((uint16_t)(seq_num + local_seq_num + info.channel[chan_num].local_seq_num_recv));
    uint32_t last_recv_lsn = htonl(info.channel[chan_num].local_seq_num_recv);
    uint32_t packet_recv_spd = htonl(info.channel[chan_num].packet_download);
    if (flag == FRAME_REDUNDANCY_CODE) {
        memcpy(buf + len, &local_seq_num_n, sizeof(uint32_t));
        memcpy(buf + len + sizeof(uint32_t), &last_recv_lsn, sizeof(uint32_t));
        memcpy(buf + len + sizeof(uint32_t) + sizeof(uint32_t), &packet_recv_spd, sizeof(uint32_t));
//        memcpy(buf + len + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t), &mini_sum, sizeof(uint16_t));
        return len + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
    }
    uint32_t seq_num_n = htonl(seq_num);
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
int seqn_add_tail(int conn_num, char *buf, int len, uint32_t seq_num, uint16_t flag, int sender_pid) {
    int newf = shm_conn_info->resend_buf_idx;

    shm_conn_info->resend_buf_idx++;
    if (shm_conn_info->resend_buf_idx == RESEND_BUF_SIZE) {
#ifdef DEBUGG
        vlog(LOG_INFO, "seqn_add_tail() resend_frames_buf loop end");
#endif
        shm_conn_info->resend_buf_idx = 0;
    }

    shm_conn_info->resend_frames_buf[newf].seq_num = seq_num;
    memset(shm_conn_info->resend_frames_buf[newf].local_seq_num, 0, sizeof(shm_conn_info->resend_frames_buf[newf].local_seq_num));
    shm_conn_info->resend_frames_buf[newf].sender_pid = sender_pid;
    shm_conn_info->resend_frames_buf[newf].chan_num = conn_num;
    shm_conn_info->resend_frames_buf[newf].len = len;
    gettimeofday(&info.current_time, NULL );
    shm_conn_info->resend_frames_buf[newf].time_stamp = info.current_time;
    memcpy((shm_conn_info->resend_frames_buf[newf].out + LINKFD_FRAME_RESERV), buf, len);
    return newf;
}

/**
 * Add packet to fast resend buffer
 *
 * @param conn_num
 * @param buf - pointer to packet
 * @return -1 - error if buffer full and packet's quantity if success
 */
int add_fast_resend_frame(int conn_num, char *buf, int len, uint32_t seq_num) {
    if (shm_conn_info->fast_resend_buf_idx >= FAST_RESEND_BUF_SIZE) {
        return -1; // fast_resend_buf is full
    }
    int i = shm_conn_info->fast_resend_buf_idx; // get next free index
    ++(shm_conn_info->fast_resend_buf_idx);
    uint16_t flag = MODE_NORMAL;
    shm_conn_info->fast_resend_buf[i].seq_num = seq_num;
    shm_conn_info->fast_resend_buf[i].sender_pid = 0;
    shm_conn_info->fast_resend_buf[i].chan_num = conn_num;
    shm_conn_info->fast_resend_buf[i].len = len;

    memcpy(shm_conn_info->fast_resend_buf[i].out, buf, len & VTUN_FSIZE_MASK);
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
    if (!check_fast_resend()) {
        return -1; // buffer is blank
    }
    int i = --(shm_conn_info->fast_resend_buf_idx);
    memcpy(buf, shm_conn_info->fast_resend_buf[i].out, shm_conn_info->fast_resend_buf[i].len & VTUN_FSIZE_MASK);
    *conn_num = shm_conn_info->fast_resend_buf[i].chan_num;
    *seq_num = shm_conn_info->fast_resend_buf[i].seq_num;
    *len = shm_conn_info->fast_resend_buf[i].len;
    return i+1;
}

void print_head_of_packet(char *buf, char* str, uint32_t seq_num, int len) {
    char packet_string[500];
    memset(packet_string, '\0', 500);
    sprintf(packet_string, "len %i seq_num %"PRIu32": ", len, seq_num);
    char* str_point = packet_string + strlen(packet_string);
    int i = 0;
    for (; ((i < 60) && (i < len)); i++) {
        sprintf(str_point, "%02X-", (uint8_t) buf[i]);
        str_point += sizeof(buf[i]) + 2;
    }
    *(str_point - 1) = '\0';
    if (i <= len)
        vlog(LOG_INFO, "%s %s", str, packet_string);
    else
        vlog(LOG_INFO, "%s %s...", str, packet_string);
}

/**
 *
 * @return 0 if buffer blank
 */
int check_fast_resend() {
    if (shm_conn_info->fast_resend_buf_idx == 0) {
        return 0; // buffer is blank
    }
    if((info.process_num == shm_conn_info->max_rtt_pnum_checkonly) && is_priority_packet(shm_conn_info->fast_resend_buf[shm_conn_info->fast_resend_buf_idx-1].out)) {
        return 0;
    }
    return 1;
}

int is_fast_resend_available() {
    if (shm_conn_info->fast_resend_buf_idx >= FAST_RESEND_BUF_SIZE) {
        return 0; // fast_resend_buf is full
    }
    return 1;
}

int is_single() {
    if(NumberOfSetBits(shm_conn_info->channels_mask) == 1) {
        return 1;
    }
    return 0;
}

int send_packet(int chan_num, char *buf, int len) {
     
    // TODO: add select() here!
    // TODO: optimize here
    uint32_t tmp_seq_counter;
    uint32_t local_seq_num_p;
    uint16_t tmp_flag = 0;
    uint16_t sum;
    len = seqn_break_tail(buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
    len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, tmp_flag);
    
    // send DATA
    int len_ret = udp_write(info.channel[chan_num].descriptor, buf, len);
    if (len && (len_ret < 0)) {
        vlog(LOG_INFO, "error retransmit to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
        return BREAK_ERROR;
    }
    info.channel[chan_num].local_seq_num++;
    // TODO: all the stats here??
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
int retransmit_send(char *out2) {
    if (drop_packet_flag) {
        return LASTPACKETMY_NOTIFY; // go dropping
    } else if (drop_counter > 0) {
        // vlog(LOG_INFO, "drop_packet_flag (retransmit_send) TOTAL %d pkts; info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d", drop_counter, info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel, shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg);
        // drop_counter = 0;
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
           vlog(LOG_INFO, "debug: retransmit_send skipping logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
            // TODO MOVE THE FOLLOWING LINE TO DEBUG! --vvv
            if (top_seq_num < last_sent_packet_num[i].seq_num) vlog(LOG_INFO, "WARNING! impossible: chan#%i last sent seq_num %"PRIu32" is > top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
            // WARNING! disabled push-to-top policy!
            if(PUSH_TO_TOP && ptt_allow_once && ((!info.head_channel) && (shm_conn_info->dropping || shm_conn_info->head_lossing))) {
                last_sent_packet_num[i].seq_num--; // push to top! (push policy)
                get_unconditional = 1;
                ptt_allow_once = 0;
            } else {
                if(check_delivery_time(SKIP_SENDING_CLD_DIV) && (!shm_conn_info->slow_start || info.head_channel)) { // TODO: head always passes! 
                    statb.skip_new_h++;
                    continue; // means that we have sent everything from rxmit buf and are ready to send new packet: no send_counter increase
                }
                // else means that we need to send something old
                //vlog(LOG_ERR, "WARNING cannot send new packets as we won't deliver in time; skip sending"); // TODO: add skip counter
                send_counter++;
                statb.skip_no++;
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
            statb.skip_no++;
            continue; // continuing w/o reading/sending pkts AND send_counter++ will cause to fast-loop; we effectively do a poll here
        } else if (sel_ret == -1) {
            vlog(LOG_ERR, "retransmit send Could not select chan %d reason %s (%d)", i, strerror(errno), errno);
        }
        // now we have something to retransmit:

        last_sent_packet_num[i].seq_num++;
        seq_num_tmp = last_sent_packet_num[i].seq_num; // save old seq_num for test

#ifdef DEBUGG
            vlog(LOG_INFO, "debug: logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
        sem_wait(&(shm_conn_info->resend_buf_sem));
        if(info.head_channel == 1) {
            // on head channel, do not allow to skip even if we see outdated packets?
            len = get_resend_frame_unconditional(i, &last_sent_packet_num[i].seq_num, &out2, &mypid); // TODO: is it correct?
            if (len == -1) {
                if (check_delivery_time(1)) { // TODO: head channel will always pass this test
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vlog(LOG_INFO, "WARNING no packets found in RB on head_channel and we can deliver new in time; sending new");
                    statb.skip_new_d++;
                    continue; // ok to send new packet
                } 
                len = get_last_packet(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
                vlog(LOG_INFO, "WARNING all RB packets expired on head_channel!!! & can not deliver new packet in time; getting newest packet from RB... seq_num %"PRIu32" top %d", last_sent_packet_num[i].seq_num, top_seq_num);
                if(len == -1) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vlog(LOG_INFO, "WARNING no packets found in RB; HEAD sending new");
                    statb.skip_new_d++;
                    continue;
                }
            }
        } else {
            // this is required to not read new packets if being pushed to top and all packets exhausted ->>>
            //if(get_unconditional) len = get_resend_frame_unconditional(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
            //else                  
            len = get_resend_frame(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
            if (len == -1) {
                last_sent_packet_num[i].seq_num--;
                if (check_delivery_time(2)  && !shm_conn_info->slow_start) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    // TODO: disable AG in case of this event!
                    vlog(LOG_INFO, "WARNING all packets in RB are sent AND we can deliver new in time; sending new");
                    statb.skip_new_d++;
                    continue; // ok to send new packet
                } 
                // else there is no way we can deliver anything in time; now get latest packet
                len = get_last_packet(i, &last_sent_packet_num[i].seq_num, &out2, &mypid);
                // TODO: counter here -->
                //vlog(LOG_ERR, "WARNING all RB packets expired & can not deliver new packet in time; getting newest packet from RB... seq_num %"PRIu32" top %d", last_sent_packet_num[i].seq_num, top_seq_num);
                if(len == -1) {
                    sem_post(&(shm_conn_info->resend_buf_sem));
                    vlog(LOG_INFO, "WARNING no packets found in RB; hd==0 sending new!!!");
                    statb.skip_new_d++;
                    continue;
                }
                statb.skip_l++;
            }
        }
        if(last_sent_packet_num[i].seq_num != seq_num_tmp) {
            if(info.head_channel == 1) {
                vlog(LOG_INFO, "WARNING retransmit_send on head channel skippig seq's from %"PRIu32" to %"PRIu32" chan %d len %d", seq_num_tmp, last_sent_packet_num[i].seq_num, i, len);
            }
            statb.skip_r++;
        }
        memcpy(out_buf, out2, len);
        sem_post(&(shm_conn_info->resend_buf_sem));

#ifdef DEBUGG
        vlog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, length);
#endif
        if(debug_trace) {
            vlog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, len);
        }

        
        // TODO: add select here!
        // TODO: optimize here
        uint32_t tmp_seq_counter;
        uint32_t local_seq_num_p;
        uint16_t tmp_flag = 0;
        uint16_t sum;
        len = seqn_break_tail(out_buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
        len = pack_packet(i, out_buf, len, tmp_seq_counter, info.channel[i].local_seq_num, tmp_flag);
        // if( (info.rtt2_lsn[i] == 0) && ((shm_conn_info->stats[info.process_num].ACK_speed /info.eff_len) > (1000/shm_conn_info->stats[info.process_num].exact_rtt)) ) {
        if(info.rtt2_lsn[i] == 0) {
            info.rtt2_lsn[i] = info.channel[i].local_seq_num;
            info.rtt2_tv[i] = info.current_time;
            info.rtt2_send_q[i] = info.channel[i].send_q;
        }
        // send DATA
        int len_ret = udp_write(info.channel[i].descriptor, out_buf, len);
        info.channel[i].packet_recv_counter = 0;
        if (len && (len_ret < 0)) {
            vlog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", i, strerror(errno), errno);
            return BREAK_ERROR;
        }
        info.channel[i].local_seq_num++;
        if(PUSH_TO_TOP && (info.channel[i].local_seq_num % PUSH_TO_TOP == 0)) {
            ptt_allow_once = 1;
        }
    
        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
        statb.packet_sent_rmit += 1000;
        if(shm_conn_info->stats[info.process_num].l_pbl_tmp < INT32_MAX)
            shm_conn_info->stats[info.process_num].l_pbl_tmp++;
        if(shm_conn_info->stats[info.process_num].l_pbl_tmp_unrec < INT32_MAX)
            shm_conn_info->stats[info.process_num].l_pbl_tmp_unrec++;
        info.channel[i].up_len += len_ret;
        statb.byte_sent_rmit_full += len_ret;
        info.channel[i].up_packets++;
        info.channel[i].bytes_put++;
//if(drop_packet_flag) {  vlog(LOG_INFO, "bytes_pass++ retransmit_send"); } 
        info.byte_r_mode += len_ret;

        send_counter++;
    }
    
    if (send_counter == 0) {
        if (check_delivery_time(1)) { // TODO: REMOVE THIS EXTRA CHECK (debug only; should never happen due to previous checks)
            return LASTPACKETMY_NOTIFY;
        } else {
            vlog(LOG_ERR, "WARNING STILL can not deliver new packet in time; skipping read from tun");
            return CONTINUE_ERROR;
        }
    }
        
    return 1;
}

/**
 * calculate total send_q_eff_mean
 * 
 */
 
int get_total_sqe_mean_pkt(int *aavg, int *lim_pkt, int ignore_msqa) {
    int sqe_tot = 0;
    int sqe_pkt;
    *aavg = 1;
    uint32_t chan_mask = shm_conn_info->channels_mask;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        // waring: ag_mask depends only on ag_flag_local, not on agag value so it may not be correct
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask & (1 << i))) { // hope this works..
            sqe_pkt = shm_conn_info->stats[i].sqe_mean / info.eff_len;
            sqe_tot += sqe_pkt;
            if(shm_conn_info->stats[i].W_cubic < shm_conn_info->stats[i].rsr) {
                if(!ignore_msqa && shm_conn_info->stats[i].max_send_q_available < shm_conn_info->stats[i].W_cubic) {
                    *lim_pkt += shm_conn_info->stats[i].max_send_q_available / info.eff_len;
                } else {
                    *lim_pkt += shm_conn_info->stats[i].W_cubic / info.eff_len;
                }
            } else {
                if(!ignore_msqa && shm_conn_info->stats[i].max_send_q_available < shm_conn_info->stats[i].rsr) {
                    *lim_pkt += shm_conn_info->stats[i].max_send_q_available / info.eff_len;
                } else {
                    *lim_pkt += shm_conn_info->stats[i].rsr / info.eff_len;
                }
            }
            if(sqe_pkt > 0) {
                *aavg += shm_conn_info->stats[i].ACK_speed_avg / sqe_pkt;
            }
        }
    }
    return sqe_tot;
}

/**
 * check that the system is in a-hold mode
 * 
 */
 
int is_a_hold() {
    int limit;
    int sqe;
    uint32_t chan_mask = shm_conn_info->channels_mask;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        // this does not work - see ag_mask_recv and mode
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask & (1 << i))) { // hope this works..
            limit = shm_conn_info->stats[i].W_cubic < shm_conn_info->stats[i].rsr ? shm_conn_info->stats[i].W_cubic : shm_conn_info->stats[i].rsr;
            sqe = shm_conn_info->stats[i].sqe_mean;
            if( percent_delta_equal(sqe, limit, 15) || (sqe > limit) ) {
                // means hold
            } else {
                return 0;
            }
        }
    }
    return 1;
}

    

int select_net_write(int chan_num) {
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
        vlog(LOG_ERR, "select_net_write() select error! errno %d",errno);
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
    if(hold_mode) return TRYWAIT_NOTIFY; // no send in HOLD
    int len, len_sum, select_ret, idx;
    uint32_t tmp_seq_counter = 0;
    int chan_num;
    struct timeval tv;
    int new_packet = 0;
    fd_set fdset_tun;
    int packet_code_ready = 0;
    int current_selection;
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
                vlog(LOG_INFO, "debug: Nothing to read from tun device (first FD_ISSET)");
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
                vlog(LOG_INFO, "select error; exit");
                return BREAK_ERROR;
            } else {
                sem_post(&(shm_conn_info->tun_device_sem));
#ifdef DEBUGG
                vlog(LOG_INFO, "select error; continue norm");
#endif
                return CONTINUE_ERROR;
            }
        } else if (select_ret == 0) {
            sem_post(&(shm_conn_info->tun_device_sem));
#ifdef DEBUGG
            vlog(LOG_INFO, "debug: we don't have data on tun device; continue norm.");
#endif
            return CONTINUE_ERROR; // Nothing to read, continue.
        }
#ifdef DEBUGG
        vlog(LOG_INFO, "debug: we have data on tun device...");
#endif
        if (FD_ISSET(info.tun_device, &fdset_tun)) {
        } else {
            sem_post(&(shm_conn_info->tun_device_sem));
            return CONTINUE_ERROR;
        }
        // we aren't checking FD_ISSET because we did select one descriptor
        len = dev_read(info.tun_device, buf, VTUN_FRAME_SIZE - 11);
        sem_post(&(shm_conn_info->tun_device_sem));
        // TODO WARNING! packet reordering will happen here: we lost sync before seq_counter incremented -->>>

        if (len < 0) { // 10 bytes for seq number (long? = 4 bytes)
            if (errno != EAGAIN && errno != EINTR) {
                vlog(LOG_INFO, "sem_post! dev read err");
                return BREAK_ERROR;
            } else { // non fatal error
#ifdef DEBUGG
            vlog(LOG_INFO, "sem_post! else dev read err"); // usually means non-blocking zeroing
#endif
                return CONTINUE_ERROR;
            }
        } else if (len == 0) {
#ifdef DEBUGG
            vlog(LOG_INFO, "sem_post! dev_read() have read nothing");
#endif
            return CONTINUE_ERROR;
        }
        shm_conn_info->avg_len_out = EFF_LEN_AVG_N * shm_conn_info->avg_len_out / EFF_LEN_AVG_D + len / EFF_LEN_AVG_D;

        if (drop_packet_flag == 1) {
            // #876
            drop_counter++;
//#ifdef DEBUGG
            int other_chan = 0;
            if (info.process_num == 0)
                other_chan = 1;
            else
                other_chan = 0;
            info.dropping = 1;
            //if (debug_trace) {
                vlog(LOG_INFO, "drop_packet_flag info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d, hold_!head: %d",
                        info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel,
                        shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg,
                        shm_conn_info->stats[other_chan].hold);
                //info.max_send_q = 0;
            //}

            sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            sem_post(&(shm_conn_info->AG_flags_sem));

            // set dropped_flag here

            /*
             for (int p = 0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
             if (chan_mask & (1 << p)) {
             vlog(LOG_INFO, "pnum %d, w %d, rtt %d, wspd %d", p, shm_conn_info->stats[p].W_cubic, shm_conn_info->stats[p].rtt_phys_avg, (shm_conn_info->stats[p].W_cubic / shm_conn_info->stats[p].rtt_phys_avg));
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
             // introduce immunity timer here
            
            sem_wait(&(shm_conn_info->stats_sem));
            if(check_drop_period_unsync()) {
            sem_post(&(shm_conn_info->stats_sem));
                shm_conn_info->drop_time = info.current_time;
                return CONTINUE_ERROR;
            } 
            sem_post(&(shm_conn_info->stats_sem));
        } else {
            if (drop_counter > 0) {
                // vlog(LOG_INFO, "drop_packet_flag TOTAL %d pkts; info.rsr %d info.W %d, max_send_q %d, send_q_eff %d, head %d, w %d, rtt %d",
                //         drop_counter, info.rsr, info.send_q_limit_cubic, info.max_send_q, send_q_eff, info.head_channel,
                //         shm_conn_info->stats[info.process_num].W_cubic, shm_conn_info->stats[info.process_num].rtt_phys_avg);
                // drop_counter = 0;
            }
        }

#ifdef DEBUGG
        vlog(LOG_INFO, "debug: we have read data from tun device and going to send it through net");
#endif

        // now determine packet IP..
        // unsigned int tcp_seq2 = 0;
        // unsigned int hash = get_l4_hash(buf, &tcp_seq2);
        // chan_num = (hash % (info.channel_amount - 1)) + 1; // send thru 1-n channel
        chan_num = 1;
        // info.encap_streams_bitcnt |= (1 << (hash % 31)); // set bin mask to 1 
        // if (shm_conn_info->streams[hash % 31] < 255)
        //     shm_conn_info->streams[hash % 31]++; // WARNING unsync but seems okay
        sem_wait(&(shm_conn_info->common_sem));
        if(shm_conn_info->ag_mask_recv & (1 << info.process_num)) {
            shm_conn_info->t_model_rtt100 = ((TMRTTA - 1) * shm_conn_info->t_model_rtt100 + info.exact_rtt * 100) / TMRTTA; // RFC6298 compliant
        }
        (shm_conn_info->seq_counter[chan_num])++;
        tmp_seq_counter = shm_conn_info->seq_counter[chan_num];

        // packet code section
#ifdef SUM_SEND
#ifdef CODE_LOG
        print_head_of_packet(buf, "add to sum ", tmp_seq_counter, len);
        vlog(LOG_INFO, "FRAME_REDUNDANCY_CODE check seq_counter %"PRIu32"", tmp_seq_counter);
#endif

        current_selection = (tmp_seq_counter - (SEQ_START_VAL + 1)) % SELECTION_NUM;

        if (tmp_seq_counter == SEQ_START_VAL + 1) {
            struct timeval redund_code_timer_time = REDUNDANT_CODE_TIMER_TIME;
            for (int i = 0; i < SELECTION_NUM; i++) {
                sum_init(&shm_conn_info->packet_code[i][chan_num], tmp_seq_counter + i, tmp_seq_counter + REDUNDANCY_CODE_LAG - SELECTION_NUM + i, i,
                        1500);
                set_timer(&shm_conn_info->packet_code[i][chan_num].timer, &redund_code_timer_time);
            }
            add_packet_code(buf, &shm_conn_info->packet_code[current_selection][chan_num], len);
            shm_conn_info->packet_code[current_selection][chan_num].current_seq = tmp_seq_counter;
        } else if (shm_conn_info->packet_code[current_selection][chan_num].stop_seq > tmp_seq_counter) {
            add_packet_code(buf, &shm_conn_info->packet_code[current_selection][chan_num], len);
        } else if (shm_conn_info->packet_code[current_selection][chan_num].stop_seq == tmp_seq_counter) {
            add_packet_code(buf, &shm_conn_info->packet_code[current_selection][chan_num], len);
            packet_code_ready = 1;
        }
        shm_conn_info->packet_code[current_selection][chan_num].current_seq = tmp_seq_counter;
#endif
        len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, channel_mode);
#ifdef SUM_SEND
        if (packet_code_ready) {
            len_sum = pack_redundancy_packet_code(buf2, &shm_conn_info->packet_code[current_selection][chan_num], tmp_seq_counter, current_selection,
                    FRAME_REDUNDANCY_CODE);
            fast_update_timer(&shm_conn_info->packet_code[current_selection][chan_num].timer, &info.current_time);
            sem_post(&(shm_conn_info->common_sem));
        } else {
            sem_post(&(shm_conn_info->common_sem));
        }
#else
        sem_post(&(shm_conn_info->common_sem));
#endif

        new_packet = 1;
#ifdef DEBUGG
        vlog(LOG_INFO, "local_seq_num %"PRIu32" seq_num %"PRIu32" len %d", info.channel[chan_num].local_seq_num, tmp_seq_counter, length);
#endif
    } else {
#ifdef DEBUGG
        vlog(LOG_INFO, "we have fast resend frame sending...");
#endif
    }
#ifdef DEBUGG
    else {
        vlog(LOG_INFO, "Trying to send from fast resend buf chan_num - %i, len - %i, seq - %"PRIu32", packet amount - %i", chan_num, length, tmp_seq_counter, idx);
    }
#endif

    FD_ZERO(&fdset_tun);
    FD_SET(info.channel[chan_num].descriptor, &fdset_tun);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    select_ret = select(info.channel[chan_num].descriptor + 1, NULL, &fdset_tun, NULL, &tv);
#ifdef DEBUGG
    vlog(LOG_INFO, "Trying to select descriptor %i channel %d", info.channel[chan_num].descriptor, chan_num);
#endif
    if ((select_ret != 1) || ((info.process_num == shm_conn_info->max_rtt_pnum_checkonly) && is_priority_packet(buf) && is_fast_resend_available())) {
        sem_wait(&(shm_conn_info->resend_buf_sem));
        idx = add_fast_resend_frame(chan_num, buf, len, tmp_seq_counter); // fast_resend technique is used for info.channel_amount > 1
        sem_post(&(shm_conn_info->resend_buf_sem));
        //if(new_packet) {
        //    info.channel[chan_num].local_seq_num--; // send next time... another pkt will have this lsn soon!
        //}
        if (idx == -1) {
            vlog(LOG_ERR, "ERROR: fast_resend_buf is full");
        }
#ifdef DEBUGG
        vlog(LOG_INFO, "BUSY - descriptor %i channel %d");
#endif
        return NET_WRITE_BUSY_NOTIFY;
    }
#ifdef DEBUGG
    vlog(LOG_INFO, "READY - descriptor %i channel %d");
#endif
    int resend_frame_idx = -1;
    if (tmp_seq_counter) {
        sem_wait(&(shm_conn_info->resend_buf_sem));
        resend_frame_idx = seqn_add_tail(chan_num, buf, len, tmp_seq_counter, channel_mode, info.pid);
        sem_post(&(shm_conn_info->resend_buf_sem));

#ifdef DEBUGG
        vlog(LOG_INFO, "writing to net.. sem_post! finished blw len %d seq_num %d, mode %d chan %d, dirty_seq_num %u", length, shm_conn_info->seq_counter[chan_num], (int) channel_mode, chan_num, (dirty_seq_num+1));
        vlog(LOG_INFO, "select_devread_send() frame ... chan %d seq %"PRIu32" len %d", chan_num, tmp_seq_counter, length);
#endif
        if (debug_trace) {
            vlog(LOG_INFO, "writing to net.. sem_post! finished blw len %d seq_num %d, mode %d chan %d, dirty_seq_num %u", len,
                    shm_conn_info->seq_counter[chan_num], (int) channel_mode, chan_num, (dirty_seq_num + 1));
        }

        // now add correct mini_sum and local_seq_num
        //if(!new_packet) {
        local_seq_num_p = 0;
        tmp_flag = 0;
        sum = 0;

        len = seqn_break_tail(buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
        len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, tmp_flag);
        // if ((info.rtt2_lsn[chan_num] == 0)
        //         && ((shm_conn_info->stats[info.process_num].ACK_speed / info.eff_len) > (1000 / shm_conn_info->stats[info.process_num].exact_rtt))) {
        if(info.rtt2_lsn[chan_num] == 0) {
            info.rtt2_lsn[chan_num] = info.channel[chan_num].local_seq_num;
            info.rtt2_tv[chan_num] = info.current_time;
            info.rtt2_send_q[chan_num] = info.channel[chan_num].send_q;
        }
        //}
    } else { // this is sum packet
        
    }
#ifdef DEBUGG
    struct timeval send1; // need for mean_delay calculation (legacy)
    struct timeval send2; // need for mean_delay calculation (legacy)
    gettimeofday(&send1, NULL );
#endif
    // send DATA
    int len_ret = udp_write(info.channel[chan_num].descriptor, buf, len);
    info.channel[chan_num].packet_recv_counter = 0;
    if (len && (len_ret < 0)) {
        vlog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
        return BREAK_ERROR;
    }
    // sem_wait(&shm_conn_info->common_sem);
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
    // sem_post(&shm_conn_info->common_sem);
#ifdef DEBUGG
    gettimeofday(&send2, NULL );
#endif
    if (tmp_seq_counter) { // this is not sum packet
        if(resend_frame_idx != -1) {
            shm_conn_info->resend_frames_buf[resend_frame_idx].local_seq_num[info.process_num] = info.channel[chan_num].local_seq_num;
        }

        info.channel[chan_num].local_seq_num++;
        if (info.channel[chan_num].local_seq_num == (UINT32_MAX - 1)) {
            info.channel[chan_num].local_seq_num = 0; // TODO: 1. not required; 2. disaster at CLI-side! 3. max. ~4TB of data
        }

#ifdef DEBUGG
        delay_acc += (int) ((send2.tv_sec - send1.tv_sec) * 1000000 + (send2.tv_usec - send1.tv_usec)); // need for mean_delay calculation (legacy)
        delay_cnt++; // need for mean_delay calculation (legacy)
        if((delay_acc/delay_cnt) > 100) vlog(LOG_INFO, "SEND DELAY: %u us", (delay_acc/delay_cnt));
#endif

        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_data_len_amt += len_ret;
        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
        statb.packet_sent_ag += 1000;
        if (shm_conn_info->stats[info.process_num].l_pbl_tmp < INT32_MAX)
            shm_conn_info->stats[info.process_num].l_pbl_tmp++;
        if (shm_conn_info->stats[info.process_num].l_pbl_tmp_unrec < INT32_MAX)
            shm_conn_info->stats[info.process_num].l_pbl_tmp_unrec++;
        info.channel[chan_num].up_len += len_ret;
        statb.byte_sent_ag_full += len_ret;
        info.channel[chan_num].up_packets++;
        info.channel[chan_num].bytes_put++;
        if (drop_packet_flag) {
            vlog(LOG_INFO, "bytes_pass++ select_send");
        }
        info.byte_efficient += len_ret;

        last_sent_packet_num[chan_num].seq_num = tmp_seq_counter;
    }
#ifdef SUM_SEND
    if (packet_code_ready) {
        len_sum = pack_packet(chan_num, buf2, len_sum, 0, 0 /* local seq */, FRAME_REDUNDANCY_CODE);

        //try send or store packet in fast resend buf
        FD_ZERO(&fdset_tun);
        FD_SET(info.channel[chan_num].descriptor, &fdset_tun);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        select_ret = select(info.channel[chan_num].descriptor + 1, NULL, &fdset_tun, NULL, &tv);
#ifdef DEBUGG
        vlog(LOG_INFO, "Trying to select descriptor %i channel %d", info.channel[chan_num].descriptor, chan_num);
#endif
        if (select_ret == 1) {
#ifdef CODE_LOG
            vlog(LOG_INFO, "send FRAME_REDUNDANCY_CODE selection %d packet_code ready %i seq start %"PRIu32" stop %"PRIu32" seq_num %"PRIu32" len %i len new %i", current_selection, packet_code_ready,shm_conn_info->packet_code[current_selection][chan_num].start_seq, shm_conn_info->packet_code[current_selection][chan_num].stop_seq, tmp_seq_counter, shm_conn_info->packet_code[current_selection][chan_num].len_sum,len);
#endif
            len_ret = udp_write(info.channel[chan_num].descriptor, buf2, len_sum | VTUN_BAD_FRAME);
            if(len_sum <= 0) {
                vlog(LOG_ERR, "error sum len %d! reason: %s (%d)", len_sum, strerror(errno), errno);
            }
            if (len_sum && (len_ret <= 0)) {
                vlog(LOG_INFO, "error direct send sum to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
            } else {
//                info.channel[chan_num].local_seq_num++;
                if (info.channel[chan_num].local_seq_num == (UINT32_MAX - 1)) {
                    info.channel[chan_num].local_seq_num = 0; // TODO: 1. not required; 2. disaster at CLI-side! 3. max. ~4TB of data
                }
            }
        } else {
#ifdef CODE_LOG
            vlog(LOG_INFO, "add FRAME_REDUNDANCY_CODE to fast resend selection %d packet_code ready %i seq start %"PRIu32" stop %"PRIu32" seq_num %"PRIu32" len %i len new %i", current_selection, packet_code_ready,shm_conn_info->packet_code[current_selection][chan_num].start_seq, shm_conn_info->packet_code[current_selection][chan_num].stop_seq, tmp_seq_counter, shm_conn_info->packet_code[current_selection][chan_num].len_sum,len);
#endif
            sem_wait(&(shm_conn_info->resend_buf_sem));
            int idx = add_fast_resend_frame(chan_num, buf2, len_sum | VTUN_BAD_FRAME, 0);
            sem_post(&(shm_conn_info->resend_buf_sem));
            if (idx == -1) {
                vlog(LOG_ERR, "ERROR: fast_resend_buf is full");
            }
//               return NET_WRITE_BUSY_NOTIFY;
        }
    }
#endif
    return len & VTUN_FSIZE_MASK;
}

int write_buf_check_n_flush(int logical_channel) {
    int fprev = -1;
    int fold = -1;
    int len;
    //struct timeval max_latency_drop = MAX_LATENCY_DROP;
    struct timeval max_latency_drop;
    uint32_t incomplete_seq_buf[FRAME_BUF_SIZE];
    int rtou = get_rto_usec();
    max_latency_drop.tv_sec = rtou / 1000000;
    max_latency_drop.tv_usec = rtou % 1000000;
    int rtt_fix; //in ms
    struct timeval tv_tmp, rtt_fix_tv;
    struct timeval tv;
    struct timeval since_write_tv, packet_wait_tv;
    int ts;
    fprev = shm_conn_info->write_buf[logical_channel].frames.rel_head;
    shm_conn_info->write_buf[logical_channel].complete_seq_quantity = 0;
    //int buf_len = shm_conn_info->write_buf[logical_channel].frames.len; // disabled for #400
    //int tail_idx = shm_conn_info->write_buf[logical_channel].frames.rel_tail;
    int buf_len;

    // first select tun
    fd_set fdset2;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fdset2);
    FD_SET(info.tun_device, &fdset2);
    int sel_ret = select(info.tun_device + 1, NULL, &fdset2, NULL, &tv);
    if (sel_ret == 0) {
    #ifdef FRTTDBG
        vlog(LOG_ERR, "write_buf_check_n_flush select - no select%d",errno);
    #endif
        return 0; // save rtt!
    } else if (sel_ret == -1) {
        vlog(LOG_ERR, "write_buf_check_n_flush select error! errno %d",errno);
        return 0;
    }

#ifdef DEBUGG
    if (fprev == -1) {
        vlog(LOG_INFO, "no data to write at all!");
    } else {
        vlog(LOG_INFO, "trying to write to to dev: seq_num %"PRIu32" lws %"PRIu32" chan %d", shm_conn_info->frames_buf[fprev].seq_num,
                shm_conn_info->write_buf[logical_channel].last_written_seq, logical_channel);
    }
#endif
    acnt = 0;
    if (fprev > -1) {
        #ifdef FRTTDBG
        vlog(LOG_ERR, "WBF forced reached: %d", forced_rtt_reached);
        #endif
        if(info.least_rx_seq[logical_channel] == UINT32_MAX) {
            info.least_rx_seq[logical_channel] = 0; // protect us from possible failures to calculate LRS in get_write_buf_wait_data()
        }
        if(shm_conn_info->frames_buf[fprev].stub_counter) {
            shm_conn_info->frames_buf[fprev].stub_counter--;
            shm_conn_info->write_buf[logical_channel].frames.stub_total--;
            if (shm_conn_info->tokens > 0) {
                shm_conn_info->tokens--; // remove a token...
            }
            if(shm_conn_info->write_buf[logical_channel].frames.stub_total < 0) {
                vlog(LOG_ERR, "ASSERT FAILED!: stub_total <0!");
                shm_conn_info->write_buf[logical_channel].frames.stub_total = 0;
            }
            shm_conn_info->write_buf[logical_channel].last_write_time = info.current_time;
            return 0;
        }
        if(shm_conn_info->frames_buf[fprev].seq_num == shm_conn_info->write_buf[logical_channel].last_written_seq) {
            vlog(LOG_ERR, "ASSERT FAILED! Duplicate packet in WB! %lu == lws %lu", shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq);
        }
        if(shm_conn_info->frames_buf[fprev].seq_num < shm_conn_info->write_buf[logical_channel].last_written_seq) {
            vlog(LOG_ERR, "ASSERT FAILED! Negative packet seq_num diff in WB! seq %lu < lws %lu", shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq);
        }
        int cond_flag;
        
        IF_WRITE_CONDITION 
        {
            if (!cond_flag) {
                char lag_pname[SESSION_NAME_SIZE] = "E\0";
                int r_amt = 0;
                shm_conn_info->tflush_counter += shm_conn_info->frames_buf[fprev].seq_num
                        - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
#ifdef TRACE_BUF_LEN
                udp_struct->lport = info.channel[1].lport;
                udp_struct->rport = info.channel[1].rport;
                char tmp[2000] = {0};
                if (get_udp_stats(udp_struct, 1)) {
                    sprintf(tmp, "udp stat tx_q %d rx_q %d drops %d ", udp_struct->tx_q, udp_struct->rx_q, udp_struct->drops);
                }
#endif
                int loss_flag = 0;
                int who_lost_pnum = -1;
                if (buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) {
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LAGGING, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                    loss_flag = 1;
                } else if (timercmp(&packet_wait_tv, &max_latency_drop, >=)
                           && timercmp(&since_write_tv, &((struct timeval) MAX_NETWORK_STALL), >=)
                           //&& (shm_conn_info->frames_buf[fprev].seq_num <= shm_conn_info->write_buf[logical_channel].last_received_seq[shm_conn_info->remote_head_pnum])
                ) {
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LAGGING, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                    loss_flag = 1;
                    if(info.least_rx_seq[logical_channel] > 0 && info.least_rx_seq[logical_channel] != UINT32_MAX) {
                        // now drop everything suspicious
                        int last_idx = missing_resend_buffer(logical_channel, incomplete_seq_buf, &buf_len, info.least_rx_seq[logical_channel]) - 1;
                        uint32_t last_loss_sqn = incomplete_seq_buf[last_idx];
                        if(discard_packets(logical_channel, last_loss_sqn) < 0) {
                            vlog(LOG_ERR, "ERROR merging loss");
                            return 0;
                        }
                    }

                } else if (info.ploss_event_flag && (shm_conn_info->frames_buf[fprev].seq_num < info.least_rx_seq[logical_channel])) {
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LOST, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                    if(r_amt == 0) {
                        if (shm_conn_info->tokens > 0) {
                            shm_conn_info->tokens--; // remove a token...
                        }
                        return 0;
                    }
                    loss_flag = 1;
                } else if (!info.ploss_event_flag && (shm_conn_info->frames_buf[fprev].seq_num < info.least_rx_seq[logical_channel])) {
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LOST, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                    if(r_amt == 0) {
                        if (shm_conn_info->tokens > 0) {
                            shm_conn_info->tokens--; // remove a token...
                        }
                        return 0;
                    }
                    loss_flag = 1;
                } else if (shm_conn_info->frames_buf[fprev].seq_num < shm_conn_info->seq_num_unrecoverable_loss) {
                    info.flush_sequential = shm_conn_info->seq_num_unrecoverable_loss - shm_conn_info->frames_buf[fprev].seq_num;
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LAGGING, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                    int r = discard_packets(logical_channel, shm_conn_info->seq_num_unrecoverable_loss);
                    if(r < 0) {
                        if(r == -2) shm_conn_info->seq_num_unrecoverable_loss = 1;
                        return 0;
                    }
                    loss_flag = 1;
                } else {
                    update_prev_flushed(logical_channel, fprev);
                    r_amt = flush_reason_chan(WHO_LOST, logical_channel, lag_pname, shm_conn_info->channels_mask, &who_lost_pnum);
                }
                if (loss_flag && !lost_buf_exists(shm_conn_info->write_buf[logical_channel].last_written_seq)) {
                    // TODO: check if there is no such entry (this sqn) in the list
                    shm_conn_info->loss_idx++;
                    if (shm_conn_info->loss_idx == LOSS_ARRAY) {
                        shm_conn_info->loss_idx = 0;
                    }
                    shm_conn_info->loss[shm_conn_info->loss_idx].timestamp = info.current_time;
                    shm_conn_info->loss[shm_conn_info->loss_idx].pbl = shm_conn_info->write_sequential;
                    shm_conn_info->loss[shm_conn_info->loss_idx].psl = info.flush_sequential;
                    if(who_lost_pnum != -1) {
                        shm_conn_info->loss[shm_conn_info->loss_idx].who_lost = shm_conn_info->stats[who_lost_pnum].hsnum;
                    } else {
                        shm_conn_info->loss[shm_conn_info->loss_idx].who_lost = -1;
                    }
                    shm_conn_info->loss[shm_conn_info->loss_idx].sqn = shm_conn_info->write_buf[logical_channel].last_written_seq + 1;
                }
            }
            
            if(shm_conn_info->prev_flushed) {
                // TODO: write avg stats here?
                shm_conn_info->write_sequential = 1;
            } else {
                shm_conn_info->write_sequential++;
            }
            shm_conn_info->prev_flushed = 0;

            struct frame_seq *frame_seq_tmp = &shm_conn_info->frames_buf[fprev];

            // calculate this stream TCP_seq_nums etc.
            unsigned int tcp_seq2 = 0, hash, tcp_seq;
            shm_conn_info->w_stream_pkts[shm_conn_info->frames_buf[fprev].shash % W_STREAMS_AMT]--;
            // unsigned int hash = get_l4_hash(frame_seq_tmp->out, &tcp_seq2);
            // unsigned int tcp_seq = getTcpSeq(frame_seq_tmp->out);
            // shm_conn_info->w_streams[hash % W_STREAMS_AMT].ts = info.current_time;
            // if(shm_conn_info->w_streams[hash % W_STREAMS_AMT].seq < tcp_seq) {
            //     shm_conn_info->w_streams[hash % W_STREAMS_AMT].seq = tcp_seq;
            // }
            // TODO: drop here may be pre-calculated once in 500ms - no need to do it each packet
            int need_drop = (shm_conn_info->frames_buf[fprev].unconditional_write_flag == 1) || ((shm_conn_info->write_buf[1].frames.length > (MSBL_LIMIT - MSBL_RESERV)) && (shm_conn_info->max_stuck_buf_len > (MSBL_LIMIT - MSBL_RESERV)) && check_drop_period_unsync());
            if(frame_seq_tmp->len > 0 && !need_drop) {
                if ((len = dev_write(info.tun_device, frame_seq_tmp->out, frame_seq_tmp->len)) < 0) {
                    vlog(LOG_ERR, "error writing to device %d %s chan %d", errno, strerror(errno), logical_channel);
                    if (errno != EAGAIN && errno != EINTR) { // TODO: WTF???????
                        vlog(LOG_ERR, "dev write not EAGAIN or EINTR");
                    } else {
                        vlog(LOG_ERR, "dev write intr - need cont");
                        return 0;
                    }
    
                } else {
                    if (len < frame_seq_tmp->len) {
                        vlog(LOG_ERR, "ASSERT FAILED! could not write to device immediately; dunno what to do!! bw: %d; b rqd: %d", len,
                                shm_conn_info->frames_buf[fprev].len);
                    }
                }
            } else {
                vlog(LOG_INFO, "dropping frame at write seq_num %lu unf %d", shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->frames_buf[fprev].unconditional_write_flag);
                drop_counter++;
                // shm_conn_info->write_buf[logical_channel].frames.stub_total--;
                
                if(need_drop) {
                    shm_conn_info->drop_time = info.current_time;
                }
            }
            
            if (debug_trace) {
                vlog(LOG_INFO, "writing to dev: bln is %d icpln is %d, sqn: %"PRIu32", lws: %"PRIu32" mode %d, ns: %d, w: %d len: %d, chan %d ts %ld.%06ld cur %ld.%06ld rtt %d pnum %d, tokens %d, tcp_seq %u == %u, hs %u", buf_len, incomplete_seq_len,
                        shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[logical_channel].last_written_seq, (int) channel_mode, shm_conn_info->normal_senders,
                        weight, shm_conn_info->frames_buf[fprev].len, logical_channel, shm_conn_info->frames_buf[fprev].time_stamp, info.current_time, shm_conn_info->frames_buf[fprev].current_rtt, shm_conn_info->frames_buf[fprev].physical_channel_num, shm_conn_info->tokens, tcp_seq, tcp_seq2, hash);
            }
            if(shm_conn_info->frames_buf[fprev].unconditional_write_flag != -1) {
                if (shm_conn_info->tokens > 0) {
                    shm_conn_info->tokens--; // remove a token...
                }
            }
            shm_conn_info->flushed_packet[shm_conn_info->frames_buf[fprev].seq_num % FLUSHED_PACKET_ARRAY_SIZE] = shm_conn_info->frames_buf[fprev].seq_num;
            shm_conn_info->write_buf[logical_channel].last_written_seq = shm_conn_info->frames_buf[fprev].seq_num;
            shm_conn_info->last_written_recv_ts = shm_conn_info->frames_buf[fprev].time_stamp;
            shm_conn_info->write_buf[logical_channel].last_write_time = info.current_time;
            fold = fprev;
            fprev = shm_conn_info->frames_buf[fprev].rel_next;
//            frame_llist_free(&shm_conn_info->write_buf[logical_channel].frames, &shm_conn_info->wb_free_frames, shm_conn_info->frames_buf, fold);
//            return 1;
            if(frame_llist_pull(&shm_conn_info->write_buf[logical_channel].frames, shm_conn_info->frames_buf, &fold) < 0) {
                vlog(LOG_ERR, "WARNING! tried to pull from empty write_buf!");
                return 0;
            }
            frame_llist_append(&shm_conn_info->wb_just_write_frames[logical_channel], fold, shm_conn_info->frames_buf);
            if (shm_conn_info->wb_just_write_frames[logical_channel].length > PACKET_CODE_BUFFER_SIZE) {
                int frame_index;
                if(frame_llist_pull(&shm_conn_info->wb_just_write_frames[logical_channel], shm_conn_info->frames_buf, &frame_index) < 0) {
                    vlog(LOG_ERR, "ASSERT FAILED! can not pull anything from wjf!");
                    return 0;
                }
                frame_llist_append(&shm_conn_info->wb_free_frames, frame_index, shm_conn_info->frames_buf);
            }
            
            return 1;
        } 
    } else {
        return 0;
    }
    return 0;
}

/**
 * push up msbl in case of loss for current channel
 * 
 */
 
void msbl_push_up_loss_unsync() {
    struct timeval loss_tv;
    if((shm_conn_info->stats[info.process_num].recv_mode == AG_MODE || shm_conn_info->stats[info.process_num].remote_head_channel) && timercmp(&info.recv_loss_immune, &info.current_time, <=)) {
        vlog(LOG_INFO, "Loss detected - pushing the MSBL up by %d", (shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt - (int) ((double)shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt * (2.0 - info.B) / 2.0)));
        shm_conn_info->max_stuck_buf_len += shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt - (int) ((double)shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt * (2.0 - info.B) / 2.0);
        ms2tv(&loss_tv, info.exact_rtt);
        timeradd(&info.current_time, &loss_tv, &info.recv_loss_immune);
    }
} 

// void msbl_push_down_drop_unsync() {
//     struct timeval loss_tv;
//         shm_conn_info->max_stuck_buf_len -= shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt - (int) ((double)shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt * (2.0 - info.B) / 2.0);
//         ms2tv(&loss_tv, info.exact_rtt);
//         timeradd(&info.current_time, &loss_tv, &info.recv_loss_immune);
// }


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
    vlog(LOG_INFO, "write_buf_add called! len %d seq_num %"PRIu32" chan %d", length, seq_num, conn_num);
#endif
    if(debug_trace) {
        vlog(LOG_INFO, "write_buf_add called! len %d seq_num %"PRIu32" chan %d", len, seq_num, conn_num);
    }
    // place into correct position first..
    int i = shm_conn_info->write_buf[conn_num].frames.rel_head, n;
    int newf;
    int j=0;
    shm_conn_info->avg_len_in = EFF_LEN_AVG_N * shm_conn_info->avg_len_in / EFF_LEN_AVG_D + len / EFF_LEN_AVG_D;

    if (i == -1) {
        shm_conn_info->write_buf[conn_num].last_write_time = info.current_time;
    }
    int tail_idx = shm_conn_info->write_buf[conn_num].frames.rel_tail;
#ifdef SYSLOG
    if ((tail_idx != -1) && ( (seq_num > shm_conn_info->frames_buf[tail_idx].seq_num ) &&
            (seq_num - shm_conn_info->frames_buf[tail_idx].seq_num ) >= STRANGE_SEQ_FUTURE )) {
        vlog(LOG_INFO, "WARNING! DROP BROKEN PKT SRANGE_SEQ_FUTURE logical channel %i seq_num %"PRIu32" lws %"PRIu32"; diff is: %d >= 1000 tail seq %lu", conn_num, seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, (seq_num - shm_conn_info->frames_buf[tail_idx].seq_num), shm_conn_info->frames_buf[tail_idx].seq_num);
    }
    if( (tail_idx != -1) && (seq_num < shm_conn_info->write_buf[conn_num].last_written_seq) &&
              ((shm_conn_info->write_buf[conn_num].last_written_seq - seq_num) >= STRANGE_SEQ_PAST) ) { // this ABS comparison makes checks in MRB unnesesary...
        vlog(LOG_INFO, "WARNING! DROP BROKEN PKT STRANGE_SEQ_PAST logical channel %i seq_num %"PRIu32" lws %"PRIu32"; diff is: %d >= 1000", conn_num, seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, (shm_conn_info->write_buf[conn_num].last_written_seq - seq_num));
    }
#endif

    if ( (seq_num <= shm_conn_info->write_buf[conn_num].last_written_seq)) {
        //check for oldest dups
        if (shm_conn_info->flushed_packet[seq_num % FLUSHED_PACKET_ARRAY_SIZE] != seq_num) {
            shm_conn_info->flushed_packet[seq_num % FLUSHED_PACKET_ARRAY_SIZE] = seq_num;
            struct timeval work_loop1, work_loop2, tmp_tv;
            //gettimeofday(&work_loop1, NULL );
            int len_ret = dev_write(info.tun_device, out, len);
            //gettimeofday(&work_loop2, NULL );
            //timersub(&work_loop2, &work_loop1, &tmp_tv);
            vlog(LOG_INFO, "latecomer seq_num %u lws %u time write %"PRIu64" ts %ld.%06ld", seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, tv2ms(&tmp_tv), info.current_time.tv_sec, info.current_time.tv_usec);
            if (len_ret < 0) {
                vlog(LOG_ERR, "error writing to device %d %s chan %d", errno, strerror(errno), conn_num);
                if (errno != EAGAIN && errno != EINTR) { // TODO: WTF???????
                    vlog(LOG_ERR, "dev write not EAGAIN or EINTR");
                } else {
                    vlog(LOG_ERR, "dev write intr - need cont");
                    return 0;
                }

            } else if (len_ret < len) {
                vlog(LOG_ERR, "ASSERT FAILED! could not write to device immediately; dunno what to do!! bw: %d; b rqd: %d", len_ret, len);
            }

        }
#ifdef DEBUGG
        vlog(LOG_INFO, "drop dup pkt seq_num %"PRIu32" lws %"PRIu32"", seq_num, shm_conn_info->write_buf[conn_num].last_written_seq);
#endif
        *succ_flag = -2;
        return 0; //missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
    }
    /*
    unsigned int tcp_seq = getTcpSeq(out);
    unsigned int tcp_seq2 = 0;
    unsigned int hash = get_l4_hash(out, &tcp_seq2);
    if(0 && shm_conn_info->w_streams[hash % W_STREAMS_AMT].seq > tcp_seq) {
        struct timeval tv_tmp;
        timersub(&info.current_time, &shm_conn_info->w_streams[hash % W_STREAMS_AMT].ts, &tv_tmp);
        if(timercmp(&tv_tmp, &((struct timeval) {5, 0}), >=)) { // 5 seconds session timeout
            shm_conn_info->w_streams[hash % W_STREAMS_AMT].seq = 0;
        } else {
            int len_ret = dev_write(info.tun_device, out, len);
            vlog(LOG_ERR, "tcp retransmission segment seq_num %u lws %u tcp_seq %u == %u last tseq: %u, hs %u ts %ld.%06ld", seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, tcp_seq, tcp_seq2, shm_conn_info->w_streams[hash % W_STREAMS_AMT].seq, hash, info.current_time.tv_sec, info.current_time.tv_usec);
            if (len_ret < 0) {
                vlog(LOG_ERR, "ERROR writing (tcprxm) to device %d %s chan %d", errno, strerror(errno), conn_num);
                if (errno != EAGAIN && errno != EINTR) { // TODO: WTF???????
                    vlog(LOG_ERR, "ERROR tcprxm dev write not EAGAIN or EINTR");
                } else {
                    vlog(LOG_ERR, "ERROR tcprxm dev write intr - need cont");
                }

            } else if (len_ret < len) {
                vlog(LOG_ERR, "ASSERT FAILED! tcprxm could not write to device immediately; dunno what to do!! bw: %d; b rqd: %d", len_ret, len);
            }
            len = 0; // indicate that this is stub packet
            //seq_num = 0; // to make stub packet support work at flushing? // actually not required since these are OK in seq_num
        }
    }
    */

    // now check if we can find it in write buf current .. inline!
    // TODO: run from BOTTOM! if seq_num[i] < seq_num: break
    /*
    if(seq_num <= shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_tail].seq_num) {
        while( i > -1 ) {
            if(shm_conn_info->frames_buf[i].seq_num == seq_num) {
#ifdef DEBUGG
                vlog(LOG_INFO, "drop exist pkt seq_num %"PRIu32" sitting in write_buf chan %i", seq_num, conn_num);
#endif
                return 0;
            }
            i = shm_conn_info->frames_buf[i].rel_next;
        }
    }
    */
    shm_conn_info->flushed_packet[seq_num % FLUSHED_PACKET_ARRAY_SIZE] = seq_num;
    i = shm_conn_info->write_buf[conn_num].frames.rel_head;

    if (frame_llist_pull(&shm_conn_info->wb_free_frames, shm_conn_info->frames_buf, &newf) < 0) {
        // try a fix
        vlog(LOG_ERR, "WARNING! No free elements in wbuf! trying to free some...");
        if(frame_llist_pull(&shm_conn_info->wb_free_frames,
                            shm_conn_info->frames_buf,
                            &newf) < 0) {
            vlog(LOG_ERR, "FATAL: could not fix free wb.");
            *succ_flag = -1;
            return -1;
        }
    }
    // if(seq_num == 0 || len == 0) { // add stub packet counter in case of retransmission packet
    //     shm_conn_info->write_buf[conn_num].frames.stub_total++;
    // }
    // now add stubs, if any
    // if(shm_conn_info->tokenbuf > MAX_STUB_JITTER) {
    //     shm_conn_info->frames_buf[newf].stub_counter = shm_conn_info->tokenbuf - MAX_STUB_JITTER;
    //     shm_conn_info->write_buf[conn_num].frames.stub_total += shm_conn_info->frames_buf[newf].stub_counter;
    //     shm_conn_info->tokenbuf = MAX_STUB_JITTER;
    // } else {
    //     shm_conn_info->frames_buf[newf].stub_counter = 0;
    // }
        
    shm_conn_info->frames_buf[newf].seq_num = seq_num;
    // do not do the copy until written
    //memcpy(shm_conn_info->frames_buf[newf].out, out, len);
    shm_conn_info->frames_buf[newf].len = len;
    shm_conn_info->frames_buf[newf].sender_pid = mypid;
    shm_conn_info->frames_buf[newf].physical_channel_num = info.process_num;
    shm_conn_info->frames_buf[newf].time_stamp = info.current_time;
    shm_conn_info->frames_buf[newf].current_rtt = info.exact_rtt;
    shm_conn_info->frames_buf[newf].unconditional_write_flag = 0;
    struct timeval t_rtt, t_frtt, tv_tmp;
    int full_rtt = ((shm_conn_info->forced_rtt_recv > shm_conn_info->frtt_local_applied) ? shm_conn_info->forced_rtt_recv : shm_conn_info->frtt_local_applied);
    if(info.exact_rtt < full_rtt) {
        ms2tv(&t_rtt, info.exact_rtt);
        ms2tv(&t_frtt, full_rtt);
        timersub(&t_frtt, &t_rtt, &tv_tmp);
        timeradd(&info.current_time, &tv_tmp, &shm_conn_info->frames_buf[newf].flush_time);
    } else {
        shm_conn_info->frames_buf[newf].flush_time = info.current_time;
    }
    shm_conn_info->write_buf[conn_num].frames.length++;
    if (buf_len_real < shm_conn_info->write_buf[1].frames.length) {
//    vlog(LOG_ERR, "FRAME_CHANNEL_INFO update buf_len %d was %d",shm_conn_info->write_buf[1].frames.length,shm_conn_info->buf_len);
        buf_len_real = shm_conn_info->write_buf[1].frames.length;
        }
    // if(shm_conn_info->tokenbuf > 0) shm_conn_info->tokenbuf--;
    int buf_len_real = shm_conn_info->write_buf[conn_num].frames.length;
    int tokens_in_out = buf_len_real - shm_conn_info->max_stuck_buf_len;
    if(tokens_in_out > 0) {
        #ifdef FRTTDBG
        vlog(LOG_INFO, "adding token+1");
        #endif
        shm_conn_info->tokens++;
        if( ((shm_conn_info->head_send_q_shift_recv == 10000) || (shm_conn_info->slow_start_recv)) && ((seq_num % SLOW_START_INCINT) == 0)) {
            vlog(LOG_INFO, "FAST PUSHING MSBL UP ???????");
           shm_conn_info->max_stuck_buf_len += 1;
        }
        //if(shm_conn_info->max_stuck_buf_len == 950) {
        //    // drop exactly one packet (at least try to)
        //    shm_conn_info->frames_buf[newf].len = 0;
        //}
    }
    int written = 0;
    unsigned int tcp_seq2 = 0;
    unsigned int shash = get_l4_hash(out, &tcp_seq2);
    int unf = -1;
    
    if(i<0) { // buffer empty.
        shm_conn_info->frames_buf[newf].rel_next = -1;
        shm_conn_info->write_buf[conn_num].frames.rel_head = shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;
        mlen = 0;
        *succ_flag=0;
        memcpy(shm_conn_info->frames_buf[newf].out, out, len); // now actually copy the data.. just a tiny optimization
        unsigned int hash = seq_num * 2654435761 % 4294967296 % WBUF_HASH_SIZE;
        shm_conn_info->write_buf_hashtable[hash].seq = seq_num;
        shm_conn_info->write_buf_hashtable[hash].n = newf;
        shm_conn_info->APCS_cnt++;
        shm_conn_info->w_stream_pkts[shash % W_STREAMS_AMT]++;
        shm_conn_info->frames_buf[newf].shash = shash;
        return mlen;
    } else { // buffer not empty
        // if(shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_tail].seq_num == seq_num - 2) {
        //     vlog(LOG_ERR, "WARNING! added one packet loss! %lu +2= %lu", shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_tail].seq_num, seq_num);
        // }
        if( (shm_conn_info->frames_buf[i].seq_num > seq_num) &&
                (shm_conn_info->frames_buf[i].rel_next > -1)) { // new packet is older (&lt) than all the buffer
            // append to head
            // no check for dups is required here as we are sure that all the buffer is newer than this packet
            shm_conn_info->write_buf[conn_num].frames.rel_head = newf;
            shm_conn_info->frames_buf[newf].rel_next = i;
            written = 1;
        } else {
            if(shm_conn_info->frames_buf[i].rel_next > -1) {
                // TODO HERE: do extreme optimization: 
                // 1. always use hashed search first
                // 2. try c=1 first, then x2, x3, etc.
                if(shm_conn_info->write_buf[conn_num].frames.length > MAX_WBUF_HASH_DEPTH && seq_num > 0) {
                    unsigned int hash = seq_num * 2654435761 % 4294967296 % WBUF_HASH_SIZE;
                    int c = 0;
                    while( (c < MAX_WBUF_HASH_DEPTH) 
                        && ((seq_num - c) > shm_conn_info->write_buf[conn_num].last_written_seq) 
                        && (shm_conn_info->write_buf_hashtable[hash].seq != (seq_num - c))) {
                        c+=1;
                        hash = (seq_num - c) * 2654435761 % 4294967296 % WBUF_HASH_SIZE;
                    }
                    if(c >= MAX_WBUF_HASH_DEPTH || (seq_num - c) <= shm_conn_info->write_buf[conn_num].last_written_seq) {
                        /*
                        hash = seq_num * 2654435761 % 4294967296 % WBUF_HASH_SIZE;
                        vlog(LOG_INFO, "Warning! hash lookup failed, falling back to search from top seq %ld hash %d", seq_num, hash);
                        */
                    } else {
                        //vlog(LOG_INFO, "New search start %d bl %d seq %ld (new hash %d) - found seq %ld hash %d tries %d", shm_conn_info->write_buf_hashtable[hash].n, shm_conn_info->write_buf[conn_num].frames.length, seq_num, seq_num * 2654435761 % 4294967296 % WBUF_HASH_SIZE, seq_num-c, hash, c);
                        i = shm_conn_info->write_buf_hashtable[hash].n;
                        /*
                        // TODO: remove this
                        if(c == 0) {
                            vlog(LOG_INFO, "zero tries: seq %ld n %d n.seq %ld", seq_num, i, shm_conn_info->frames_buf[i].seq_num);                   
                        }
                        // now make sure that the entry point we have found is actually found inside the wb
                        int k;
                        for (k = shm_conn_info->write_buf[conn_num].frames.rel_head; k != -1; k = shm_conn_info->frames_buf[k].rel_next) {
                            if(k == i) break;
                        }
                        if(k == -1) {
                            vlog(LOG_ERR, "ASSERT FAILED! entry point is outside the write_buf!");
                        }
                        */
                    }
                }
                
                while( i > -1 ) {
                    if( shm_conn_info->frames_buf[i].seq_num == seq_num) {
                        break; // found a dup, not setting written flag
                    }
                    n = shm_conn_info->frames_buf[i].rel_next;
                    if(n > -1) {
                        if( shm_conn_info->frames_buf[n].seq_num > seq_num) {
                            shm_conn_info->frames_buf[i].rel_next = newf;
                            shm_conn_info->frames_buf[newf].rel_next = n;
                            written = 1;
                            break;
                        } // else try next...
                    } else {
                        // append to tail
                        #ifdef SYSLOG
                        if(i != shm_conn_info->write_buf[conn_num].frames.rel_tail) {
                            vlog(LOG_ERR, "ASSERT FAILED! i!=tail: sqn %ld, %d %d: wb: %d, jwb: %d, fr: %d, lws: %ld", shm_conn_info->frames_buf[i].seq_num, i, shm_conn_info->write_buf[conn_num].frames.rel_tail, shm_conn_info->write_buf[conn_num].frames.rel_tail, shm_conn_info->wb_just_write_frames[conn_num].rel_tail, shm_conn_info->wb_free_frames.rel_tail, shm_conn_info->write_buf[conn_num].last_written_seq);
                        }
                        #endif
                        shm_conn_info->frames_buf[i].rel_next=newf;
                        shm_conn_info->frames_buf[newf].rel_next = -1;
                        shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;
                        written = 1;
                        break;
                    }
                    i = n;
                }

            } else {
                if(shm_conn_info->frames_buf[i].seq_num != seq_num) { // dup protect?
                    if(shm_conn_info->frames_buf[i].seq_num > seq_num) {
                        shm_conn_info->write_buf[conn_num].frames.rel_head = newf;
                        shm_conn_info->frames_buf[newf].rel_next = i;
                    } else {
                        shm_conn_info->write_buf[conn_num].frames.rel_tail = newf;
                        shm_conn_info->frames_buf[i].rel_next = newf;
                        shm_conn_info->frames_buf[newf].rel_next = -1;
                    }
                    written = 1;
                }
            }
        }
    }
    
    if(!written) {
        // means we were unable to write, put the packet back to free
        // vlog(LOG_INFO, "Unable to find position to add packet! %ld", seq_num); // dup detected
        shm_conn_info->write_buf[conn_num].frames.length--; // we have not written that packet to buffer...
        frame_llist_prepend(&shm_conn_info->wb_free_frames, newf, shm_conn_info->frames_buf);
        *succ_flag= 0;
        return 0;
    }
    
    if(   shm_conn_info->write_buf[conn_num].frames.rel_head >= 0 && 
          shm_conn_info->write_buf[conn_num].frames.length > 20 && 
          shm_conn_info->w_stream_pkts[shash % W_STREAMS_AMT] == 0 && 
          shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_head].unconditional_write_flag != -1 && 
          shm_conn_info->frames_buf[shm_conn_info->write_buf[conn_num].frames.rel_head].seq_num != seq_num) {
        // duplicate this packet in front of queue
        if (frame_llist_pull(&shm_conn_info->wb_free_frames, shm_conn_info->frames_buf, &unf) < 0) {
            vlog(LOG_ERR, "WARNING! Can not write new stream packet in front: no free elements in buffer");
        } else {
            frame_llist_prepend(&shm_conn_info->write_buf[conn_num].frames, unf, shm_conn_info->frames_buf);
            
            shm_conn_info->frames_buf[unf].unconditional_write_flag = -1;
            shm_conn_info->frames_buf[unf].seq_num = shm_conn_info->write_buf[conn_num].last_written_seq;
            shm_conn_info->write_buf[conn_num].last_written_seq = shm_conn_info->frames_buf[unf].seq_num - 1;
            shm_conn_info->frames_buf[unf].len = len;
            shm_conn_info->frames_buf[unf].sender_pid = mypid;
            shm_conn_info->frames_buf[unf].physical_channel_num = info.process_num;
            shm_conn_info->frames_buf[unf].time_stamp = info.current_time;
            shm_conn_info->frames_buf[unf].current_rtt = info.exact_rtt;
            memcpy(shm_conn_info->frames_buf[unf].out, out, len); // now actually copy the data.. just a tiny optimization
            shm_conn_info->w_stream_pkts[shash % W_STREAMS_AMT]++;
            shm_conn_info->frames_buf[unf].shash = shash;
            vlog(LOG_ERR, "Adding priority packet seq %lu imitated %lu, next is %lu", seq_num, shm_conn_info->frames_buf[unf].seq_num, shm_conn_info->frames_buf[shm_conn_info->frames_buf[unf].rel_next].seq_num);
        }
    }
    
    memcpy(shm_conn_info->frames_buf[newf].out, out, len); // now actually copy the data.. just a tiny optimization
    unsigned int hash = seq_num * 2654435761 % 4294967296 % WBUF_HASH_SIZE;
    shm_conn_info->write_buf_hashtable[hash].seq = seq_num;
    shm_conn_info->write_buf_hashtable[hash].n = newf;
    shm_conn_info->APCS_cnt++;
    shm_conn_info->w_stream_pkts[shash % W_STREAMS_AMT]++;
    shm_conn_info->frames_buf[newf].shash = shash;
    if(unf >= 0) {
        shm_conn_info->frames_buf[newf].unconditional_write_flag = 1;
    }

    mlen = 0; //missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);

    *succ_flag= 0;
    return mlen;
}

void sem_post_if(int *dev_my, sem_t *rd_sem) {
    if(*dev_my) sem_post(rd_sem);
    else {
        // it is actually normal to try to post sem in idle-beg and in net-end blocks
        // vlog(LOG_INFO, "ASSERT FAILED! posting posted rd_sem");
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
        vlog(LOG_ERR, "ASSERT FAILED! Semaphore value > 1: %d, doing one more sem_wait", sval);
        sem_wait(sem);
    }

    if( sem_timedwait(sem, &ts) < 0 ) {
        vlog(LOG_ERR, "ASSERT FAILED! Emergrency quit semaphore waiting");
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
    vlog(LOG_INFO, "Head change BDP");
    shm_conn_info->max_chan = max_chan;
}

int check_plp_ok(int pnum, int32_t chan_mask) { // TODO TCP model => remove
    #define PBL_THRESH 2500 // PBL after which chan is ok to use for normal OP
    int chali = 0;
    int pmax =0;
    int imax=-1;
    int l_pbl;
    int rtt_min = INT32_MAX;
    // 1. set chan thresh
    // 2. check all other chans for thresh. if no chans are OK -> use chan with highest PBL
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
            l_pbl = plp_avg_pbl_unrecoverable(i);
            if(l_pbl > PBL_THRESH) {
                chali++;
            }
            if(pmax < l_pbl) {
                pmax = l_pbl;
                imax=i;
            }
            if(rtt_min > shm_conn_info->stats[i].exact_rtt){
                rtt_min = shm_conn_info->stats[i].exact_rtt;
            }
        }
    }
    if((shm_conn_info->stats[pnum].exact_rtt - rtt_min) > MAX_LATENCY_DROP_USEC/1000) { // TODO remove when FRTT theory will kick in
        return 0;
    } else {
        if(chali) {
            return (plp_avg_pbl_unrecoverable(pnum) > PBL_THRESH);
        } else {
           return (pnum == imax);
        }
    }
}

int transition_period_time(int hsqs) {
    int j=0;
    int i;
    int min_diff = 10; // TODO: variable/constant
    for(i=hsqs; i>min_diff; i=i-i/5) j++; // TODO: same constant as in MSBL
    return j * (SELECT_SLEEP_USEC/1000); // return milliseconds to converge
}

int redetect_head_unsynced(int32_t chan_mask, int exclude) { // TODO: exclude is only used to change head!
    // shm_conn_info->max_chan = 0; // change immedialtey
    // shm_conn_info->max_chan_new = 0;
    // return 1;
    
    int fixed = 0;
    int htime = 0;
    int Ch = 0;
    int Cs = 0;
     // This is AG_MODE algorithm
    int moremax = 0;
    int max_chan_H = -1;
    int max_chan_CS = -1;
    int min_rtt = INT32_MAX;
    int max_ACS = 0;
    int max_ACS_chan = -1;
    int max_chan = shm_conn_info->max_chan;
    int immune_sec = 0;
    struct timeval tv_tmp;
    int new_max_chan = -1;

    if( exclude == max_chan) { // the only case right now
        // choose first (random) head, excluding 'excluded', then do following redetect
        int new_head = -1;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != exclude)) {
                new_head = i;
                break;
            }
        }
        if(new_head != -1) { // means we've found one alive and not excluded
            shm_conn_info->max_chan = new_head;
            shm_conn_info->max_chan_new = new_head;
            max_chan = new_head;
            // set redetect time to future
            immune_sec = SPEED_REDETECT_IMMUNE_SEC;
        }
    }

    if(shm_conn_info->idle) {
        // use RTT-only choosing of head while idle!
        int min_rtt = INT32_MAX;
        int min_rtt_chan = 0;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                    min_rtt = shm_conn_info->stats[i].exact_rtt;
                    min_rtt_chan = i;
                }
            }
        }
        //vlog(LOG_INFO, "IDLE: Head is %d due to lowest rtt %d", min_rtt_chan, min_rtt);
        shm_conn_info->max_chan = min_rtt_chan;
        shm_conn_info->max_chan_new = min_rtt_chan;
        fixed = 1;
        shm_conn_info->last_switch_time = info.current_time; // nothing bad in this..
        shm_conn_info->last_switch_time.tv_sec += immune_sec;
    } else {
        // ---> ACS == and rtt
        min_rtt = shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ( (chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != shm_conn_info->max_chan) && (i != exclude) && check_plp_ok(i, chan_mask) ) {
                if(percent_delta_equal(shm_conn_info->stats[i].ACK_speed_avg, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed_avg, 10)) { // 15% corridor to consider speeds the same
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
            vlog(LOG_INFO, "ACS~=: Need changing HEAD to %d with ACS %d and rtt %d", max_chan_H, shm_conn_info->stats[max_chan_H].ACK_speed_avg, shm_conn_info->stats[max_chan_H].exact_rtt);
        }

        // TODO: what to do if these two methods disagree? Is it possible?
        
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ( (chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (i != shm_conn_info->max_chan) && (i != exclude) /* && check_plp_ok(i, chan_mask)*/) {
                if( !percent_delta_equal(shm_conn_info->stats[i].ACK_speed_avg, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed_avg, 10)
                         && ( shm_conn_info->stats[i].ACK_speed_avg > shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed_avg )) { // 15% corridor to consider speeds the same
                    max_chan_H = i;
                    vlog(LOG_INFO, "ACS>>: Need changing HEAD to %d with ACS %d > ACS(max) %d", i, shm_conn_info->stats[i].ACK_speed_avg, shm_conn_info->stats[shm_conn_info->max_chan].ACK_speed_avg);
                }
            }
        }
        
        // TODO HERE: What if Wf < Wh and Sf > Sh => RSRf < RSRh => f can not get full speed due to RSRf
        if(max_chan_H != -1 && max_chan_CS == -1) {
//                        vlog(LOG_INFO, "Head change H");
            //shm_conn_info->max_chan = max_chan_H;
            new_max_chan = max_chan_H;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
            shm_conn_info->last_switch_time.tv_sec += immune_sec;
        } else if (max_chan_H == -1 && max_chan_CS != -1) {
            vlog(LOG_INFO, "Head change CS");
            //shm_conn_info->max_chan = max_chan_CS;
            new_max_chan = max_chan_CS;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
            shm_conn_info->last_switch_time.tv_sec += immune_sec;
        } else if (max_chan_H != -1 && max_chan_CS != -1) {
            if(max_chan_H != max_chan_CS) {
                vlog(LOG_INFO, "Head change: CS/CH don't agree with Si/Sh: using latter");
            }
            //shm_conn_info->max_chan = max_chan_H;
            new_max_chan = max_chan_H;
            fixed = 1;
            shm_conn_info->last_switch_time = info.current_time;
            shm_conn_info->last_switch_time.tv_sec += immune_sec;
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
                vlog(LOG_INFO, "Head change - first alive (default): %s(%d), excluded: %d ACS2=%d,PCS2=%d (idle? %d)",
                        shm_conn_info->stats[alive_chan].name, alive_chan, exclude, shm_conn_info->stats[alive_chan].max_ACS2,
                        shm_conn_info->stats[alive_chan].max_PCS2, shm_conn_info->idle);
                shm_conn_info->max_chan = alive_chan; // change immedialtey
                shm_conn_info->max_chan_new = alive_chan;
                new_max_chan = alive_chan;
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
                    vlog(LOG_INFO, "Head no change - first and only channel dead: %d, excluded: %d", alive_chan, exclude);
                    shm_conn_info->max_chan = alive_chan;
                    shm_conn_info->max_chan_new = alive_chan;
                    new_max_chan = alive_chan;
                } else {
                    vlog(LOG_ERR, "WARNING! No chan is alive; no head (undefined): %d", shm_conn_info->max_chan);
                }
            }
            if(alive_cnt > 1) {
                // all is OK
                vlog(LOG_INFO, "Head detect - current max chan is correct: max_chan=%d, exclude=%d", shm_conn_info->max_chan, exclude);
            }
        }
    }
    if(new_max_chan == -1) {
        //vlog(LOG_INFO, "Head detect - no new head max_chan=%d, exclude=%d", shm_conn_info->max_chan, exclude);
        shm_conn_info->head_detected_ts = info.current_time;
        shm_conn_info->max_chan_new = shm_conn_info->max_chan;
        return fixed;
    }
    if(new_max_chan != shm_conn_info->max_chan_new) {
        shm_conn_info->head_detected_ts = info.current_time;
        shm_conn_info->max_chan_new = new_max_chan;
        // TODO HERE: for AG_MODE use different hsqs calc! see #731
        int hsqs = shm_conn_info->stats[shm_conn_info->max_chan].sqe_mean - shm_conn_info->stats[shm_conn_info->max_chan_new].sqe_mean;
        if(hsqs <= 0) htime = 0;
        else htime = transition_period_time(hsqs);
        if(htime < HEAD_HYSTERESIS_MIN_MS) shm_conn_info->head_change_htime = HEAD_HYSTERESIS_MIN_MS; // ms? // TODO: variable constant!
        ms2tv(&shm_conn_info->head_change_htime_tv, shm_conn_info->head_change_htime);
        vlog(LOG_INFO, "Head detect - New head wait start max_chan=%d, exclude=%d TIME=%d ms", shm_conn_info->max_chan, exclude, shm_conn_info->head_change_htime);
    } else {
        vlog(LOG_INFO, "Head detect - New head is not new - NO WAIT max_chan=%d, exclude=%d", shm_conn_info->max_chan, exclude);
    }
    
    timersub(&info.current_time, &shm_conn_info->head_detected_ts, &tv_tmp);
    //if(timercmp(&tv_tmp, &((struct timeval) HEAD_REDETECT_HYSTERESIS_TV), >=)) {
    if(timercmp(&tv_tmp, &shm_conn_info->head_change_htime_tv, >=)) {
        vlog(LOG_INFO, "Head detect - wait timer triggered max_chan=%d, exclude=%d", shm_conn_info->max_chan, exclude);
        shm_conn_info->max_chan = shm_conn_info->max_chan_new;
        shm_conn_info->head_detected_ts = info.current_time;
    }
    // now re-calculate lossing for new head
    timersub(&(info.current_time), &(shm_conn_info->stats[max_chan].real_loss_time), &tv_tmp);
    if(timercmp(&tv_tmp, &((struct timeval) {DROPPING_LOSSING_DETECT_SECONDS, 0}), >=)) {
        // noop
    } else {
        shm_conn_info->head_lossing = 1;
        shm_conn_info->idle = 0;
    }    
    return fixed;
}

int hsnum2pnum(int hsnum) {
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if(hsnum == shm_conn_info->stats[i].hsnum) {
            return i;
        }
    }
    if(hsnum == 65535) { // it is okay to have this value - means we ignore
        return -1;
    }
    vlog(LOG_ERR, "ASSERT FAILED: hsnum not found: %d", hsnum);
    return -1;
}

uint32_t name2hsnum(char *name) {
    int i = 0;
    unsigned char ch = name[0];
    uint32_t sum = 0;
    while(ch != 0) {
        ch = name[i];
        sum += ch;
        i++;
    }
    return sum % 31;
}

uint32_t ag_mask2hsag_mask(uint32_t ag_mask) {
    uint32_t hsag_mask = 0;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if(ag_mask & (1 << i)) {
            hsag_mask |= (1 << shm_conn_info->stats[i].hsnum); // set bin mask to 1
        }
    }
    return hsag_mask;
}

uint32_t hsag_mask2ag_mask(uint32_t hsag_mask) {
    uint32_t ag_mask = 0;
    int hs;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if(hsag_mask & (1 << i)) {
            hs = hsnum2pnum(i);
            if(hs > -1) {
                ag_mask |= (1 << hs); // set bin mask to 1
            }
        }
    }
    return ag_mask;
}
/* M = Wmax, W = desired Wcubic */
double t_from_W (double W, double M, double B, double C) {
    // Math form: t = ((B M)/C)^(1/3)+(C^2 W-C^2 M)^(1/3)/C
    //vlog(LOG_INFO, "t_from_W = %d", (int)(cbrt(B * M / C) + cbrt( (W - M) / C )));
    return cbrt(B * M / C) + cbrt( (W - M) / C );
}

int get_t_loss(struct timeval *loss_tv, int tmax) {
    struct timeval t_tv;
    timersub(&(info.current_time), loss_tv, &t_tv);
    int t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
    t = t / CUBIC_T_DIV;
    t = t > tmax ? tmax : t; // 400s limit
    return t;
}

int cubic_recalculate(int t, int cubic_max, double beta, double c) {
    double K = cbrt((((double) cubic_max) * beta) / c);
    double tp = ((double) (t)) - K;
    return (uint32_t) (c * tp*tp*tp + cubic_max); // TODO: calculate in integers!
}

int set_W_cubic_unrecoverable(int t) {
    shm_conn_info->stats[info.process_num].W_cubic_u = cubic_recalculate(t, info.W_u_max, info.Bu, info.Cu);
}

// t in ms
int set_W_unsync(int t) {
    info.send_q_limit_cubic = cubic_recalculate(t, info.send_q_limit_cubic_max, info.B, info.C);
    shm_conn_info->stats[info.process_num].W_cubic = info.send_q_limit_cubic;
    //vlog(LOG_INFO, "set W t=%d, W=%d, Wmax=%d", t, info.send_q_limit_cubic, info.send_q_limit_cubic_max);
    return 1;
}

int set_W_to(int send_q, int slowness, struct timeval *loss_time) {
    *loss_time = info.current_time;
    //vlog(LOG_INFO, "set W to, sq=%d", send_q);
    info.send_q_limit_cubic_max = send_q;
    set_W_unsync(0);
}

int set_Wu_to(int send_q) {
    info.u_loss_tv = info.current_time;
    info.W_u_max = send_q;
    info.cubic_t_max_u = t_from_W(RSR_TOP, info.W_u_max, info.Bu, info.Cu); // TODO: place it everywhere whenever W_u_max changes??
    shm_conn_info->stats[info.process_num].W_cubic_u = cubic_recalculate(0, info.W_u_max, info.Bu, info.Cu);
}

int set_IDLE() {
    uint32_t chan_mask = shm_conn_info->channels_mask;
    struct timeval tv_tmp_tmp_tmp;
   
    sem_wait(&(shm_conn_info->stats_sem));
    timersub(&info.current_time, &shm_conn_info->last_switch_time, &tv_tmp_tmp_tmp);
    int idle = 1;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
            if( (shm_conn_info->stats[i].sqe_mean > SEND_Q_EFF_WORK) || (shm_conn_info->stats[i].ACK_speed > ACS_NOT_IDLE) ) {
                idle = 0;
            }
        }
    }

    if(!idle) {
        shm_conn_info->idle = 0; 
    } else {
        shm_conn_info->idle = 1;
        shm_conn_info->slow_start = 0; // Second slow_start exit here: at IDLE - just in case. No specific purpose.
    }
    
    if(shm_conn_info->idle) {
        shm_conn_info->stats[info.process_num].l_pbl_tmp = INT32_MAX; // when idling, PBL is unknown!
        shm_conn_info->stats[info.process_num].l_pbl_tmp_unrec = INT32_MAX; // when idling, PBL is unknown!
        shm_conn_info->stats[info.process_num].loss_send_q = LOSS_SEND_Q_UNKNOWN;
    }
    
    sem_post(&(shm_conn_info->stats_sem));
    return 0;
}

int plp_avg_pbl(int pnum) {
    if(shm_conn_info->stats[pnum].l_pbl_tmp > shm_conn_info->stats[pnum].l_pbl_recv) {
        shm_conn_info->stats[pnum].l_pbl = shm_conn_info->stats[pnum].l_pbl_tmp;
        return shm_conn_info->stats[pnum].l_pbl_tmp;
    } else {
        shm_conn_info->stats[pnum].l_pbl = shm_conn_info->stats[pnum].l_pbl_recv;
        return shm_conn_info->stats[pnum].l_pbl_recv;
    }
}

int plp_avg_pbl_unrecoverable(int pnum) {
    if(shm_conn_info->stats[pnum].l_pbl_tmp_unrec > shm_conn_info->stats[pnum].l_pbl_unrec_avg) {
        if(shm_conn_info->stats[pnum].l_pbl_unrec_avg < INT32_MAX / PBL_SMOOTH_NUMERATOR) {
            return PBL_SMOOTH_NUMERATOR * shm_conn_info->stats[pnum].l_pbl_unrec_avg / PBL_SMOOTH_DENOMINATOR + shm_conn_info->stats[pnum].l_pbl_tmp_unrec / PBL_SMOOTH_DENOMINATOR;
        } else {
            return shm_conn_info->stats[pnum].l_pbl_unrec_avg;
        }
    } else {
        return shm_conn_info->stats[pnum].l_pbl_unrec_avg;
    }
}

int fill_path_descs_unsync(struct mini_path_desc *path_descs, uint32_t chan_mask) {
    int p=0;
    memset((void *)path_descs, 0, sizeof(path_descs));
    
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i))
            && (!shm_conn_info->stats[i].channel_dead)) {
            path_descs[p].process_num = i;
            path_descs[p].rtt = shm_conn_info->stats[i].srtt2_100/100;
            path_descs[p].packets_between_loss = shm_conn_info->stats[i].l_pbl;
            p++;
        }
    }
    return p;
}

int compare_descs_pbl (struct mini_path_desc *a, struct mini_path_desc *b) {
     int temp = b->packets_between_loss - a->packets_between_loss; // b-a = descending
     if (temp > 0)
          return 1;
     else if (temp < 0)
          return -1;
     else
          return 0;
}

int calc_xhi(struct mini_path_desc *path_descs, int count) {
    int xhi = 0;
    double rtt,Ps,Ps_u=0,Ps_d = 0,spd;
    //int max_rtt = -1;
    int min_rtt = INT32_MAX;
    int sum_rtt = 0;
    if(count == 0) return 0;
    for (int i=0; i< count; i++ ) {
        if(shm_conn_info->stats[path_descs[i].process_num].brl_ag_enabled) {
            spd = (double) shm_conn_info->stats[path_descs[i].process_num].ACK_speed/info.eff_len;
            Ps_u += spd / (double)path_descs[i].packets_between_loss;
            Ps_d += spd;
            sum_rtt += path_descs[i].rtt;
            //if(path_descs[i].rtt > max_rtt) {
            //    max_rtt = path_descs[i].rtt;
            //}
            if(path_descs[i].rtt && (path_descs[i].rtt < min_rtt)) {
                min_rtt = path_descs[i].rtt;
            }
        }
    }

    Ps = Ps_u / Ps_d;
    //rtt = (double) (sum_rtt / count);
    rtt = (double) min_rtt;
    rtt /= 1000; // ms -> s

    double maxwin = 1.17 * pow( rtt/Ps, 3.0/4.0 );
#define TCP_MINWIN 49.0
    if(maxwin < TCP_MINWIN) maxwin = TCP_MINWIN; // protect us from dropping window too much on very-high-speed links (see office wi-fi)
    // TODO: this is uninvestigated area: cubic seems to behave differently on lower-cwnd areas and lower RTTs (hystart?)
    xhi = (int) round( maxwin / rtt );

    return xhi;
}

double xhi_function(int rtt_ms, int pbl) {
    double rtt = rtt_ms;
    rtt /= 1000.0;
    double plp = pbl;
    plp = 1.0 / plp;
    
    double maxwin = 1.17 * pow( rtt / plp, 3.0/4.0 );
    int xhi = (int) round( maxwin / rtt );
    return xhi * info.eff_len;
}

int print_xhi_data(struct mini_path_desc *path_descs, int count) {
    for (int i=0; i< count; i++ ) {
        vlog(LOG_INFO, "XHI: pnum=%d rtt=%d, pbl=%d, ACS=%d, ENB=%d", path_descs[i].process_num, 
                path_descs[i].rtt, path_descs[i].packets_between_loss, shm_conn_info->stats[path_descs[i].process_num].ACK_speed/info.eff_len, shm_conn_info->stats[path_descs[i].process_num].brl_ag_enabled);
    }
}

int set_xhi_brl_flags_unsync() {
    uint32_t chan_mask = shm_conn_info->channels_mask;
    struct mini_path_desc path_descs[MAX_TCP_PHYSICAL_CHANNELS];
    int count = fill_path_descs_unsync(path_descs, chan_mask);
    int xhi;
    // TODO; what if highest speed chan != lowest p chan?
    // maybe sort by speed instead?
    qsort(path_descs, count, sizeof(struct mini_path_desc), compare_descs_pbl);
    // 1. find worst rtt from AG chans
    // 1.1 calculate sum speed of ALL alive chans
    int sum_speed = 0;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if (       (chan_mask & (1 << i)) 
                && (!shm_conn_info->stats[i].channel_dead)) {
            sum_speed += shm_conn_info->stats[i].ACK_speed / info.eff_len;
        }
    }

    // 2. now calc xhi and Ps and set flags per chans
    // 2.1 first, enable one channel
    shm_conn_info->stats[path_descs[0].process_num].brl_ag_enabled = 1;
    print_xhi_data(path_descs, count);
    xhi = calc_xhi(path_descs, count);
    vlog(LOG_INFO, "XHI: %d, TOTspeed: %d", xhi, sum_speed);

    // 2.2 try to add each chan one-by-one and calculate total xhi
    for(int j=1; j<count; j++) {
        shm_conn_info->stats[path_descs[j].process_num].brl_ag_enabled = 1;
        print_xhi_data(path_descs, count);
        xhi = calc_xhi(path_descs, count);
        vlog(LOG_INFO, "XHI: %d, TOTspeed: %d", xhi, sum_speed);
        if(xhi < sum_speed) { // TODO: really sum_speed ? or maybe sum of the above? or just max speed chan?
            shm_conn_info->stats[path_descs[j].process_num].brl_ag_enabled = 0;
            break;
        }
    }
    return xhi;
}

int lossed_count() {
    int cnt = 0;
    int idx_prev = info.lossed_complete_received;
    int idx = idx_prev;
    uint32_t last_sqn_lost = 0;
    unsigned int old_lsn = info.lossed_loop_data[idx].local_seq_num;
    int pkt_shift = 1;
    while(idx != info.lossed_last_received) {
        idx++;
        if(idx >= LOSSED_BACKLOG_SIZE) idx = 0;
        if((info.lossed_loop_data[info.lossed_complete_received].local_seq_num + pkt_shift) == info.lossed_loop_data[idx].local_seq_num) {
            // ok
        } else {
            cnt++;
            last_sqn_lost = info.lossed_loop_data[info.lossed_complete_received].local_seq_num + pkt_shift;
            if(cnt == 1) {
                info.lossed_local_seq_num_lost_start = last_sqn_lost;
            }
        }
        idx_prev = idx;
        pkt_shift++;
    }
    // WARNING: TODO: replacing normal loss-only counter by full range of loss including non-lost here
    //return cnt;
    return last_sqn_lost - info.lossed_local_seq_num_lost_start + 1;
}

int lossed_latency_drop(unsigned int *last_received_seq) {
    // finish waiting for packets by latency; should be called by FCI process
    if(!lossed_count()) {
        vlog(LOG_ERR, "ASSERT FAILED: lossed_latency_drop called with no loss!");
    }
    vlog(LOG_INFO, "Registering loss +%d by LATENCY lsn: %d; last lsn: %d, sqn: %d, last ok lsn: %d", lossed_count(), info.lossed_loop_data[info.lossed_last_received].local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, info.lossed_loop_data[info.lossed_last_received].seq_num, info.lossed_loop_data[info.lossed_complete_received].local_seq_num);
    //lossed_print_debug();
    int loss = lossed_count();
    msbl_push_up_loss_unsync();
    if(loss > UNRECOVERABLE_LOSS) {
        vlog(LOG_INFO, "Detected unrecoverable loss of %d packets", loss);
        shm_conn_info->seq_num_unrecoverable_loss = shm_conn_info->write_buf[1].last_received_seq[info.process_num];
    }
    info.lossed_complete_received = info.lossed_last_received;
    *last_received_seq = info.lossed_loop_data[info.lossed_last_received].local_seq_num;
    return loss;
}

int is_loss() {
    if(info.lossed_last_received != info.lossed_complete_received) {
        return 1;
    }
    return 0;
}

int lossed_consume(unsigned int local_seq_num, unsigned int seq_num, unsigned int *last_received_seq, unsigned int *last_local_received_seq) {
    // 1. try to fill in the array with lsn
    // 1.1 shift the cursors if all OK
    // 2. detect loss events by setting flags for FCI
    // 3. set up loss cutoff for tflush
    // 4. upon loss, shift the cursor
   
    // TODO: local seq add at FCI receive
    // TODO: rtt and send_q calculations
    
    // TODO: may be optimized by not doing excessive *last_local_received_seq = local_seq_num
   
    // local_seq_num is init at 1 so it is okay to start right-away
    int s_shift = local_seq_num - info.lossed_loop_data[info.lossed_last_received].local_seq_num;
    int new_idx = info.lossed_last_received + s_shift;
    
    if(new_idx >= LOSSED_BACKLOG_SIZE) {
        new_idx = new_idx - LOSSED_BACKLOG_SIZE;
    }
    
/*    
    if(new_idx >= LOSSED_BACKLOG_SIZE) {
        vlog(LOG_INFO, "WARNING lossed_consume protecting from OVERFLOW new_idx is %d, lsn: %d; last lsn: %d, sqn: %d", new_idx, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        new_idx = 0;
    }
*/  

    if(new_idx < 0) {
        new_idx = LOSSED_BACKLOG_SIZE + new_idx;
    }
    
/*    
    if(new_idx < 0) {
        vlog(LOG_INFO, "WARNING lossed_consume protecting from OVERFLOW #2 new_idx is %d, lsn: %d; last lsn: %d, sqn: %d", new_idx, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        new_idx = 0;
    }
    
    if(new_idx >= LOSSED_BACKLOG_SIZE) {
        // TODO: remove this - should never fire!
        vlog(LOG_INFO, "WARNING lossed_consume protecting from OVERFLOW #3 new_idx is %d, lsn: %d; last lsn: %d, sqn: %d", new_idx, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        new_idx = 0;
    }
*/

    if(new_idx >= LOSSED_BACKLOG_SIZE || new_idx < 0) {
        //lossed_print_debug();
        vlog(LOG_ERR, "Warning! Reorder buffer overflow LOSSED_BACKLOG_SIZE=%d; lsn: %d; last lsn: %d, sqn: %d", LOSSED_BACKLOG_SIZE, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        need_send_loss_FCI_flag = LOSSED_BACKLOG_SIZE;
        vlog(LOG_INFO, "Detected unrecoverable loss of at least %d packets", LOSSED_BACKLOG_SIZE);
        shm_conn_info->seq_num_unrecoverable_loss = seq_num;
        msbl_push_up_loss_unsync();
        info.lossed_complete_received = 0;
        info.lossed_last_received = 0;
        info.lossed_loop_data[0].local_seq_num = local_seq_num;
        info.lossed_loop_data[0].seq_num = seq_num;
        *last_received_seq = seq_num;
        *last_local_received_seq = local_seq_num;
        return 0;
    }
    
    if(s_shift >= LOSSED_BACKLOG_SIZE) {
        //lossed_print_debug();
        vlog(LOG_ERR, "Warning! Reordering (or loss) is larger than LOSSED_BACKLOG_SIZE=%d; lsn: %d; last lsn: %d, sqn: %d", LOSSED_BACKLOG_SIZE, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        need_send_loss_FCI_flag = LOSSED_BACKLOG_SIZE;
        vlog(LOG_INFO, "Detected unrecoverable loss of at least %d packets", LOSSED_BACKLOG_SIZE);
        shm_conn_info->seq_num_unrecoverable_loss = seq_num;
        msbl_push_up_loss_unsync();
        info.lossed_complete_received = new_idx;
        info.lossed_last_received = new_idx;
        info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
        info.lossed_loop_data[new_idx].seq_num = seq_num;
        *last_received_seq = seq_num;
        *last_local_received_seq = local_seq_num;
        return 0;
    }
    
    if( (s_shift == 1) && (info.lossed_complete_received == info.lossed_last_received)) {
        //vlog(LOG_INFO, "Lossed: normally consuming packet lsn: %d; last lsn: %d, sqn: %d, new_idx: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num, new_idx);
        info.lossed_last_received = new_idx;
        info.lossed_complete_received = new_idx;
        info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
        info.lossed_loop_data[new_idx].seq_num = seq_num;
        *last_received_seq = seq_num;
        *last_local_received_seq = local_seq_num;
        //lossed_print_debug();
        return 0;
    }
    
    if(local_seq_num < info.lossed_loop_data[info.lossed_complete_received].local_seq_num) {
        //lossed_print_debug();
        // now check if it is dup or LATE
        if(info.lossed_loop_data[new_idx].local_seq_num == local_seq_num) {
            vlog(LOG_INFO, "DUP lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        } else {
            vlog(LOG_INFO, "LATE? max_reorder is %d, lsn: %d; last lsn: %d, sqn: %d", (info.lossed_last_received-new_idx), local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
            need_send_loss_FCI_flag = -1; // inform that we are experiencing reorder
            if(shm_conn_info->stats[info.process_num].pbl_lossed_saved != 0) {
                vlog(LOG_INFO, "Restoring local pbl counters pbl_lossed %d, pbl_lossed_cnt %d", shm_conn_info->stats[info.process_num].pbl_lossed_saved, shm_conn_info->stats[info.process_num].pbl_lossed_cnt_saved);
                shm_conn_info->stats[info.process_num].pbl_lossed = shm_conn_info->stats[info.process_num].pbl_lossed_saved;
                shm_conn_info->stats[info.process_num].pbl_lossed_cnt = shm_conn_info->stats[info.process_num].pbl_lossed_cnt_saved;
                
                shm_conn_info->stats[info.process_num].pbl_lossed_saved = 0;
            }
        }
        *last_received_seq = info.lossed_loop_data[info.lossed_complete_received].seq_num;
        *last_local_received_seq = info.lossed_loop_data[info.lossed_complete_received].local_seq_num;
        return -1;
    }
   
    int reordering = local_seq_num - info.lossed_loop_data[info.lossed_complete_received].local_seq_num;
    if(reordering > MAX_REORDER_PERPATH) {
        *last_received_seq = seq_num;
        *last_local_received_seq = local_seq_num;
        info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
        info.lossed_loop_data[new_idx].seq_num = seq_num;
        info.lossed_last_received = new_idx;
        int loss_calc = lossed_count();
        vlog(LOG_INFO, "Detected loss +%d by REORDER lsn: %d; last lsn: %d, sqn: %d, lsq before loss %d", loss_calc, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num, info.lossed_loop_data[info.lossed_complete_received].local_seq_num);
        if(loss_calc > UNRECOVERABLE_LOSS) {
            vlog(LOG_INFO, "Detected unrecoverable loss of %d packets", loss_calc);
            shm_conn_info->seq_num_unrecoverable_loss = seq_num;
        }
        info.lossed_complete_received = new_idx;
        // now push up MSBL
        msbl_push_up_loss_unsync();
        need_send_loss_FCI_flag = loss_calc;
        //lossed_print_debug();
        return loss_calc;
    }
    
    // now we have finished error handling - now account for pure data receipt
    
    if(s_shift > 1) {
        //lossed_print_debug();
        vlog(LOG_INFO, "loss +%d lsn: %d; last lsn: %d, sqn: %d", (s_shift - 1), local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        info.lossed_last_received = new_idx;
        info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
        info.lossed_loop_data[new_idx].seq_num = seq_num;
        *last_received_seq = info.lossed_loop_data[info.lossed_complete_received].seq_num;
        *last_local_received_seq = info.lossed_loop_data[info.lossed_complete_received].local_seq_num;
        return s_shift - 1;
    }
    
    if(s_shift == 1) {
        // if s_shift == 1 && (info.lossed_complete_received != info.lossed_last_received)
        vlog(LOG_INFO, "Append packet +REORDER lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        info.lossed_last_received = new_idx;
        info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
        info.lossed_loop_data[new_idx].seq_num = seq_num;
        *last_received_seq = info.lossed_loop_data[info.lossed_complete_received].seq_num;
        *last_local_received_seq = info.lossed_loop_data[info.lossed_complete_received].local_seq_num;
        //lossed_print_debug();
        return -3;
    }
    
    // again, detect DUPs
    if(local_seq_num == info.lossed_loop_data[new_idx].local_seq_num) {
        //lossed_print_debug();
        vlog(LOG_INFO, "DUP +REORDER lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        *last_received_seq = info.lossed_loop_data[info.lossed_complete_received].seq_num;
        *last_local_received_seq = info.lossed_loop_data[info.lossed_complete_received].local_seq_num;
        return -2;
    }
    
    // now try to re-assemble
    // [ 0 1[2]  4 5 6 7 8 9 ]
    //         3
    
    // add data to its position
    //lossed_print_debug();
    vlog(LOG_INFO, "reorder -1 lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
    info.lossed_loop_data[new_idx].local_seq_num = local_seq_num;
    info.lossed_loop_data[new_idx].seq_num = seq_num;
    
    int next_missed;
    
    while(1) {
        next_missed = info.lossed_complete_received + 1;
        if(next_missed >= LOSSED_BACKLOG_SIZE) next_missed = next_missed - LOSSED_BACKLOG_SIZE;
        //TODO here: protect from double overflow
        if(next_missed >= LOSSED_BACKLOG_SIZE) { 
            next_missed = 0;
            vlog(LOG_INFO, "WARNING lossed_consume protecting from OVERFLOW next_missed is %d, lsn: %d; last lsn: %d, sqn: %d", next_missed, local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
        }
        
        if(info.lossed_loop_data[next_missed].local_seq_num == info.lossed_loop_data[info.lossed_complete_received].local_seq_num + 1) {
            info.lossed_complete_received = next_missed;
            if(info.lossed_loop_data[next_missed].seq_num != 0) { // 0 is set by FCI seq_num (0)
                *last_received_seq = info.lossed_loop_data[next_missed].seq_num;
                *last_local_received_seq = info.lossed_loop_data[next_missed].local_seq_num;
            } else {
                vlog(LOG_INFO, "Warning! Cannot set last_received_seq as it is 0! lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
                *last_local_received_seq = info.lossed_loop_data[next_missed].local_seq_num;
            }
        } else {
            return info.lossed_complete_received - info.lossed_complete_received - 1;
        }
        
        if(info.lossed_complete_received == info.lossed_last_received) {
            //lossed_print_debug();
            vlog(LOG_INFO, "reorder reassembled. lsn: %d; last lsn: %d, sqn: %d", local_seq_num, info.lossed_loop_data[info.lossed_last_received].local_seq_num, seq_num);
            return 0;
        }
    }
    return -1;
}

int get_rttlag(uint32_t ag_mask) {
    uint32_t chan_mask = shm_conn_info->channels_mask;
    if(NumberOfSetBits(ag_mask)< 2) {
        return 0;
    } else {
        int min_rtt = INT32_MAX;
        int max_rtt = 0;
        int chamt = 0;
        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (ag_mask & (1 << i))) { 
                if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                    min_rtt = shm_conn_info->stats[i].exact_rtt;
                }

                if(max_rtt < shm_conn_info->stats[i].exact_rtt) {
                    max_rtt = shm_conn_info->stats[i].exact_rtt;
                }
                chamt++;
            }
        }
        if(chamt > 1) {
            // now check that max_rtt_lag is adequate
            if(max_rtt > (min_rtt * RTT_THRESHOLD_MULTIPLIER)) {
                vlog(LOG_INFO, "WARNING! max_rtt_lag is %d > min_rtt * 7 %d", max_rtt, min_rtt);
                max_rtt = min_rtt * RTT_THRESHOLD_MULTIPLIER;
            }
            return max_rtt; // correct is max_rtt only // assume whole RTT is bufferbloat so PT >> rtt_phys
        } else {
            return 0; // correct is max_rtt only
        }
    }
}

int get_rto_usec() {
    int sum_rtt = (shm_conn_info->rttvar_worst) * 1000;
    if(sum_rtt > info.max_latency_drop.tv_usec) {
        return sum_rtt;
    }
    return info.max_latency_drop.tv_usec;
}

// compute controlled - "lagger" based buf len
int get_lbuf_len() {
    uint32_t chan_mask = shm_conn_info->channels_mask;
    int tail_idx = shm_conn_info->write_buf[1].frames.rel_tail;
    if(tail_idx == -1) {
        return 0;
    }
    int pktdiff = shm_conn_info->frames_buf[tail_idx].seq_num - shm_conn_info->write_buf[1].last_written_seq;
    return pktdiff; // always return ibl
    if(NumberOfSetBits(shm_conn_info->ag_mask_recv)< 2) {
       int lbl =  shm_conn_info->write_buf[1].last_received_seq[shm_conn_info->remote_head_pnum] - shm_conn_info->write_buf[1].last_written_seq; // tcp_cwnd = lbl + gSQ
        //shm_conn_info->lbuf_len = lbl; // we are writing versus HEAD?
        return lbl;
    }
    return info.least_rx_seq[1] - shm_conn_info->write_buf[1].last_written_seq; // this can result in negative values when AG-on switch happens
}
int set_rttlag() { // TODO: rewrite using get_rttlag
    uint32_t chan_mask = shm_conn_info->channels_mask;
    int min_rtt = INT32_MAX;
    int min_rtt_chan = shm_conn_info->max_chan;
    int max_rtt = 0;
    int max_rtt_chan = shm_conn_info->max_chan;
    int chamt = 0;
    
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        // if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask_recv & (1 << i))) { // hope this works..
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask & (1 << i))) { // hope this works..
            if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                min_rtt = shm_conn_info->stats[i].exact_rtt;
                min_rtt_chan = i;
            }

            if(max_rtt < shm_conn_info->stats[i].exact_rtt) {
                max_rtt = shm_conn_info->stats[i].exact_rtt;
                max_rtt_chan = i;
            }
            chamt++;
        }
    }
    
    if(chamt > 1) {
        shm_conn_info->max_rtt_pnum_checkonly = max_rtt_chan;
        shm_conn_info->min_rtt_pnum_checkonly = min_rtt_chan;
        // now check that max_rtt_lag is adequate
        // if(max_rtt > (min_rtt * RTT_THRESHOLD_MULTIPLIER)) {
        //     vlog(LOG_INFO, "WARNING! max_rtt_lag is %d > min_rtt * 7 %d", max_rtt, min_rtt);
        //     max_rtt = min_rtt * RTT_THRESHOLD_MULTIPLIER;
        // }
        // shm_conn_info->max_rtt_lag = max_rtt; // correct is max_rtt only // assume whole RTT is bufferbloat so PT >> rtt_phys
    } else {
        // shm_conn_info->max_rtt_lag = 0; // correct is max_rtt only
        shm_conn_info->max_rtt_pnum_checkonly = -1;
        shm_conn_info->min_rtt_pnum_checkonly = -1;
    }
    
}

int set_rttlag_total() {  // unused TODO REMOVE
    uint32_t chan_mask = shm_conn_info->channels_mask;
    int min_rtt = INT32_MAX;
    int min_rtt_var = INT32_MAX;
    int min_rtt_chan = shm_conn_info->max_chan;
    int max_rtt = 0;
    int max_rtt_var = 0;
    int max_rtt_chan = shm_conn_info->max_chan;
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        // TODO HERE: WARNING: here we determine max allowed channels latency difference as MLD*2 milliseconds (see #659)
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && 
                (shm_conn_info->stats[i].exact_rtt - shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt < MAX_LATENCY_DROP_USEC/500)) { // get total possible lag
            if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                min_rtt = shm_conn_info->stats[i].exact_rtt;
                min_rtt_var = shm_conn_info->stats[i].rttvar;
                min_rtt_chan = i;
            }

            if(max_rtt < shm_conn_info->stats[i].exact_rtt) {
                max_rtt = shm_conn_info->stats[i].exact_rtt;
                max_rtt_var = shm_conn_info->stats[i].rttvar;
                max_rtt_chan = i;
            }
        }
    }
    shm_conn_info->total_min_rtt = min_rtt;
    shm_conn_info->total_min_rtt_var = min_rtt_var;
    shm_conn_info->total_max_rtt = max_rtt;
    shm_conn_info->total_max_rtt_var = max_rtt_var;
    //vlog(LOG_INFO, "computed max_rtt: %d, max_rtt_var: %d, min_rtt %d, min_rtt_var: %d", max_rtt, max_rtt_var, min_rtt, min_rtt_var);
}

int infer_lost_seq_num(uint32_t *incomplete_seq_buf) {
    // Search write_buf for lost seq_num
    int ms_token;
    int buf_len;
    uint32_t chan_mask = shm_conn_info->channels_mask;
    get_write_buf_wait_data(chan_mask, &ms_token);
    // now that least_rx_seq calculated, see if we have direct loss detected
    // TODO: speculative loss detection
    //      speculative loss is less effective here though as waiting for 20+ packets is crucial time
    int incomplete_seq_len = missing_resend_buffer(1, incomplete_seq_buf, &buf_len, info.least_rx_seq[1]);    
    if(incomplete_seq_len <= 2) { // TODO: how will this interact with per-local-seq retransmissions?
        for(int i=0; i<incomplete_seq_len; i++) {
            vlog(LOG_INFO, "Fast requesting packet %lu", incomplete_seq_buf[i]);
            shm_conn_info->loss_idx++;
            if (shm_conn_info->loss_idx == LOSS_ARRAY) {
                shm_conn_info->loss_idx = 0;
            }
            shm_conn_info->loss[shm_conn_info->loss_idx].timestamp = info.current_time;
            shm_conn_info->loss[shm_conn_info->loss_idx].pbl = shm_conn_info->write_sequential;
            shm_conn_info->loss[shm_conn_info->loss_idx].psl = 1;
            // TODO: who_lost
            shm_conn_info->loss[shm_conn_info->loss_idx].who_lost = -1;
            shm_conn_info->loss[shm_conn_info->loss_idx].sqn = incomplete_seq_buf[i];
        }
    }
}
int lost_buf_exists(uint32_t seq_num) {
    for(int i=0;i<LOSS_ARRAY;i++) {
        if((shm_conn_info->loss[i].sqn == seq_num) || (shm_conn_info->loss[i].sqn == (seq_num + 1))) {
            return 1;
        }
    }
    return 0;
}



int get_cwnd() {
    int max_gsend_q = 0;
    int max_gsend_q_chan = -1;
    int min_gsend_q = INT32_MAX;
    int min_gsend_q_chan = -1;
    int gsq;
    int chamt = 0;
    int full_cwnd;
    struct timeval tv_tmp;
    // 1. in case of no AG - the drop is done by head channel
    // 2. in case of AG - we should take the most lagging chan+LBL
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((shm_conn_info->channels_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && ((i == shm_conn_info->max_chan) || (shm_conn_info->ag_mask & (1 << i)))) {
            timersub(&info.current_time, &shm_conn_info->stats[i].agon_time, &tv_tmp);
            if(tv2ms(&tv_tmp) <= 2*shm_conn_info->stats[i].exact_rtt) { // switch immunity time
                // TODO: calculate real time needed for buffer to be recalculated and received
                continue; // immunity time for recalculate - wait for buffer to pripagate and to return new value
            }
            gsq = shm_conn_info->seq_counter[1] - shm_conn_info->stats[i].la_sqn;
            if(max_gsend_q < gsq) {
                max_gsend_q = gsq; 
                max_gsend_q_chan = i;
            }
            if(min_gsend_q > gsq) {
                min_gsend_q = gsq; 
                min_gsend_q_chan = i;
            }
            chamt++;
        }
    }
    // TODO: possible problem here: the channel may be in AG mode but head will resend all its packets anyway if it is not in AG itself
    if(shm_conn_info->msbl_recv > 0) {
        full_cwnd = min_gsend_q + shm_conn_info->msbl_recv;
    } else {
        full_cwnd = max_gsend_q;
    }
    return full_cwnd;
}

int get_cwnd2() {
    return shm_conn_info->seq_counter[1] - shm_conn_info->write_buf[1].remote_lws;
}

int compute_max_allowed_rtt() {
    int full_cwnd = get_cwnd();
    int spd = shm_conn_info->tpps;
    shm_conn_info->full_cwnd = full_cwnd;
    if(spd == 0) return 0;
    int max_frtt = full_cwnd * 1000 / spd; // in ms
    return max_frtt;
}

int is_happiness_reached() {
    double d_rtt = (double)shm_conn_info->stats[shm_conn_info->max_chan].exact_rtt / 1000.0;
    if(d_rtt == 0) d_rtt = 1.0;
    double my_mbits = ((double)(shm_conn_info->tpps) * (double)info.eff_len) / 1000000.0 * 8.0;
    double happy_mbits = 3.87 + 0.031 / d_rtt - 3.93 * d_rtt;
    return (my_mbits > happy_mbits);
}

int mawmar_allowed() {
    if(info.head_channel) return 1;
    int BL = (int)shm_conn_info->msbl_recv;
    /*
    int sql;
    // count all RSR/cubics?
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask & (1 << i))) { // hope this works..
            sql = 
        }
    }
    int MAW = (info.rsr > info.send_q_limit_cubic ? info.rsr : info.send_q_limit_cubic);
    int MAR = () * shm_conn_info->tpps; 
    */
    // implementing binary MSWMAR here for two channels only:
    int cwnd = get_cwnd2();
    // we are not head here...
    int max_chan = shm_conn_info->max_chan;
    //int head_limit = (shm_conn_info->stats[max_chan].rsr < shm_conn_info->stats[max_chan].W_cubic ? shm_conn_info->stats[max_chan].rsr : shm_conn_info->stats[max_chan].W_cubic);
    //int head_limit = shm_conn_info->stats[max_chan].sqe_mean; 
    int my_limit = (info.rsr < info.send_q_limit_cubic ? info.rsr : info.send_q_limit_cubic);
    //int MAW = (my_limit + head_limit) / info.eff_len;
    int MAR = (info.exact_rtt - shm_conn_info->stats[max_chan].exact_rtt) * shm_conn_info->tpps / 1000; // our rtt is greater than head's (usually we suppose)
    if(MAR < 0) MAR = -MAR; // MAR can not influence MAW as the window required to load both networks has nothing to do with jitter smoothing buffer
    statb.maw = my_limit / info.eff_len;
    statb.mar = MAR;
    if(shm_conn_info->stats[info.process_num].ag_flag_local == R_MODE) {
        //return (MAW + MAR < cwnd) && (MAR < BL);
        return (my_limit / info.eff_len < BL) && (MAR < BL); // in theory we need to check MAW+MAR - if, after we push msbl to net, we will still be able to compansate for the jitter
    } else { // AG_MODE
        return (MAR < BL); // this will automatically fail if we push all the MSBL to network
    }
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
#ifdef PROF
    int pid = getpid();
    char pbuf[30];
    sprintf(pbuf, "/tmp/vtrunkd_%d", pid);
    mkdir(pbuf, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    chdir(pbuf);
#endif
    int tpps=0;
    memset((void *)&log_tmp, 0, sizeof(log_tmp));
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
    
#ifdef SHM_DEBUG
    if (!info.process_num) {
        void *aligned_shm = (void *) (((unsigned long) shm_conn_info->void1) & ~(getpagesize() - 1));
        static const char ar[] = { 0xfe, 0xed, 0xf0, 0x0d, 0xfa, 0xce };
        int mprotect_ret = mprotect(aligned_shm, getpagesize(), PROT_NONE);
        if (mprotect_ret != 0) {
            vlog(LOG_ERR, "mprotect %s (%d)", strerror(errno), errno);
        }
        vlog(LOG_ERR, "void1 address %X aligned to page %X", shm_conn_info->void2, aligned_shm);
        aligned_shm = (void *) (((unsigned long) shm_conn_info->void2) & ~(getpagesize() - 1));
        mprotect_ret = mprotect(aligned_shm, getpagesize(), PROT_NONE);
        if (mprotect_ret != 0) {
            vlog(LOG_ERR, "mprotect %s (%d)", strerror(errno), errno);
        }
        vlog(LOG_ERR, "void2 address %X aligned to page %X", shm_conn_info->void2, aligned_shm);
        aligned_shm = (void *) (((unsigned long) shm_conn_info->void3) & ~(getpagesize() - 1));
        mprotect_ret = mprotect(aligned_shm, getpagesize(), PROT_NONE);
        if (mprotect_ret != 0) {
            vlog(LOG_ERR, "mprotect %s (%d)", strerror(errno), errno);
        }
        vlog(LOG_ERR, "void3 address %X aligned to page %X", shm_conn_info->void3, aligned_shm);
    }
#endif

    
    struct timeval MAX_REORDER_LATENCY = { 0, 50000 };

    int sq_control = 1;
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
            vlog(LOG_INFO, "Can't set cpu");
        } else {
            vlog(LOG_INFO, "Set process %i on cpu %i", info.process_num, info.process_num % cpu_numbers);
        }
    } else {
        vlog(LOG_INFO, "sysconf(_SC_NPROCESSORS_ONLN) return error");
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
        vlog(LOG_ERR,"Can't allocate buffer for the linker");
        return 0;
    }
    char *save_buf = buf;
    if( !(out_buf = lfd_alloc(VTUN_FRAME_SIZE+VTUN_FRAME_OVERHEAD)) ) {
        vlog(LOG_ERR,"Can't allocate out buffer for the linker");
        return 0;
    }
    if( !(buf2 = lfd_alloc(VTUN_FRAME_SIZE2)) ) {
        vlog(LOG_ERR,"Can't allocate buffer 2 for the linker");
        return 0;
    }
    
    struct timer_obj *recv_n_loss_send_timer = create_timer(); // TODO: create_timer may fail, should be fixed
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
        vlog(LOG_ERR, "setsockopt failed");
        linker_term = TERM_NONFATAL;
    }
    if (setsockopt(service_channel, SOL_SOCKET, SO_SNDTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
        vlog(LOG_ERR, "setsockopt failed");
        linker_term = TERM_NONFATAL;
    }
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].rtt_phys_avg = 1;
    shm_conn_info->latest_la_sqn = 0;
    strcpy(shm_conn_info->stats[info.process_num].name, lfd_host->host);
    // set up hash name
    shm_conn_info->stats[info.process_num].hsnum = name2hsnum(shm_conn_info->stats[info.process_num].name);
    sem_post(&(shm_conn_info->stats_sem));    
#ifdef CLIENTONLY
    info.srv = 0;
#endif
    if(info.srv) {
//        memset(shm_conn_info->void1,4096,1); //test mprotect
        /** Server accepted all logical channel here and get and send pid */
        // now read one single byte
        vlog(LOG_INFO,"Waiting for client to request channels...");
		read_n(service_channel, buf, sizeof(uint16_t)+sizeof(uint16_t));
        info.channel_amount = ntohs(*((uint16_t *) buf)); // include info channel
        info.channel_amount = 2; // WARNING! TODO! HARDCODED 2 hardcoded chan_amt
        if (info.channel_amount > MAX_TCP_LOGICAL_CHANNELS) {
            vlog(LOG_ERR, "Client ask for %i channels. Exit ", info.channel_amount);
            info.channel_amount = MAX_TCP_LOGICAL_CHANNELS;
            linker_term = TERM_NONFATAL;
        }
        if(info.channel_amount < 1) {
            vlog(LOG_ERR, "Client ask for %i channels. Exit ", info.channel_amount);
            info.channel_amount = 1;
            linker_term = TERM_NONFATAL;
        }
        info.channel = calloc(info.channel_amount, sizeof(*(info.channel)));
        if (info.channel == NULL) {
            vlog(LOG_ERR, "Cannot allocate memory for info.channel, process - %i, pid - %i",info.process_num, info.pid);
            return -1;
        }
        chan_info = (struct channel_info *) calloc(info.channel_amount, sizeof(struct channel_info));
        if (chan_info == NULL ) {
            vlog(LOG_ERR, "Can't allocate array for struct chan_info for the linker");
            goto finish_loop;
        }
		sem_wait(&(shm_conn_info->stats_sem));
        info.channel[0].descriptor = service_channel; // load service channel
		shm_conn_info->stats[info.process_num].pid_remote = ntohs(*((uint16_t *) (buf + sizeof(uint16_t))));
		time_lag_local.pid_remote = shm_conn_info->stats[info.process_num].pid_remote;
		time_lag_local.pid = shm_conn_info->stats[info.process_num].pid;
    	*((uint16_t *) buf) = htons(shm_conn_info->stats[info.process_num].pid);
		sem_post(&(shm_conn_info->stats_sem));
		len = write_n(service_channel, buf, sizeof(uint16_t));
 		if(len < 0) {
            vlog(LOG_ERR, "Error! failed to send pid %s(%d)", strerror(errno), errno);
            goto finish_loop;
 		}
#ifdef DEBUGG
 		vlog(LOG_ERR,"Remote pid - %d, local pid - %d", time_lag_local.pid_remote, time_lag_local.pid);
#endif
        vlog(LOG_INFO,"Will create %d channels", info.channel_amount);
        uint16_t port_tmp = lfd_host->start_port;
        if (port_tmp != 0 )
            vlog(LOG_INFO,"port range is %"PRIu16" - %"PRIu16"", lfd_host->start_port, lfd_host->end_port);
        for (int i = 1; i < info.channel_amount; i++) {
            if ((info.channel[i].descriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                vlog(LOG_ERR, "Can't create Channels socket");
                goto finish_loop;
            }

            // Get buffer size
            socklen_t optlen = sizeof(sendbuff);
            if (getsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen) == -1) {
                vlog(LOG_ERR, "Error getsockopt one");
            } else {
                vlog(LOG_INFO, "send buffer size = %d\n", sendbuff);
            }
            /*
            sendbuff = RCVBUF_SIZE;
            // WARNING! This should be on sysadmin's duty to optimize!
            if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &sendbuff, sizeof(int)) == -1) {
                vlog(LOG_ERR, "WARNING! Can not set rmem (SO_RCVBUF) size. Performance will be poor.");
            }
            */

//            prio_opt = 1;
//            setsockopt(prio_s, SOL_SOCKET, SO_REUSEADDR, &prio_opt, sizeof(prio_opt));
            for (; ; ++port_tmp <= lfd_host->end_port) {
                // try to bind to portnum my_num+smth:
                memset(&my_addr, 0, sizeof(my_addr));
                laddrlen = sizeof(localaddr);
                if (getsockname(service_channel, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                    vlog(LOG_ERR, "My port socket getsockname error; retry %s(%d)", strerror(errno), errno);
                    close(prio_s);
                    goto finish_loop;
                }
                memcpy(&my_addr.sin_addr.s_addr, &localaddr.sin_addr.s_addr, sizeof(localaddr.sin_addr.s_addr));
                my_addr.sin_port = htons(port_tmp);
                memset(&rmaddr, 0, sizeof(rmaddr));
                my_addr.sin_family = AF_INET;
                if (bind(info.channel[i].descriptor, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) {
                    if ((errno == EADDRINUSE) & (port_tmp < lfd_host->end_port)) {
                        vlog(LOG_ERR, "Can't bind port %"PRIu16", try next", port_tmp);
                    } else if ((errno == EADDRINUSE) & (port_tmp == lfd_host->end_port)) {
                        vlog(LOG_ERR, "Can't find free port in range %"PRIu16"-%"PRIu16"", lfd_host->start_port, lfd_host->end_port);
                        goto finish_loop;
                    } else {
                        vlog(LOG_ERR, "Can't bind to the Channels socket reason: %s (%d)", strerror(errno), errno);
                        goto finish_loop;
                    }
                } else {
                    break;
                }
            }
            // now get my port number
            laddrlen = sizeof(localaddr);
            if (getsockname(info.channel[i].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                vlog(LOG_ERR, "My port socket getsockname error; retry %s(%d)", strerror(errno), errno);
                close(prio_s);
                linker_term = TERM_NONFATAL;
                goto finish_loop;
                // break;
            }

            info.channel[i].lport = ntohs(localaddr.sin_port);
        }
        for (int i = 1; i < info.channel_amount; i++) {
            uint16_t hton_ret = htons(info.channel[i].lport);
            memcpy(buf + sizeof(uint16_t) * (i - 1), &hton_ret, sizeof(uint16_t));
            vlog(LOG_INFO, "Send port to client %u", info.channel[i].lport);
        }
        len = write_n(service_channel, buf, sizeof(uint16_t) * (info.channel_amount - 1));
 		if(len < 0) {
            vlog(LOG_ERR, "Error! failed to send chamt %s(%d)", strerror(errno), errno);
            goto finish_loop;
 		}


        *((uint32_t *) buf) = htonl(0); // already in htons format...
        *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_PRIO_PORT_NOTIFY);
        if (proto_write(service_channel, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
            vlog(LOG_ERR, "Could not send FRAME_PRIO_PORT_NOTIFY pkt; exit %s(%d)", strerror(errno), errno);
            close(prio_s);
            linker_term = TERM_NONFATAL;
            goto finish_loop;
        }

        // now listen to socket, wait for connection

        vlog(LOG_INFO,"Entering loop to create %d channels", info.channel_amount - 1);
        // TODO: how many TCP CONN AMOUNT allowed for server??
        for (i = 1; (i < info.channel_amount) && (i < MAX_TCP_LOGICAL_CHANNELS); i++) {
#ifdef DEBUGG
            vlog(LOG_INFO,"Chan %d", i);
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
                    vlog(LOG_ERR, "Recvfrom err on chan %i %s(%d)", i, strerror(errno), errno);
                    break_out = 1;
                    break;
                }
                connect(info.channel[i].descriptor, &cli_addr, sizeof(cli_addr));
                info.channel[i].rport = ntohs(cli_addr.sin_port);
            } else {
                vlog(LOG_ERR, "Accept timeout on chan %i", i);
                break_out = 1;
                break;
            }
            //alarm(0);
        }

        if(break_out) {
            close(prio_s);
            for(; i>=0; i--) {
                close(info.channel[i].descriptor);
            }
            linker_term = TERM_NONFATAL;
            //alarm(0); // TODO why?
            goto finish_loop;
        }

        memset(&rmaddr, 0, sizeof(rmaddr));
        memset(&localaddr, 0, sizeof(localaddr));
        rmaddrlen = sizeof(rmaddr);
        laddrlen = sizeof(localaddr);
        if (getpeername(info.channel[0].descriptor, (struct sockaddr *) (&rmaddr), &rmaddrlen) < 0) {
            vlog(LOG_ERR, "Service channel socket getsockname error; retry %s(%d)", strerror(errno), errno);
            linker_term = TERM_NONFATAL;
            goto finish_loop;
        }
        if (getsockname(info.channel[0].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
            vlog(LOG_ERR, "Service channel socket getsockname error; retry %s(%d)", strerror(errno), errno);
            linker_term = TERM_NONFATAL;
            goto finish_loop;
         }
        info.channel[0].rport = ntohs(rmaddr.sin_port);
        info.channel[0].lport = ntohs(localaddr.sin_port);

        gettimeofday(&info.current_time, NULL );
        maxfd = info.tun_device;
        for (int i = 0; i < info.channel_amount; i++) {
            vlog(LOG_INFO, "Server descriptor - %i logical channel - %i lport - %i rport - %i", info.channel[i].descriptor, i,
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
        len = write_n(service_channel, buf, sizeof(uint16_t) + sizeof(uint16_t));
 		if(len < 0) {
            vlog(LOG_ERR, "Error! failed to send pid %s(%d)", strerror(errno), errno);
            goto finish_loop;
 		}

 		len = read_n(service_channel, buf, sizeof(uint16_t));
 		if(len <= 0) {
            vlog(LOG_ERR, "Error! failed to read remote pid %s(%d)", strerror(errno), errno);
            goto finish_loop;
 		}
 		sem_wait(&(shm_conn_info->stats_sem));
 		shm_conn_info->stats[info.process_num].pid_remote = ntohs(*((uint16_t *) buf));
 		time_lag_local.pid_remote = shm_conn_info->stats[info.process_num].pid_remote;
 		sem_post(&(shm_conn_info->stats_sem));
 		vlog(LOG_INFO,"Remote pid - %d, local pid - %d", time_lag_local.pid_remote, time_lag_local.pid);

 		len = read_n(service_channel, buf, sizeof(uint16_t) * (info.channel_amount - 1));
 		if(len <= 0) {
            vlog(LOG_ERR, "Error! failed to read remote ports %s(%d)", strerror(errno), errno);
            goto finish_loop;
 		}
 		    
        vlog(LOG_INFO, "remote ports len %d", len);

        for (int i = 1; i < info.channel_amount; i++) {
            uint16_t rport_h;
            memcpy(&rport_h, buf + (i - 1) * sizeof(uint16_t), sizeof(uint16_t));
            info.channel[i].rport = ntohs(rport_h);
            vlog(LOG_INFO, "remote port recived %u", info.channel[i].rport);
        }
 		info.channel_amount = 1; // now we'll accumulate here established logical channels
    }

    // we start in a normal mode...
    if(channel_mode == MODE_NORMAL) {
        shm_conn_info->normal_senders++;
        vlog(LOG_INFO, "normal sender added: now %d", shm_conn_info->normal_senders);
    }

    sem_wait(&(shm_conn_info->AG_flags_sem));
    *((uint32_t *) buf) = htonl(shm_conn_info->session_hash_this);
    sem_post(&(shm_conn_info->AG_flags_sem));
    *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_JUST_STARTED);
    if (proto_write(service_channel, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
        vlog(LOG_ERR, "Could not send init pkt; exit");
        linker_term = TERM_NONFATAL;
        goto finish_loop;
    }
#ifdef JSON
    vlog(LOG_INFO,"{\"name\":\"%s\",\"start\":1, \"build\":\"%s\"}", lfd_host->host, BUILD_DATE);
#endif

    shm_conn_info->stats[info.process_num].weight = lfd_host->START_WEIGHT;
    
    gettimeofday(&info.current_time, NULL);
    last_action = info.current_time.tv_sec;
    long int last_net_read_ds = get_ds_ts(info.current_time); 
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


    

    struct timeval t_tv;
    struct timeval loss_time, loss_immune, loss_tv = { 0, 0 };
    gettimeofday(&loss_time, NULL);
    gettimeofday(&loss_immune, NULL);
    
    sem_wait(&(shm_conn_info->AG_flags_sem));
    last_channels_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
    drop_packet_flag = 0;
    info.Cu = CUBIC_C/8.0; // x lower
    info.C = CUBIC_C/3.0; // x lower
    //info.C = 0.9; // VERY FAST!
    info.max_send_q = 0;
    info.max_send_q_u = 0;

    gettimeofday(&info.cycle_last, NULL); // for info.rsr smooth avg
    int ag_flag_local = R_MODE;
    
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].ag_flag_local = ag_flag_local;
    shm_conn_info->last_head = info.current_time;
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
    for (int i = 0; i < info.channel_amount; i++) {
        info.channel[i].local_seq_num=1; // init to 1 for lossed
    }

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
    int send_q_eff_var = 0;
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

    t = (int) t_from_W( RSR_TOP - 10000, info.send_q_limit_cubic_max, info.B, info.C);
    struct timeval new_lag;
    ms2tv(&new_lag, t * CUBIC_T_DIV); // multiply to compensate
    timersub(&info.current_time, &new_lag, &loss_time);
    sem_wait(&(shm_conn_info->stats_sem));
    set_W_unsync(t);
    set_W_to(RSR_TOP, 1, &loss_time); // 1 means immediately!
    set_Wu_to(RSR_TOP);
    
    sem_post(&(shm_conn_info->stats_sem));
    int ELD_send_q_max = 0;
    int need_send_FCI = 0;
    info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC;
    int PCS = 0;
    int PCS_aux = 0;
    int rttvar = 0;
    info.fast_pcs_ts = info.current_time;
    int pump_adj = 0;
    int temp_sql_copy =0;
    int temp_sql_copy2 =0;
    int temp_acs_copy =0;

    struct timeval wb_1ms_time = { 0, 1000 };
    struct timeval wb_1ms_timer = info.current_time;
    
    // init pbl
    shm_conn_info->stats[info.process_num].l_pbl_tmp = INT32_MAX;
    int cubic_t_max = t_from_W(RSR_TOP, info.send_q_limit_cubic_max, info.B, info.C);
    vlog(LOG_INFO, "Cubic Tmax t=%d", cubic_t_max);
    memset(shm_conn_info->check, 170, CHECK_SZ);
    info.head_change_tv = info.current_time;
    info.head_change_safe = 1;

    //reset FRAME_L_LOSS_INFO sending
    info.last_sent_FLLI_idx = shm_conn_info->l_loss_idx;
    //reset FRAME_LOSS_INFO sending
    info.last_sent_FLI_idx = shm_conn_info->loss_idx;
    struct timeval select_tv_copy; int alive_physical_channels = 1;
    info.idle_enter = info.current_time;

    vlog_shm_set(1, &shm_conn_info->syslog.logSem, shm_conn_info->syslog.log, &shm_conn_info->syslog.counter, SHM_SYSLOG);
    int max_send_q_available = MIN_SEND_Q_BESTGUESS_3G_PKT * info.eff_len;
    struct conn_stats * my_stats = &shm_conn_info->stats[info.process_num];
    struct _events * my_events = &my_stats->events;

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
        //if((shm_conn_info->hold_mask & shm_conn_info->channels_mask) == 0) {
        //    vlog(LOG_ERR, "ASSERT FAILED! all channels in HOLD! %d", shm_conn_info->hold_mask);
        //    sig_send1();
        //}
        if(shm_conn_info->last_net_read_ds < last_net_read_ds) {
            shm_conn_info->last_net_read_ds = last_net_read_ds;
        }
        if(statb.tokens_max < shm_conn_info->tokens) {
            statb.tokens_max = shm_conn_info->tokens; // TODO: for debug only - remove!
        }
        shm_conn_info->stats[info.process_num].lssqn = last_sent_packet_num[1].seq_num;
        errno = 0;
        super++;
        plp_avg_pbl(info.process_num);
        
        gettimeofday(&info.current_time, NULL);
        // struct timespec ts_f;
        // clock_gettime(CLOCK_MONOTONIC, &ts_f);
        // TIMESPEC_TO_TIMEVAL(&info.current_time, &ts_f);
        
#ifdef TRACE_BUF_LEN
        timersub(&info.current_time, &wb_1ms_timer, &tv_tmp);
        if (timercmp(&tv_tmp, &wb_1ms_time, >)) {
            wb_1ms_timer = info.current_time;
            wb_1ms_idx++;
            if (wb_1ms_idx >= WB_1MS_SIZE) {
                wb_1ms_idx = 0;
            }
            if (start_print == wb_1ms_idx) {
                start_print++;
                if (start_print >= WB_1MS_SIZE) {
                    start_print = 0;
                }
            }
            wb_1ms[wb_1ms_idx] = shm_conn_info->write_buf[1].frames.length;
        }
#endif

        // IDLE EXIT >>>
        if( (send_q_eff_mean > SEND_Q_EFF_WORK) || (shm_conn_info->stats[info.process_num].ACK_speed > ACS_NOT_IDLE) ) {
            shm_conn_info->idle = 0; // exit IDLE immediately for all chans    
        }
        if(info.previous_idle && !shm_conn_info->idle) { // usnig local previos flag to avoid need of syncing this op!
            // detect IDLE exit and CWR-1S
            shm_conn_info->cwr_tv = info.current_time; // warning this will race into value
            //shm_conn_info->slow_start = 1;
            shm_conn_info->slow_start = 0; // disabled
            shm_conn_info->slow_start_tv = info.current_time;
            info.previous_idle = 0;
        }
        if(shm_conn_info->idle && !info.previous_idle) {
            vlog(LOG_INFO, "Entering IDLE");
            info.idle_enter = info.current_time;
        }
        info.previous_idle = shm_conn_info->idle;
        // <<< END IDLE EXIT
        
        // EXACT_RTT >>>
        if(0 && info.rtt2_lsn[1] != 0) { // rtt2 DDS detect
            timersub(&info.current_time, &info.rtt2_tv[1], &tv_tmp);
            if(tv2ms(&tv_tmp) > (info.srtt2_10 + info.srtt2var)/10) {
                info.rtt2 = tv2ms(&tv_tmp);
                if (info.rtt2 <= 0) info.rtt2 = 1;
            }
        }

        // Section to set exact_rtt
        timersub(&ping_req_tv[1], &info.rtt2_tv[1], &tv_tmp);
        if (((!shm_conn_info->idle) || timercmp(&tv_tmp, &((struct timeval) {lfd_host->PING_INTERVAL, 0}), <=)) && (info.rtt2 > 3)){ // TODO: threshold depends on phys RTT and speed; investigate that!
            if(info.rtt2 == 0) {
                vlog(LOG_INFO, "WARNING! info.rtt2 == 0!");
                info.rtt2 = 1;
            }
            exact_rtt = info.rtt2; 
            rttvar = info.srtt2var;
        } else {
            // TODO: make sure that we sent PING after high load __before__ this happens!
            if(info.rtt == 0) {
                vlog(LOG_INFO, "WARNING! info.rtt == 0!");
                info.rtt = 1;
            }
            exact_rtt = info.rtt;
            rttvar = 0;
        }
        info.exact_rtt = exact_rtt;
        // <<< END EXACT_RTT
        

        CHKCPU(7);


        // SEND_Q_EFF CALC >>>
        uint32_t my_max_send_q = info.channel[my_max_send_q_chan_num].send_q;
        int64_t bytes_pass = 0;

        timersub(&info.current_time, &info.channel[my_max_send_q_chan_num].send_q_time, &t_tv);
        int64_t upload_eff = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        if(upload_eff < 10) upload_eff = 100000; // 1000kpkts default start speed
        if((t_tv.tv_sec == 0) && (t_tv.tv_usec < info.exact_rtt * 1000)) {
            bytes_pass = (((int64_t)t_tv.tv_sec * upload_eff
                    + (((int64_t)t_tv.tv_usec/10) * upload_eff) / 100000)*3)/10;
        } else {
            bytes_pass = 0;
        }

        uint32_t speed_log = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        // removed semaphore here: exact value not required
        info.eff_len = shm_conn_info->eff_len.sum;
        // end removed sem
        send_q_eff = //my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000;
            (my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * info.eff_len) > bytes_pass ?
                    my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * info.eff_len - bytes_pass : 0;
#ifdef DEBUGG
        if(drop_packet_flag) {
        vlog(LOG_INFO,"Calc send_q_eff: %d + %d * %d - %d", my_max_send_q, info.channel[my_max_send_q_chan_num].bytes_put, info.eff_len, bytes_pass);
        } 
#endif
        // <<< END SEND_Q_EFF CALC
        
        // SLOW START DETECTOR >>>
        // sem_wait(&(shm_conn_info->write_buf_sem));
        // struct timeval ss_runtime;
        // struct timeval ss_immune = SLOW_START_IMMUNE;
        // struct timeval ss_max_run = SLOW_START_MAX_RUN;
        // timersub(&info.current_time, &shm_conn_info->slow_start_tv, &ss_runtime);
        // shm_conn_info->slow_start_allowed = 1;
        // if(timercmp(&ss_runtime, &ss_max_run, >=)) {
        //     shm_conn_info->slow_start_allowed = 0;
        //     if(shm_conn_info->slow_start) {
        //         shm_conn_info->slow_start = 0;
        //         // The ONLY slow start EXIT here!
        //         for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        //             if ((shm_conn_info->channels_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) {
        //                 // leave lossq as unknown
        //                 //if(shm_conn_info->stats[i].loss_send_q == LOSS_SEND_Q_MAX) {
        //                     //shm_conn_info->stats[i].loss_send_q = shm_conn_info->stats[i].sqe_mean / info.eff_len;
        //                 //}
        //             }
        //         }
        //         need_send_FCI = 1;
        //     }
        // }
        // if(timercmp(&ss_runtime, &ss_immune, >=)) {
        //     shm_conn_info->slow_start_allowed = 1;
        // }
        //   /* // this is slow-start -unidle KISS experiment (do a slow start on each new connection?) 
        // if(shm_conn_info->seq_counter[1] - shm_conn_info->ssd_pkts_sent >= 50) {
        //     int gsq = get_cwnd();
        //     info.gsend_q_grow = gsq - shm_conn_info->ssd_gsq_old;
        //     if((shm_conn_info->slow_start_force || (info.gsend_q_grow >= 30 && info.gsend_q_grow < 100)) && shm_conn_info->slow_start_allowed) { // grow > 100 means we have a window restore or some other crazy stuff??
        //         shm_conn_info->slow_start = 1;
        //     } else {
        //         shm_conn_info->slow_start = 0;
        //         shm_conn_info->slow_start_force = 0;
        //     }
        //     if(shm_conn_info->slow_start != shm_conn_info->slow_start_prev) {
        //         if(shm_conn_info->slow_start) {
        //             shm_conn_info->slow_start_tv = info.current_time;
        //         }
        //         need_send_FCI = 1;
        //     }
        //     shm_conn_info->slow_start_prev = shm_conn_info->slow_start;
        //     shm_conn_info->ssd_pkts_sent = shm_conn_info->seq_counter[1];
        //     shm_conn_info->ssd_gsq_old = gsq;
        // }
        // */
        // sem_post(&(shm_conn_info->write_buf_sem));
        // <<< END
        

                
        /* Temporarily disabled this due to massive loss :-\
        // EXTERNAL LOSS DETECT >>> 
        if(send_q_eff > info.send_q_limit_threshold && (send_q_eff < ELD_send_q_max) && !percent_delta_equal(send_q_eff, ELD_send_q_max, 20)) {
            vlog(LOG_INFO, "WARNING: External loss detected! send_q from %d to %d", ELD_send_q_max, send_q_eff);
            ELD_send_q_max = send_q_eff;
        } else if (send_q_eff > ELD_send_q_max) {
            ELD_send_q_max = send_q_eff;
        }
        // <<< END EXTERNAL LOSS DETECT
        */
        



        // calculate on-line RTT: >>>
        if(ping_rcvd == 0) {
            timersub(&info.current_time, &ping_req_tv[0], &tv_tmp);
            int cur_rtt = tv2ms(&tv_tmp);
            // removed sem here: value not required
            //for(int i=0; i<info.channel_amount; i++) { // only chan 0 !
            if(cur_rtt > shm_conn_info->stats[info.process_num].rtt_phys_avg) {
                shm_conn_info->stats[info.process_num].rtt_phys_avg = cur_rtt;
                info.rtt = cur_rtt;
            }
            //}
            // TODO: in case of DDS initiate second ping immediately!!??
        }
        // <<< END calculate on-line RTT

        
        // DEAD DETECT and COPY HEAD from SHM >>>
        // max_chan=-1; // this is bad practice ;-)
        // removed sem here: value not required
        uint32_t chan_mask = shm_conn_info->channels_mask;
        // end sem
        
        sem_wait(&(shm_conn_info->stats_sem)); // critical_sem
        if(info.dropping) { // will ONLY drop if PESO in play. Never as of now...
            info.dropping = 0;
            shm_conn_info->drop_time = info.current_time;
            shm_conn_info->dropping = 1;
        }
        if(shm_conn_info->stats[info.process_num].packet_upload_cnt > 50) {
            timersub(&info.current_time, &shm_conn_info->stats[info.process_num].packet_upload_tv, &tv_tmp_tmp_tmp);
            int ms_passed = tv2ms(&tv_tmp_tmp_tmp);
            if(ms_passed > 5) {
                shm_conn_info->stats[info.process_num].packet_upload_spd = shm_conn_info->stats[info.process_num].packet_upload_cnt * 1000 / ms_passed;
                shm_conn_info->stats[info.process_num].packet_upload_cnt = 0;
                shm_conn_info->stats[info.process_num].packet_upload_tv = info.current_time;
                
                // int max_pups = 0;
                // int max_pups_chan = 0;
                // int min_rtt = INT32_MAX;
                // int min_rtt_chan = 0;
                // for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                //     if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                //         if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                //             min_rtt = shm_conn_info->stats[i].exact_rtt;
                //             min_rtt_chan = i;
                //         }
                //         if(max_pups < shm_conn_info->stats[info.process_num].packet_upload_spd) {
                //             max_pups = shm_conn_info->stats[info.process_num].packet_upload_spd;
                //             max_pups_chan = i;
                //         }
                //     }
                // }
                // if(shm_conn_info->stats[max_pups_chan].exact_rtt > min_rtt) {
                //     shm_conn_info->drtt = shm_conn_info->stats[max_pups_chan].exact_rtt - min_rtt;
                //     vlog(LOG_INFO, "WARNING Fastest chan Not Lowest RTT delta %d (FnLR) max_pups %d max_pups_chan %d rtt %d min_rtt %d min_rtt_chan %d", 
                //         shm_conn_info->drtt, max_pups, max_pups_chan, shm_conn_info->stats[max_pups_chan].exact_rtt, min_rtt, min_rtt_chan);
                //     if(shm_conn_info->drtt > shm_conn_info->forced_rtt) {
                //         //shm_conn_info->forced_rtt = shm_conn_info->drtt;
                //         //need_send_FCI = 1;
                //         //vlog(LOG_INFO, "WARNING FnLR disabled");
                //     }
                // }
            }
        }

        // AVERAGE (MEAN) SEND_Q_EFF calculation --->>>
        timersub(&info.current_time, &info.tv_sqe_mean_added, &tv_tmp_tmp_tmp);
        if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, SELECT_SLEEP_USEC }), >=)) {
            // FAST TIMER HERE: 20 ticks per second (50ms)
            
            
            // AG DECISION >>>
            ag_flag_local = ((    //(!info.head_channel) && (info.rsr <= info.send_q_limit_threshold)  
                (shm_conn_info->stats[info.process_num].ACK_speed < (shm_conn_info->stats[max_chan].ACK_speed / RATE_THRESHOLD_MULTIPLIER))
                               //|| (send_q_limit_cubic_apply <= info.send_q_limit_threshold) // disabled for #187
                               //|| (send_q_limit_cubic_apply < info.rsr) // better w/o this one?!? // may re-introduce due to PESO!
                               || shm_conn_info->slow_start
                               || ( channel_dead )
                               || (shm_conn_info->avg_len_out < AVG_LEN_IN_ACK_THRESH) // ACK/telemetry mode
                               || ( shm_conn_info->idle )
                               //|| ( info.head_change_safe && !check_rtt_latency_drop() ) // replace by MAWMAR
                               || ((agag < AGAG_AG_THRESH) && (!mawmar_allowed()))
                               || (( !shm_conn_info->dropping && !shm_conn_info->head_lossing ) && !is_happiness_reached())
                               //|| ( shm_conn_info->stats[info.process_num].l_pbl < (shm_conn_info->stats[max_chan].l_pbl / 7) ) // TODO: TCP model => remove
                               || ( plp_avg_pbl_unrecoverable(info.process_num) < PLP_UNRECOVERABLE_CUTOFF ) // TODO we assume that local unrecoverable PLP is on-par with tflush PBL
                               //|| ( !shm_conn_info->stats[info.process_num].brl_ag_enabled ) // TODO: for future TCP model
                               /*|| (shm_conn_info->stats[max_chan].sqe_mean < SEND_Q_AG_ALLOWED_THRESH)*/ // TODO: use mean_send_q
                               ) ? R_MODE : AG_MODE);
            // logging part
            if(info.head_channel && (shm_conn_info->avg_len_out >= AVG_LEN_IN_ACK_THRESH) && !shm_conn_info->idle && !shm_conn_info->slow_start) {// TODO HERE: add RTT/BW decision here
                ag_flag_local = AG_MODE;
            }
            if(ag_flag_local == AG_MODE) {
                shm_conn_info->ag_mask |= (1 << info.process_num); // set bin mask to 1
            } else {
                shm_conn_info->ag_mask &= ~(1 << info.process_num); // set bin mask to zero
            }
            if(ag_flag_local_prev != ag_flag_local) {
                need_send_FCI = 1; // TODO WARNING FCI may be LOST!! need transport
            }
            
            // now calculate AGAG
            uint32_t dirty_seq = 0;
            if(ag_flag_local == AG_MODE) {
                if(ag_flag_local_prev != ag_flag_local) {
                    if(agag < 10) { // start from zero
                        agon_time = info.current_time;
                        shm_conn_info->stats[info.process_num].agon_time = agon_time;
                    } else {
                        // recalculate
                        struct timeval agtime;
                        timersub(&info.current_time, &agon_time, &agtime);
                        ms2tv(&agtime, agag * 10);
                        timersub(&info.current_time, &agtime, &agon_time);
                        shm_conn_info->stats[info.process_num].agon_time = agon_time;
                    }
                    ag_flag_local_prev = ag_flag_local;
                }
                // first calculate agag
                timersub(&info.current_time, &agon_time, &tv_tmp);
                //agag = (tv2ms(&tv_tmp) - info.exact_rtt * 2)/ 10;
                agag = tv2ms(&tv_tmp) / 10;
                if(agag > 0) {
                    if(agag > AGAG_MAX) agag = AGAG_MAX; // 2555 milliseconds for full AG (~1% not AG)
                    for(int i=0; i<info.channel_amount; i++) {
                        dirty_seq += info.channel[i].local_seq_num;
                    }
                    if(agag < 127) {
                        ag_flag = ((dirty_seq % (128 - agag)) == 0) ? AG_MODE : R_MODE;
                    } else {
                        ag_flag = ((dirty_seq % (agag - 125)) == 0) ? R_MODE : AG_MODE;
                    }
                }
                // and finally re-set ag_flag_local since send packet part will use it to choose R/AG
            } else {
                if(ag_flag_local_prev == AG_MODE) {
                    vlog(LOG_INFO, "Dropping AG on Channel %s (head? %d) (idle? %d) (sqe %d) (rsr %d) (ACS %d) (PCS %d)", lfd_host->host, info.head_channel, shm_conn_info->idle, send_q_eff, info.rsr, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2);
                    vlog(LOG_INFO, "       (rsr=%d)<=(THR=%d) || (W=%d)<=(THR=%d) || DEAD=%d || !CLD=%d || dropping=%d", info.rsr ,info.send_q_limit_threshold, -1/*send_q_limit_cubic_apply*/ ,info.send_q_limit_threshold, channel_dead, ( !check_rtt_latency_drop() ), ( !shm_conn_info->dropping && !shm_conn_info->head_lossing ) );
                
                }
                
                if(ag_flag_local_prev != ag_flag_local) {
                    if(agag > 200) { // start from top
                        agon_time = info.current_time;
                        shm_conn_info->stats[info.process_num].agon_time = agon_time;
                    } else {
                        // recalculate
                        struct timeval agtime;
                        timersub(&info.current_time, &agon_time, &agtime);
                        ms2tv(&agtime, (255 - agag) * 30); 
                        timersub(&info.current_time, &agtime, &agon_time);
                        shm_conn_info->stats[info.process_num].agon_time = agon_time;
                    }
                    ag_flag_local_prev = ag_flag_local;
                }
                // first calculate agag
                timersub(&info.current_time, &agon_time, &tv_tmp);
                agag = 255 - tv2ms(&tv_tmp) / 30; // WARNING: overflow may happen here // 3x times slower for NVR to be able to collect CWND before loss
                // TODO: dup code - may be optimized!
                if(agag > 0) {
                    if(agag > AGAG_MAX) agag = AGAG_MAX; // 2555 milliseconds for full AG (~1% not AG)
                    for(int i=0; i<info.channel_amount; i++) {
                        dirty_seq += info.channel[i].local_seq_num;
                    }
                    if(agag < 127) {
                        ag_flag = ((dirty_seq % (128 - agag)) == 0) ? AG_MODE : R_MODE;
                    } else {
                        ag_flag = ((dirty_seq % (agag - 125)) == 0) ? R_MODE : AG_MODE;
                    }
                } else {
                    agag = 0;
                    ag_flag = R_MODE;
                }
            }
            if(shm_conn_info->stats[info.process_num].channel_dead) {
                agag = 0; // protect in case we suddenly died
            }
            // <<< END AG DECISION
                
            // now compute W
            
            timersub(&(info.current_time), &loss_time, &t_tv);
            int t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
            t = t / CUBIC_T_DIV;
            t = t > cubic_t_max ? cubic_t_max : t; // 400s limit
            set_W_unsync(t);
            t = get_t_loss(&info.u_loss_tv, info.cubic_t_max_u);
            shm_conn_info->stats[info.process_num].W_cubic_u = cubic_recalculate(t, info.W_u_max, info.Bu, info.Cu);
            
            // #define SELECT_SLEEP_USEC 50000 // crucial for mean sqe calculation during idle
            /* 
            if( (shm_conn_info->stats[info.process_num].sqe_mean > SEND_Q_EFF_WORK) 
                    || (shm_conn_info->stats[info.process_num].ACK_speed > ACS_NOT_IDLE) ) {
                shm_conn_info->idle = 0; 
            }
            */
            // calculate hsqs
            //info.head_send_q_shift = shm_conn_info->stats[max_chan].loss_send_q * 65 / 100 - shm_conn_info->stats[max_chan].sqe_mean / info.eff_len;
            timersub(&info.current_time, &shm_conn_info->head_detected_ts, &tv_tmp_tmp_tmp);
            int headswitch_start_ok = timercmp(&tv_tmp_tmp_tmp, &((struct timeval) HEAD_TRANSITION_DELAY), >=); // protect from immediate dolbejka TODO: need more precise timing
            if(shm_conn_info->stats[max_chan].loss_send_q != LOSS_SEND_Q_UNKNOWN) {
                int rsrp = 0, sum_aer; 
                int sqe = get_total_sqe_mean_pkt(&sum_aer, &rsrp, 0);
                int sqe_above = rsrp * 85 / 100; // above thresh -> push to MBSL
                int sqe_below = rsrp * 75 / 100; // below thresh -> push to net
                // int sqe_above = shm_conn_info->stats[max_chan].rsr * 60 / 100 / info.eff_len; // above thresh -> push to MBSL
                // int sqe_below = shm_conn_info->stats[max_chan].rsr * 40 / 100 / info.eff_len; // below thresh -> push to net
                // int sqe = shm_conn_info->stats[max_chan].sqe_mean / info.eff_len; // no sync, don't care about actual value +-?
                // int rsrp = shm_conn_info->stats[max_chan].rsr / info.eff_len;
                if(sqe > sqe_above && sqe_above != rsrp) {
                    //info.head_send_q_shift = - calculate_hsqs_percents(MAX_HSQS_EAT, (sqe - sqe_above) * 100 / (rsrp - sqe_above) ) * sqe / 100/ 100; // negative value
                    if(sqe > rsrp) {
                        if(info.head_send_q_shift > 0) {
                            info.head_send_q_shift = -10;
                        } else {
                            info.head_send_q_shift -= 5;
                        }
                    } else if(sqe < rsrp && percent_delta_equal(sqe, rsrp, 10)) {
                        if(info.head_send_q_shift > 0) {
                            info.head_send_q_shift = -5;
                        } else {
                            info.head_send_q_shift -= 1;
                        }
                    } else if(sqe < rsrp && percent_delta_equal(sqe, rsrp, 20)) {
                        info.head_send_q_shift = -2;
                    } else {
                        info.head_send_q_shift = -1;
                    }
                    //need_send_FCI = 1;
                } else if(sqe < sqe_below && sqe_below > 0) {
                    //info.head_send_q_shift = calculate_hsqs_percents(MAX_HSQS_PUSH, (sqe_below - sqe) * 100 / sqe_below ) * sqe / 100/100; // positive value
                    if(percent_delta_equal(sqe, sqe_below, 10)) {
                        info.head_send_q_shift = 1;
                    } else if(percent_delta_equal(sqe, sqe_below, 20)) {
                        info.head_send_q_shift = 3;
                    } else if(percent_delta_equal(sqe, sqe_below, 40)) {
                        info.head_send_q_shift = 5;
                    } else {
                        info.head_send_q_shift += 3;
                    }
                    //need_send_FCI = 1;
                } else {
                    info.head_send_q_shift = 0; // this one is actually not required
                }
            } else {
                info.head_send_q_shift = MIN_SEND_Q_BESTGUESS_3G_PKT - shm_conn_info->stats[max_chan].sqe_mean / info.eff_len / MSBL_PUSHUP_K;
            }
            if(info.head_send_q_shift != info.head_send_q_shift_old && !shm_conn_info->idle) {
                info.head_send_q_shift_old = info.head_send_q_shift;
                info.FCI_send_counter = 0;
            }
            if(info.FCI_send_counter < 100) { // send as many times as possible?
                need_send_FCI = 1;
                info.FCI_send_counter++;
            }
            
            timersub(&info.current_time, &shm_conn_info->msbl_tick, &tv_tmp_tmp_tmp);
            if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, SELECT_SLEEP_USEC }), >=)) {
                int iK;
                if(shm_conn_info->head_send_q_shift_recv > 0) {
                        iK = 1; // push down
                } else {
                    // only this seems to work now
                    if(shm_conn_info->head_send_q_shift_recv < -10000) {
                        iK = 5; // push up FAST
                        shm_conn_info->head_send_q_shift_recv += 10000; // fix it back
                    } else {
                        iK = 1; // push up
                    }
                }
                int msbl_K;
                if(timercmp(&info.recv_loss_immune, &info.current_time, <=)) {
                    msbl_K = shm_conn_info->head_send_q_shift_recv * iK; 
                } else {
                    msbl_K = 0; // disable any event processing immediately after detected loss since we now have outdated info
                }
                    
                if(!((shm_conn_info->head_send_q_shift_recv == 10000) && (shm_conn_info->slow_start_recv))) {
                    shm_conn_info->max_stuck_buf_len -= msbl_K;
                }
                if(shm_conn_info->max_stuck_buf_len < 0 || shm_conn_info->is_single_channel) { 
                    shm_conn_info->max_stuck_buf_len = 0;
                }
                if(shm_conn_info->max_stuck_buf_len > MSBL_LIMIT) {
                    shm_conn_info->max_stuck_buf_len = MSBL_LIMIT;
                }
                // now fix msbl to 0 as an implementation of #77 workaround
                // warning! this is a temporary workaround and should be removed
                // int max_rtt = 0;
                // for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                //     if ((shm_conn_info->channels_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { 
                //         if(max_rtt < shm_conn_info->stats[i].exact_rtt) {
                //             max_rtt = shm_conn_info->stats[i].exact_rtt;
                //         }
                //     }
                // }
                // if(max_rtt && ((max_rtt * shm_conn_info->APCS)/1000 < 80)) {
                //     // if(shm_conn_info->max_stuck_buf_len > 10) shm_conn_info->max_stuck_buf_len -= 10;
                //     // else
                //     shm_conn_info->max_stuck_buf_len = 0;
                //     if(max_rtt < 50) 
                //         statb.web_surf_optimization |= 4;
                //     else
                //         statb.web_surf_optimization |= 2;
                // }
                // <-- end workaround
                shm_conn_info->msbl_tick = info.current_time;
            }
            
            timersub(&info.current_time, &shm_conn_info->msrt_tick, &tv_tmp_tmp_tmp);
            if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, SELECT_SLEEP_USEC }), >=)) {
                if(shm_conn_info->idle) {
                    if(shm_conn_info->max_stuck_rtt > 0) { 
                        shm_conn_info->max_stuck_rtt -= 1; // drop 1 ms at a time
                    }
                } else {
                    //int max_total_rtt = (shm_conn_info->total_max_rtt+shm_conn_info->total_max_rtt_var) - (shm_conn_info->total_min_rtt - shm_conn_info->total_min_rtt_var); 
                    int rhd = shm_conn_info->remote_head_pnum;
                    int max_total_rtt = shm_conn_info->stats[rhd].exact_rtt * RTT_THRESHOLD_MULTIPLIER;
                    if(shm_conn_info->max_stuck_rtt < max_total_rtt && shm_conn_info->tokens_in_out > 0) {
                        shm_conn_info->max_stuck_rtt += 1;
                    }
                }
                    
                shm_conn_info->msrt_tick = info.current_time;
            }
            
            timersub(&info.current_time, &shm_conn_info->frtt_smooth_tick, &tv_tmp_tmp_tmp);
            if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, SELECT_SLEEP_USEC }), >=)) {
                shm_conn_info->frtt_local_applied = 34 * shm_conn_info->frtt_local_applied / 35 + shm_conn_info->max_rtt_lag / 35;
                int full_rtt = ((shm_conn_info->forced_rtt_recv > shm_conn_info->frtt_local_applied) ? shm_conn_info->forced_rtt_recv : shm_conn_info->frtt_local_applied);
                info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC + full_rtt * 1000;
                shm_conn_info->frtt_smooth_tick = info.current_time;
            }
            
            CHKCPU(8);
            // FAST speed counter
            timersub(&info.current_time, &info.fast_pcs_ts, &tv_tmp_tmp_tmp);
            int time_passed = tv2ms(&tv_tmp_tmp_tmp);
            if(        ( (PCS-info.fast_pcs_old) > FAST_PCS_PACKETS_CAN_CALC_SPEED) 
                    && (time_passed > FAST_PCS_MINIMAL_INTERVAL)
                    && (info.fast_pcs_old < PCS) 
              ) {
                info.channel[1].packet_download = (PCS - info.fast_pcs_old) * 100 / time_passed * 10; // packets/second
                need_send_FCI = 1;
                info.fast_pcs_ts = info.current_time;
                info.fast_pcs_old = PCS;
            }
            
            // FAST-redetect head experiment
            redetect_head_unsynced(chan_mask, -1);
            
            //send_q_eff_mean += (send_q_eff - send_q_eff_mean) / 30; // TODO: choose aggressiveness for smoothed-sqe (50?) // TODO: use correct smoothing algorithm!
            send_q_eff_mean = 6 * send_q_eff_mean / 7 + send_q_eff / 7;
            if(send_q_eff < info.max_send_q) {
                info.max_send_q = 25 * info.max_send_q / 26 + send_q_eff / 26;
            } else {
                info.max_send_q = send_q_eff;
            }
            int sqe_delta = send_q_eff - send_q_eff_mean;
            if(sqe_delta > 0) {
                send_q_eff_var = (6 * send_q_eff_var  +  sqe_delta)/7;
            } else {
                send_q_eff_var = (6 * send_q_eff_var  -  sqe_delta)/7;
            }
            
            if(shm_conn_info->stats[info.process_num].sqe_mean_lossq < send_q_eff) {
                shm_conn_info->stats[info.process_num].sqe_mean_lossq = send_q_eff;
            } else {
                //send_q_eff_mean += (send_q_eff - send_q_eff_mean) / 30; // TODO: choose aggressiveness for smoothed-sqe (50?)
                //shm_conn_info->stats[info.process_num].sqe_mean_lossq = (send_q_eff - shm_conn_info->stats[info.process_num].sqe_mean_lossq) / 30;
                shm_conn_info->stats[info.process_num].sqe_mean_lossq = 6 * shm_conn_info->stats[info.process_num].sqe_mean_lossq / 7 + send_q_eff / 7;
            }
            if (info.max_send_q_u < send_q_eff_mean) {
                info.max_send_q_u = send_q_eff_mean;
            }
            info.tv_sqe_mean_added = info.current_time;
            
            timersub(&info.current_time, &info.head_change_tv, &tv_tmp_tmp_tmp);
            info.head_change_safe = (tv2ms(&tv_tmp_tmp_tmp) > (info.exact_rtt * 2) ? 1 : 0);
                    
        }
        // << END AVERAGE (MEAN) SEND_Q_EFF calculation



            CHKCPU(81);
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
            if((shm_conn_info->last_net_read_ds - last_net_read_ds) > (MAX_NETWORK_STALL_MS / 10 + info.rtt2 + info.srtt2var)) {
                // vlog(LOG_ERR, "WARNING! detecting dead channel by last_net_read_ds: %d, %d", shm_conn_info->last_net_read_ds, last_net_read_ds);
                channel_dead = 1;
            }
        }

        if(channel_dead == 1 && channel_dead != shm_conn_info->stats[info.process_num].channel_dead) {
            vlog(LOG_INFO, "Warning! Channel %s suddenly died! (head? %d) (idle? %d) (sqe %d) (rsr %d) (ACS %d) (PCS %d) (exact_rtt %d)", lfd_host->host, info.head_channel, shm_conn_info->idle, send_q_eff, info.rsr, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2, shm_conn_info->stats[info.process_num].exact_rtt);
            shm_conn_info->last_switch_time.tv_sec = 0;
            if(info.head_channel) {
                vlog(LOG_INFO, "Warning! %s is head! Re-detecting new HEAD!", lfd_host->host);
                redetect_head_unsynced(chan_mask, info.process_num);
            }
        }
        if (channel_dead == 0 && channel_dead != shm_conn_info->stats[info.process_num].channel_dead){
            vlog(LOG_INFO, "Channel %s went alive! (head? %d) (idle? %d) (sqe %d) (rsr %d) (ACS %d) (PCS %d) (exact_rtt %d)", lfd_host->host, info.head_channel, shm_conn_info->idle, send_q_eff, info.rsr, shm_conn_info->stats[info.process_num].max_ACS2, shm_conn_info->stats[info.process_num].max_PCS2, shm_conn_info->stats[info.process_num].exact_rtt);
        }
        shm_conn_info->stats[info.process_num].channel_dead = channel_dead;
        shm_conn_info->stats[info.process_num].sqe_mean = send_q_eff_mean;
        shm_conn_info->stats[info.process_num].sqe_var = send_q_eff_mean;
        shm_conn_info->stats[info.process_num].max_send_q = send_q_eff;
        shm_conn_info->stats[info.process_num].exact_rtt = exact_rtt;
        shm_conn_info->stats[info.process_num].rttvar = rttvar;
        max_chan = shm_conn_info->max_chan;
#ifdef FIX_HEAD_CHAN
        if(info.process_num == FIX_HEAD_CHAN)  info.head_channel = 1;
        else info.head_channel = 0;
#else
        // head switch block
            CHKCPU(82);
        if(max_chan == info.process_num) {
            if(info.head_channel != 1) {
                skip++;
                // info.W_cubic_copy = info.send_q_limit_cubic;
                // info.Wu_cubic_copy = shm_conn_info->stats[info.process_num].W_cubic_u;
                vlog(LOG_INFO, "Switching head to 1 (ON) saving W %d", info.send_q_limit_cubic);
                if(shm_conn_info->head_lossing && !shm_conn_info->idle) {
                    shm_conn_info->stats[info.process_num].real_loss_time = info.current_time; // just to continue AG due to dropping_lossing
                }
            }
            info.head_channel = 1;
        } else {
            if(info.head_channel != 0) {
                skip++;
                vlog(LOG_INFO, "Switching head to 0 (OFF) restoring W %d if > than current W %d", info.W_cubic_copy, info.send_q_limit_cubic);
                if(info.send_q_limit_cubic < info.W_cubic_copy) {
                    // here #876
                    // set_W_to(info.W_cubic_copy, 1, &loss_time);
                    // set_Wu_to(info.Wu_cubic_copy);
                }
                info.head_change_tv = info.current_time;
                info.head_change_safe = 0;
            }
            info.head_channel = 0;
        }
#endif
        // <<< DEAD DETECT and COPY HEAD from SHM
        
    
            CHKCPU(83);

        // RSR section here >>>
        int rtt_shift;
        int rsr_top;
        if (info.head_channel) {
            //info.rsr = RSR_TOP;
            info.rsr = info.send_q_limit_cubic;
            if(shm_conn_info->is_single_channel) {
                info.send_q_limit_cubic = lfd_host->MAX_WINDOW;
            }
            max_send_q_available = info.rsr;
            shm_conn_info->stats[info.process_num].max_send_q_available = info.rsr;
            
            temp_sql_copy = info.send_q_limit; 
            temp_acs_copy = shm_conn_info->stats[info.process_num].ACK_speed ; 
        } else {
            rsr_top = shm_conn_info->stats[max_chan].rsr;
            
            // copy all vars used to their 'double' reprs
            double d_ACS_h = shm_conn_info->stats[        max_chan].ACK_speed; // bytes/s
            double d_ACS = shm_conn_info->stats[info.process_num].ACK_speed; // bytes/s
            double d_rsr_top = shm_conn_info->stats[max_chan].rsr; // bytes
            double d_rtt_h = shm_conn_info->stats[max_chan].exact_rtt; // ms
            d_rtt_h = d_rtt_h / 1000.0; // ms->s
            double d_rtt_h_var = shm_conn_info->stats[max_chan].rttvar;// ms
            d_rtt_h_var /= 1000.0; // ms->s
            double d_rtt = shm_conn_info->stats[info.process_num].exact_rtt;// ms
            d_rtt = d_rtt / 1000.0; // ms->s
            double d_rtt_var = shm_conn_info->stats[info.process_num].rttvar;// ms
            d_rtt_var /= 1000.0; // ms->s
            double d_frtt = shm_conn_info->forced_rtt;// ms
            d_frtt /= 1000.0; // ms->s
            double d_rsr = info.rsr; // bytes
            
            if(d_ACS_h < 1) {
                d_ACS_h = 1; // zero-protect
            }
            double d_sql = d_rsr_top * ( d_ACS / d_ACS_h );
            info.send_q_limit = (int) d_sql; // TODO IS IT NEEDED REMOVE
            
            temp_sql_copy = info.send_q_limit; 
            temp_acs_copy = shm_conn_info->stats[info.process_num].ACK_speed ; 
            
            // TODO: rtt_shift and pump_adj are essentially the same - we should join them one day...
            //double d_rtt_diff = (d_rtt_h - d_rtt_h_var) - (d_rtt + d_rtt_var);
            double d_rtt_diff = d_rtt_h - d_rtt;
            
            //double d_mld_ms = MAX_LATENCY_DROP_USEC / 1000;
            double d_msbl_overdrive = 50; // packets?
            /*d_mld_ms /= 1000000.0; 
            if(shm_conn_info->max_allowed_rtt < d_mld_ms) {
                d_mld_ms = shm_conn_info->max_allowed_rtt;
            }
            d_mld_ms /= 1000.0; // to seconds
            */
            //d_mld_ms += d_frtt; // ?
            //double d_pump_adj = d_ACS * ( d_mld_ms + d_rtt_diff );
            //double d_pump_adj = d_ACS * ( d_mld_ms - d_rtt );
            //if(d_pump_adj < 0) d_pump_adj = 0;
            
            //double d_rtt_shift = ((d_rtt + d_rtt_var) - d_rtt_h) * d_ACS_h;
            double d_rtt_shift = (d_rtt - d_rtt_h) * d_ACS_h; // rttvar seems to be causing high RSR jitter
            if(d_rtt_shift < d_sql) {
                d_sql -= d_rtt_shift;
            } else {
                d_sql = SEND_Q_LIMIT_MINIMAL;
            }
            
            //d_sql += d_pump_adj;
            d_sql += ((double)(shm_conn_info->buf_len_recv / 3) + d_msbl_overdrive) * (double)info.eff_len;
            temp_sql_copy2 = (int) d_sql; 
            if(d_sql > RSR_TOP) {
                d_sql = RSR_TOP;
            }
            
            // now calculate max RSR limit in case of CWND deficiency
            int sum_aer, lim;
            int total_sq_pkt = get_total_sqe_mean_pkt(&sum_aer, &lim, 1) + shm_conn_info->msbl_recv - MSBL_RESERV;
            int total_sq_avail = rsr_top > (MIN_SEND_Q_BESTGUESS_3G_PKT * info.eff_len) ? (total_sq_pkt - MIN_SEND_Q_BESTGUESS_3G_PKT) : (total_sq_pkt - rsr_top / info.eff_len);
            int sqe_pkt = shm_conn_info->stats[info.process_num].sqe_mean / info.eff_len;
            if(sqe_pkt > 0) {
                int aer = shm_conn_info->stats[info.process_num].ACK_speed_avg / sqe_pkt;
                if(aer > 0 && sum_aer > 0) {
                    max_send_q_available = (total_sq_avail * aer) / sum_aer * info.eff_len;
                } else {
                    max_send_q_available = SEND_Q_AG_ALLOWED_THRESH; // what to do if our ACS == 0? we're R_MODE probably..
                }
            } else {
                max_send_q_available = MIN_SEND_Q_BESTGUESS_3G_PKT * info.eff_len; // in case we have zero sqe we just dont care
            }
            shm_conn_info->stats[info.process_num].max_send_q_available = max_send_q_available;
            
            timersub(&(info.current_time), &info.cycle_last, &t_tv);
            int32_t ms_passed = tv2ms(&t_tv);
            if(ms_passed > RSR_SMOOTH_GRAN) { // 10 ms intvl, 500ms full
                d_rsr = 17.0/18.0 * d_rsr + 1.0/18.0 * d_sql;
                info.cycle_last = info.current_time;
            }
            
           
           /*
            double d_sqlm = d_rtt * (SPEED_MINIMAL - d_ACS);
            if(d_sqlm > SEND_Q_LIMIT_MINMAX) {
                d_sqlm = SEND_Q_LIMIT_MINMAX;
            }
            */
            
            double d_sqlm = 0; // TODO: pump_adj should deal with this problem!
            if(d_sqlm > SEND_Q_LIMIT_MINIMAL) {
                if(d_rsr < d_sqlm) {
                    d_rsr = d_sqlm;
                }
            } else {
                if(d_rsr < SEND_Q_LIMIT_MINIMAL) {
                    d_rsr = SEND_Q_LIMIT_MINIMAL;
                    //vlog(LOG_INFO, "WARNING! d_rsr < SQL_MIMIMAL: %f; setting to MIN", d_rsr);
                }
            }
                
            info.rsr = d_rsr;
            
            
            
            //pump_adj = (int) d_pump_adj;
            rtt_shift = (int) d_rtt_shift;
        }
        shm_conn_info->stats[info.process_num].rsr = info.rsr;
        
        
        
        CHKCPU(84);
        //int send_q_limit_cubic_apply = (info.send_q_limit_cubic > shm_conn_info->stats[info.process_num].W_cubic_u ? info.send_q_limit_cubic : shm_conn_info->stats[info.process_num].W_cubic_u);
        int send_q_limit_cubic_apply = info.send_q_limit_cubic;
        if (send_q_limit_cubic_apply < SEND_Q_LIMIT_MINIMAL) {
            send_q_limit_cubic_apply = SEND_Q_LIMIT_MINIMAL-1;
        }

        // <<< END RSR section here




            CHKCPU(85);
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
        
        // if(0 && ag_flag_local == AG_MODE) {
        //     // check our protup against all other chans
        //     for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        //         if ((chan_mask & (1 << i)) 
        //             && (!shm_conn_info->stats[i].channel_dead)
        //             && ((shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[i].exact_rtt)*1000 > ((int)info.max_latency_drop.tv_usec)) 
        //             && ((shm_conn_info->stats[i].ag_flag_local) || (check_delivery_time_path_unsynced(i, 2)))) { // warning! CLD may
        //             info.frtt_remote_predicted = get_rttlag(shm_conn_info->ag_mask);
        //             if( ((shm_conn_info->stats[info.process_num].exact_rtt - shm_conn_info->stats[i].exact_rtt)*1000 > ((int)info.max_latency_drop.tv_usec) + info.frtt_remote_predicted * 1000) ) {
        //                 if(info.head_channel) {
        //                     vlog(LOG_ERR, "WARNING: PROTUP condition detected on our channel: ertt %d - ertt %d > %u and is head frtt_rem %d rtt2-1 %d rtt2-2 %d", shm_conn_info->stats[info.process_num].exact_rtt, shm_conn_info->stats[i].exact_rtt, ((int)info.max_latency_drop.tv_usec), info.frtt_remote_predicted, shm_conn_info->stats[info.process_num].rtt2, shm_conn_info->stats[i].rtt2);
        //                     redetect_head_unsynced(chan_mask, info.process_num);
        //                     // TODO: immediate action required!
        //                 } else {
        //                     vlog(LOG_ERR, "WARNING: PROTUP condition detected on our channel: %d - %d > %u frtt_rem %d", shm_conn_info->stats[info.process_num].rtt2, shm_conn_info->stats[i].rtt2, ((int)info.max_latency_drop.tv_usec), info.frtt_remote_predicted);

        //                 }
        //             }
        //         }
        //     }
        // }
        
        
            CHKCPU(86);


        CHKCPU(80);

        // HOLD/DROP setup >>>
        int hold_mode_previous = hold_mode;
        //if(ag_flag_local == AG_MODE) {
        if(agag > AGAG_AG_THRESH) {
            if(info.head_channel) {
                hold_mode = 0; // no hold whatsoever;
                // here we decide on whether to hold or not to hold
                drop_packet_flag = 0;
                //if (send_q_eff > info.rsr) {
                if (send_q_eff > send_q_limit_cubic_apply) {
                        // #876
                        //if(is_a_hold() && (shm_conn_info->msbl_recv > (MSBL_LIMIT - MSBL_RESERV))) drop_packet_flag = 1;
                        //else {
                            hold_mode = 1;
                        //}
                }
                // warning the whole block is not sync
                if(((shm_conn_info->ag_mask & (~(1 << info.process_num))) & (shm_conn_info->channels_mask)) !=  // hope that ag_mask is consistent with chan_mask
                        ( (~shm_conn_info->hold_mask) & (~(1 << info.process_num)) & (shm_conn_info->channels_mask) & (shm_conn_info->ag_mask))){ 
                    // exclude current head from comparison (it may not be consistent about flags with mode/hold)
                    // hold_mask is negative: 1 means send allowed
                    ///hold_mode = 1; // do not allow to send if the channels are in AG and not in HOLD
                    ///drop_packet_flag = 0;
                    // TODO HERE: may have problems in case of 
                    // 1. incorrect detection of chan RSR/W
                    // 2. channel for some reason can not reach hold (any reasons?)
                    // 3. possible problems with HEAD detect in case there will be no packets available to send for HEAD to support top speed
                    // may be implement a 'soft' hold for head (push other chans to top (APTT) - not by going 100% committed to hold if not pushed
                    shm_conn_info->hold_mask = shm_conn_info->channels_mask;
                }
            } else {
                drop_packet_flag = 0;
                if ( (send_q_eff > info.rsr) || (send_q_eff > send_q_limit_cubic_apply) || (send_q_eff > max_send_q_available)) {
                    //vlog(LOG_INFO, "hold_mode!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d", send_q_eff, rsr, send_q_limit_cubic_apply);
                    hold_mode = 1;
                } else {
                    hold_mode = 0;
                }
            }
        } else { // R_MODE.. no intermediate modes.. yet ;-)
            hold_mode = 0;
            drop_packet_flag = 0;
            if(info.head_channel) {
                //if(send_q_eff > info.rsr) { // no cubic control on max speed chan!
                if(shm_conn_info->is_single_channel) {
                    if (send_q_eff > send_q_limit_cubic_apply) {
                        hold_mode = 1;
                    }
                } else {
                    if (send_q_eff > send_q_limit_cubic_apply/2) {
                            // #876
                        //vlog(LOG_INFO, "R_MODE DROP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                            //drop_packet_flag = 1; // no drop in retransmit? TODO HERE
                            set_W_to(send_q_eff*2, 1, &loss_time);
                            set_Wu_to(send_q_eff*2);
                    } else {
                        //vlog(LOG_INFO, "R_MODE NOOP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    }
                }
            } else {
                if((send_q_eff > send_q_limit_cubic_apply) || (send_q_eff > info.rsr)) {
                    //vlog(LOG_INFO, "R_MODE DROP!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    hold_mode = 1;
                } else {
                    //vlog(LOG_INFO, "R_MODE NOOP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                }
            }
        }

        if(hold_mode) {
            shm_conn_info->hold_mask &= ~(1 << info.process_num); // set bin mask to zero (send not allowed)
        } else {
            //shm_conn_info->hold_mask |= (1 << info.process_num); // set bin mask to 1 (free send allowed)
        }
        // << END HOLD/DROP setup
        if(hold_mode) {
            info.hold_time = info.current_time;
        }
        // #ifdef CLIENTONLY
        // if(!sq_control) {
        //     hold_mode = 0;
        //     if(! (dirty_seq_num % 30) ) {
        //         info.max_latency_drop.tv_usec = 1000;
        //         shm_conn_info->frtt_local_applied = 1;
        //         shm_conn_info->rttvar_worst = 1;
        //         drop_packet_flag = 1;
        //     } else {
        //         info.max_latency_drop.tv_usec = 50000;
        //     }
        // }
        // #endif
        
        
        // // fast convergence to underlying encap flow >>> 
        // if(info.head_channel && (drop_packet_flag || hold_mode) && !shm_conn_info->head_lossing ) { 
        //     // if we are head and not lossing -> converge instead of dropping
        //     drop_packet_flag = 0;
        //     hold_mode = 0;
        //     set_W_to(send_q_eff + 2000, 1, &loss_time);
        //     set_Wu_to(send_q_eff + 2000);
        // }

        // // Push down envelope
        // if(info.head_channel && (send_q_eff < (int32_t)info.send_q_limit_cubic)) {
        //     //set_W_to(send_q_eff, 30, &loss_time);
        //     // here #876
        //     // converge only if no losses were detected
        //     if( !shm_conn_info->dropping && !shm_conn_info->head_lossing ) {
        //         set_W_to(send_q_eff, 1, &loss_time); // 1 means immediately!
        //         set_Wu_to(send_q_eff);
        //     }
        // }
        // // <<< END fast convergence to underlying encap flow
        

#ifdef NOCONTROL
        hold_mode = 0;
        drop_packet_flag = 0;
#endif
        
        shm_conn_info->stats[info.process_num].hold = hold_mode;
        sem_post(&(shm_conn_info->stats_sem)); // critical_sem
        // if(!info.head_channel) {
        //     if(hold_mode_previous == 0 && hold_mode == 1) {
        //         sig_send1(); // notify head (all) about our new condition
        //     }
        // }
        // if(info.head_channel) {
        //     if(hold_mode_previous == 1 && hold_mode == 0) {
        //         vlog(LOG_INFO, "HEAD unhold.");
        //     }
        // }
        //vlog(LOG_INFO, "debug0: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
        if(hold_mode == 1) {
            was_hold_mode = 1; // for JSON ONLY!
            info.whm_send_q = send_q_eff;
            info.whm_cubic = send_q_limit_cubic_apply;
            info.whm_rsr = info.rsr;
        }
        
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
                        //vlog(LOG_INFO, "chan %d down packet speed %"PRIu32" packets %"PRIu32" time %"PRIu32" timer %"PRIu32"", i, info.channel[i].packet_download, info.channel[i].down_packets, tv, packet_speed_timer_time.tv_usec/1000);
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
        
       
        timersub(&info.current_time, &json_timer, &tv_tmp_tmp_tmp);
        if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, 500000}), >=)) {
            int json_ms = tv2ms(&tv_tmp_tmp_tmp);
            set_rttlag();
            set_rttlag_total();
            if(shm_conn_info->max_rtt_lag > shm_conn_info->frtt_local_applied) {
                //shm_conn_info->frtt_local_applied = shm_conn_info->max_rtt_lag;
                shm_conn_info->frtt_local_applied = (5 * shm_conn_info->frtt_local_applied + shm_conn_info->max_rtt_lag) / 6;
                int full_rtt = ((shm_conn_info->forced_rtt_recv > shm_conn_info->frtt_local_applied) ? shm_conn_info->forced_rtt_recv : shm_conn_info->frtt_local_applied);
                info.max_latency_drop.tv_usec = MAX_LATENCY_DROP_USEC + full_rtt * 1000;
            }
            
            struct timeval min_tv, max_pkt_lag, max_lag = {5, 100000}, since_write_tv;
            get_wb_oldest_ts_unsync(&min_tv);
            timersub(&info.current_time, &min_tv, &max_pkt_lag);
            if(timercmp(&max_pkt_lag, &max_lag, >)) {
                timersub(&info.current_time, &shm_conn_info->write_buf[1].last_write_time, &since_write_tv);
                vlog(LOG_ERR, "ERROR! Max buffer packet lag exceeded: %ld.%06ld s, wlag %ld.%06ld s, buf_len=%d, APCS=%d tks=%d maxstall %ld.%06ld s MLD %d ms. Adding tokens", max_pkt_lag, since_write_tv, shm_conn_info->write_buf[1].frames.length, shm_conn_info->APCS, shm_conn_info->tokens, shm_conn_info->max_network_stall, get_rto_usec()/1000);
                //shm_conn_info->tokenbuf+=50;
                if(shm_conn_info->tokens == 0) {
                    shm_conn_info->tokens += 10;
                }
            }
            
            //if( info.head_channel && (max_speed != shm_conn_info->stats[info.process_num].ACK_speed) ) {
            //    vlog(LOG_ERR, "WARNING head chan detect may be wrong: max ACS != head ACS");            
            //}

            if(shm_conn_info->idle) {
                shm_conn_info->stats[info.process_num].l_pbl_tmp = INT32_MAX;
                set_W_to(RSR_TOP / 2, 1, &loss_time); // protect from overflow??
                set_Wu_to(RSR_TOP/2);
                shm_conn_info->stats[info.process_num].loss_send_q = LOSS_SEND_Q_UNKNOWN;
                //info.W_cubic_copy = info.send_q_limit_cubic;
            }
            
            // expensive thing: recalculate minimal rtt channel
            int min_rtt = INT32_MAX;
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                    if(min_rtt > shm_conn_info->stats[i].exact_rtt) {
                        min_rtt = shm_conn_info->stats[i].exact_rtt;
                        info.min_rtt_chan = i;
                    }
                }
            }
            
            /*
            if(shm_conn_info->drtt < shm_conn_info->forced_rtt) { // WTF??
                shm_conn_info->forced_rtt = shm_conn_info->drtt;
            }
            */
            
            // compute perceived loss probability
            if(info.p_lost > 0 && info.r_lost > 0) {
                info.i_plp += (((info.channel[1].local_seq_num - info.last_loss_lsn) / info.p_lost) - info.i_plp) / 2;
                info.last_loss_lsn = info.channel[1].local_seq_num; // WRN channel broken here
                info.p_lost = 0;
                
                info.i_rplp += (((info.channel[1].local_seq_num_recv - info.last_rlost_lsn) / info.r_lost) - info.i_rplp) / 2;
                info.last_rlost_lsn = info.channel[1].local_seq_num_recv;
                info.r_lost = 0;
            }
            
            int cur_plp = plp_avg_pbl(info.process_num);
            int cur_plp_unrec = plp_avg_pbl_unrecoverable(info.process_num);
            
            sem_wait(&(shm_conn_info->stats_sem));
            
            shm_conn_info->rttvar_worst = 0;
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) && (shm_conn_info->ag_mask_recv & (1 << i))) { // hope this works..
                    if(shm_conn_info->rttvar_worst < shm_conn_info->stats[i].rttvar) {
                        shm_conn_info->rttvar_worst = shm_conn_info->stats[i].rttvar;
                    }
                }
            }

            int new_mar = compute_max_allowed_rtt();
            if(new_mar > shm_conn_info->max_allowed_rtt) {
                shm_conn_info->max_allowed_rtt = 8 * shm_conn_info->max_allowed_rtt / 9 + new_mar / 9;
            } else {
                shm_conn_info->max_allowed_rtt = 5 * shm_conn_info->max_allowed_rtt / 6 + new_mar / 6;
            }
            
            timersub(&info.current_time, &shm_conn_info->APCS_tick_tv, &tv_tmp);
            if(timercmp(&tv_tmp, &((struct timeval) {1, 350000}), >=) || (shm_conn_info->APCS_cnt > 500)) {
                int new_APCS = shm_conn_info->APCS_cnt * 1000 / tv2ms(&tv_tmp);
                shm_conn_info->APCS = 6 * shm_conn_info->APCS / 7 + new_APCS / 7;
                shm_conn_info->APCS_cnt = 0;
                shm_conn_info->APCS_tick_tv = info.current_time;
            }
            if(shm_conn_info->APCS < MIN_PPS) {
                shm_conn_info->APCS = MIN_PPS;
            }
           
            shm_conn_info->stats[info.process_num].l_pbl = cur_plp; // absolutely unnessessary (done at loop )
            //set_xhi_brl_flags_unsync(); // compute xhi from l_pbl
            shm_conn_info->stats[info.process_num].packet_speed_ag = statb.packet_sent_ag / json_ms;
            shm_conn_info->stats[info.process_num].packet_speed_rmit = statb.packet_sent_rmit / json_ms;

            timersub(&info.current_time, &shm_conn_info->drop_time, &tv_tmp_tmp_tmp);
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {DROPPING_LOSSING_DETECT_SECONDS, 0}), >=)) {
                if(DL_flag_drop_allowed_unsync_stats(chan_mask)) shm_conn_info->dropping = 0;
            } else {
                shm_conn_info->dropping = 1;
            }
            
            if(info.head_channel) {
                timersub(&(info.current_time), &(shm_conn_info->stats[info.process_num].real_loss_time), &tv_tmp_tmp_tmp);
                if(timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {DROPPING_LOSSING_DETECT_SECONDS, 0}), >=)) {
                    if(DL_flag_drop_allowed_unsync_stats(chan_mask)) shm_conn_info->head_lossing = 0;
                } else {
                    shm_conn_info->head_lossing = 1;
                    shm_conn_info->idle = 0;
                }
            }

            // calc ACS2 and DDS detect
            int max_ACS2=0;
            int Hchan=-1;
            for(int i=0; i<info.channel_amount; i++) {
                info.channel[i].ACS2 = (info.channel[i].packet_seq_num_acked - info.channel[i].old_packet_seq_num_acked) * 2 * info.eff_len;
                info.channel[i].old_packet_seq_num_acked = info.channel[i].packet_seq_num_acked;
                if(max_ACS2 < info.channel[i].ACS2) { 
                    max_ACS2 = info.channel[i].ACS2;
                    Hchan = i;
                }
            }
            
            if(max_ACS2 != info.channel[1].ACS2) {
                vlog(LOG_ERR,"ERROR: ACS2 on chan 1 not highest!: %d, ch: %d", max_ACS2, Hchan);
                max_ACS2 = info.channel[1].ACS2;
            }
            
            // now put max_ACS2 and PCS2 to SHM:
            shm_conn_info->stats[info.process_num].max_PCS2 = (PCS + PCS_aux) * 2 * info.eff_len;
            if(info.pcs_sent_old == info.channel[1].packet_download)  {
                info.channel[1].packet_download = PCS * 2;
                info.pcs_sent_old = info.channel[1].packet_download;
            }
            timersub(&info.current_time, &info.idle_enter, &tv_tmp);
            if(timercmp(&tv_tmp, &((struct timeval) {2, 0}), <=)) {
                need_send_FCI = 1;
            }
            //max_ACS2 = (max_ACS2 < (info.PCS2_recv * info.eff_len) ? max_ACS2 : (info.PCS2_recv * info.eff_len)); // disabled for future fix
            shm_conn_info->stats[info.process_num].max_ACS2 = max_ACS2;
            shm_conn_info->stats[info.process_num].ACK_speed= max_ACS2; // !
            shm_conn_info->stats[info.process_num].ACK_speed_avg = 6 * shm_conn_info->stats[info.process_num].ACK_speed_avg / 7 + max_ACS2 / 7;
            miss_packets_max = shm_conn_info->miss_packets_max;
             
            timersub(&info.current_time, &shm_conn_info->tpps_tick_tv, &tv_tmp);
            if ((timercmp(&tv_tmp, &((struct timeval) {0, 400000}), >=) && ((shm_conn_info->seq_counter[1] - shm_conn_info->tpps_old) > 150))
                    || (timercmp(&tv_tmp, &((struct timeval) {5, 0}), >=))) {
                tpps = (shm_conn_info->seq_counter[1] - shm_conn_info->tpps_old) * 1000 / tv2ms(&tv_tmp);
                shm_conn_info->tpps = tpps;
                shm_conn_info->tpps_old = shm_conn_info->seq_counter[1];
                shm_conn_info->tpps_tick_tv = info.current_time;
            }
            shm_conn_info->is_single_channel = is_single();
            
            sem_post(&(shm_conn_info->stats_sem));
            statb.packet_sent_ag = 0;
            statb.packet_sent_rmit = 0;
            
            info.psl_per_second = info.psl_count * 2;
            info.loss_events_per_second = info.loss_event_count * 2;
            info.psl_count = 0;
            info.loss_event_count = 0;
            if(info.loss_events_per_second > 10 && info.psl_per_second > 100) {
                info.xlm = 1;
            } else {
                info.xlm = 0;
            }
                
            
            //Check time interval and ping if need.
            if (((info.current_time.tv_sec - last_ping) > lfd_host->PING_INTERVAL) ) {
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
                            vlog(LOG_INFO, "PING2 chan_num %d", i);
                        }
                    } else {
                        // send ping request - 2
                        len_ret = udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                        if(debug_trace) {
                            vlog(LOG_INFO, "PING2 chan_num %d", i);
                        }
                    }
                    if (len_ret < 0) {
    						vlog(LOG_ERR, "Could not send echo request 2 chan %d reason %s (%d)", i, strerror(errno), errno);
    						break;
    					}
    				shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                    shm_conn_info->stats[info.process_num].packet_upload_cnt++;
    				info.channel[i].up_len += len_ret;
    			}
    		}

            json_timer = info.current_time;
            info.max_send_q_max = 0;
            info.max_send_q_min = 120000;
            fire_event(&my_events->update);
            max_chan = shm_conn_info->max_chan;
        }
        // <<< END JSON LOGS
        
        

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
        // for (i = 1; i < info.channel_amount; i++) {
        {
            i=1;
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
                
#ifdef CLIENTONLY
                if(info.head_channel) { 
                    tmp16_n = htons((uint16_t) (100+i)); // chan_num ?? not needed in fact TODO remove
                } else {
                    tmp16_n = htons((uint16_t) (i)); // chan_num ?? not needed in fact TODO remove
                }
#else
                if(info.head_channel) { 
                    tmp16_n = htons((uint16_t) (200+i)); // chan_num ?? not needed in fact TODO remove
                } else {
                    tmp16_n = htons((uint16_t) (i)); // chan_num ?? not needed in fact TODO remove
                }
#endif
                memcpy(buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), &tmp16_n, sizeof(uint16_t));
                tmp32_n = htonl(info.channel[1].packet_download);
                memcpy(buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // down speed per current chan (PCS send)
                struct timeval tmp_tv;
                // local_seq_num
                tmp32_n = htonl(info.channel[i].local_seq_num);
                memcpy(buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // local_seq_num
                /*
                uint16_t tmp16 = ((uint16_t) (-1));
                sem_wait(write_buf_sem);
                if ((unsigned int) shm_conn_info->forced_rtt < ((uint16_t) (-1))) {
                    tmp16 = shm_conn_info->forced_rtt;
                }
                sem_post(write_buf_sem);
                tmp16_n = htons(tmp16); //forced_rtt here
                */
                //tmp16_n = htons(shm_conn_info->frtt_local_applied); //forced_rtt here // replacing this with hsqs
                tmp16_n = htons(info.head_send_q_shift);
                memcpy(buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); // hsqs
                tmp32_n = htonl(ag_mask2hsag_mask(shm_conn_info->ag_mask));
                memcpy(buf + 5 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //ag_mask
//                vlog(LOG_ERR,"FRAME_CHANNEL_INFO send buf_len %d counter %d current buf_len %d", buf_len_real, shm_conn_info->buf_len_send_counter,shm_conn_info->write_buf[1].frames.length);
                tmp32_n = htons(shm_conn_info->stats[info.process_num].sqe_mean / info.eff_len); // sqe_mean (in pkt)
                memcpy(buf + 5 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint16_t)); // sqe_mean (in pkt)
                buf_len_real = shm_conn_info->write_buf[1].frames.length;
                tmp32_n = htons(buf_len_real);
                memcpy(buf + 6 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint16_t)); //buf_len
                //tmp16_n = htons(get_lbuf_len());
                tmp16_n = htons(shm_conn_info->max_stuck_buf_len);
                memcpy(buf + 7 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //lbuf_len
                tmp32_n = htonl(shm_conn_info->write_buf[i].last_received_seq[info.process_num]); // global seq_num
                memcpy(buf + 8 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //global seq_num
                //tmp32_n = htons(shm_conn_info->slow_start); 
                tmp32_n = htonl(shm_conn_info->seq_counter[1]); 
                //tmp16_n = 0;
                memcpy(buf + 8 * sizeof(uint16_t) + 5 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //global seq_num
                if(debug_trace) {
                vlog(LOG_ERR,
                        "FRAME_CHANNEL_INFO LLRS send chan_num %d packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" ",
                        i, info.channel[i].packet_recv_counter, info.channel[i].packet_loss_counter,
                        (int16_t)info.channel[i].local_seq_num_recv, (uint32_t) (tmp_tv.tv_sec * 1000000 + tmp_tv.tv_usec));
                        }
                // send FCI-LLRS
                int len_ret = udp_write(info.channel[i].descriptor, buf, ((8 * sizeof(uint16_t) + 6 * sizeof(uint32_t)) | VTUN_BAD_FRAME));
                info.channel[i].local_seq_num++;
                if (len_ret < 0) {
                    vlog(LOG_ERR, "Could not send FRAME_CHANNEL_INFO; reason %s (%d)", strerror(errno), errno);
                    linker_term = TERM_NONFATAL;
                    break;
                }
                info.channel[i].packet_recv_counter = 0;
                shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret; // WTF?? no sync / futex ??
                shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                info.channel[0].up_len += len_ret;
            }

            // now check if we need to fire LOSS event - send and commit locally
            if(is_loss() || need_send_loss_FCI_flag) { // we are in loss monitoring state..
                timersub(&info.current_time, &info.channel[i].last_recv_time, &tv_tmp);
                int timer_result2 = timercmp(&tv_tmp, &info.max_reorder_latency, >=);
                if ( (need_send_loss_FCI_flag || timer_result2) && select_net_write(i)) {
                    // now send and zero
                    int lrs = 0; // TODO: this seems unessessary
                    if(timer_result2) need_send_loss_FCI_flag = lossed_latency_drop(&lrs);
                    tmp16_n = htons((uint16_t)info.channel[i].packet_recv_counter); // amt of rcvd packets
                    memcpy(buf, &tmp16_n, sizeof(uint16_t)); // amt of rcvd packets

                    // TODO: do we use local_seq_num difference or total packets receive count??
                    info.r_lost++;
                    //if( (info.channel[i].local_seq_num_recv - info.channel[i].local_seq_num_beforeloss) > MAX_REORDER_PERPATH) {
                    vlog(LOG_INFO, "sedning loss %hd lrs %d, llrs %d", need_send_loss_FCI_flag, shm_conn_info->write_buf[i].last_received_seq[info.process_num], info.channel[i].local_seq_num_recv);

                    if(shm_conn_info->stats[info.process_num].pbl_lossed_cnt < 100) {
                        tmp16_n = htons(need_send_loss_FCI_flag + 10000); // dumbass method of telling that loss is unrecoverable
                    } else {
                        tmp16_n = htons(need_send_loss_FCI_flag); // amt of pkts lost till this moment
                    }

                    // inform here that we detected loss -->
                    sem_wait(&(shm_conn_info->write_buf_sem));
                    shm_conn_info->l_loss_idx++;
                    if (shm_conn_info->l_loss_idx == LOSS_ARRAY) {
                        shm_conn_info->l_loss_idx = 0;
                    }
                    shm_conn_info->l_loss[shm_conn_info->l_loss_idx].timestamp = info.current_time;
                    shm_conn_info->l_loss[shm_conn_info->l_loss_idx].psl = need_send_loss_FCI_flag;
                    shm_conn_info->l_loss[shm_conn_info->l_loss_idx].pbl = shm_conn_info->stats[info.process_num].pbl_lossed_cnt;
                    shm_conn_info->l_loss[shm_conn_info->l_loss_idx].sqn = info.lossed_local_seq_num_lost_start;
                    shm_conn_info->l_loss[shm_conn_info->l_loss_idx].who_lost = shm_conn_info->stats[info.process_num].hsnum;
                    
                    shm_conn_info->stats[info.process_num].pbl_lossed_saved = shm_conn_info->stats[info.process_num].pbl_lossed;
                    shm_conn_info->stats[info.process_num].pbl_lossed_cnt_saved = shm_conn_info->stats[info.process_num].pbl_lossed_cnt;
                    
                    shm_conn_info->stats[info.process_num].pbl_lossed = shm_conn_info->stats[info.process_num].pbl_lossed_cnt;
                    shm_conn_info->stats[info.process_num].pbl_lossed_cnt = 0;
                    memcpy(&shm_conn_info->l_loss[shm_conn_info->l_loss_idx].name, lfd_host->host + strlen(lfd_host->host) - 2, 2);
                    need_send_loss_FCI_flag = 0;
                    if(lrs) shm_conn_info->write_buf[i].last_received_seq[info.process_num] = lrs; // TODO: this seems unessessary
                    shm_conn_info->write_buf[i].possible_seq_lost[info.process_num] = shm_conn_info->write_buf[i].last_received_seq[info.process_num] - 1;
                    // inform that we lost packet
                    shm_conn_info->write_buf[i].packet_lost_state[info.process_num] = 1;
                    
                    sem_post(&(shm_conn_info->write_buf_sem));

                    memcpy(buf + sizeof(uint16_t), &tmp16_n, sizeof(uint16_t)); // loss
                    tmp16_n = htons(FRAME_CHANNEL_INFO);  // flag
                    memcpy(buf + 2 * sizeof(uint16_t), &tmp16_n, sizeof(uint16_t)); // flag
                    tmp32_n = htonl(info.channel[i].local_seq_num_recv); // last received local seq_num
                    memcpy(buf + 3 * sizeof(uint16_t), &tmp32_n, sizeof(uint32_t));
                     
#ifdef CLIENTONLY
                if(info.head_channel) { 
                    tmp16_n = htons((uint16_t) (100+i)); // chan_num ?? not needed in fact TODO remove
                } else {
                    tmp16_n = htons((uint16_t) (i)); // chan_num ?? not needed in fact TODO remove
                }
#else
                if(info.head_channel) { 
                    tmp16_n = htons((uint16_t) (200+i)); // chan_num ?? not needed in fact TODO remove
                } else {
                    tmp16_n = htons((uint16_t) (i)); // chan_num ?? not needed in fact TODO remove
                }
#endif
                    
                    memcpy(buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //chan_num
                    tmp32_n = htonl(info.channel[i].local_seq_num); // local_seq_num
                    memcpy(buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // local_seq_num
                    tmp32_n = htonl(info.channel[1].packet_download);
                    memcpy(buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // down speed per current chan
                    /*
                    uint16_t tmp16 = ((uint16_t) (-1));
                    sem_wait(write_buf_sem);
                    if ((unsigned int) shm_conn_info->forced_rtt < ((uint16_t) (-1))) {
                        tmp16 = shm_conn_info->forced_rtt;
                    }
                    sem_post(write_buf_sem);
                    tmp16_n = htons(tmp16); //forced_rtt here
                    */
                    //tmp16_n = htons(shm_conn_info->frtt_local_applied); //forced_rtt here
                    tmp16_n = htons(info.head_send_q_shift);
                    memcpy(buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //forced_rtt
                    tmp32_n = htonl(ag_mask2hsag_mask(shm_conn_info->ag_mask));
                    memcpy(buf + 5 * sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //forced_rtt

//                    vlog(LOG_ERR,"FRAME_CHANNEL_INFO send buf_len %d counter %d current buf_len %d",buf_len_real, shm_conn_info->buf_len_send_counter,shm_conn_info->write_buf[1].frames.length);
                    memcpy(buf + 5 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint16_t)); //buf_len counter
                    buf_len_real = shm_conn_info->write_buf[1].frames.length;
                    tmp32_n = htons(buf_len_real);
                    memcpy(buf + 6 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint16_t)); //buf_len
                    //tmp16_n = htons(get_lbuf_len());
                    tmp16_n = htons(shm_conn_info->max_stuck_buf_len);
                    memcpy(buf + 7 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp16_n, sizeof(uint16_t)); //lbuf_len
                    tmp32_n = htonl(shm_conn_info->write_buf[i].last_received_seq[info.process_num]); // global seq_num
                    memcpy(buf + 8 * sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //global seq_num
                    tmp32_n = htonl(shm_conn_info->seq_counter[1]); 
                    //tmp16_n = htons(shm_conn_info->slow_start); 
                    //tmp16_n = 0;
                    memcpy(buf + 8 * sizeof(uint16_t) + 5 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); //global seq_num
                        if(debug_trace) {
                    vlog(LOG_INFO,
                            "FRAME_CHANNEL_INFO send chan_num %d packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" ",
                            i, info.channel[i].packet_recv_counter, info.channel[i].packet_loss_counter,
                            (int16_t)info.channel[i].local_seq_num_recv, (uint32_t) (tv_tmp.tv_sec * 1000000 + tv_tmp.tv_usec));
                        }
                    // send FCI
                    // TODO: select here ???
                    int len_ret = udp_write(info.channel[i].descriptor, buf, ((8 * sizeof(uint16_t) + 6 * sizeof(uint32_t)) | VTUN_BAD_FRAME));
                    info.channel[i].local_seq_num++;

                    if (len_ret < 0) {
                        vlog(LOG_ERR, "Could not send FRAME_CHANNEL_INFO; reason %s (%d)", strerror(errno), errno);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                    info.channel[i].packet_recv_counter = 0;
                    shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret; // WTF?? no sync / futex ??
                    shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                    info.channel[0].up_len += len_ret;                    
                    infer_lost_seq_num(incomplete_seq_buf);
                }
            }

            /* TODO write function for lws sending*/
            // sem_wait(&(shm_conn_info->write_buf_sem));
            // uint32_t last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
            uint32_t last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
            // sem_post(&(shm_conn_info->write_buf_sem));
            if ((last_written_seq_tmp > (last_last_written_seq[i] + LWS_NOTIFY_MAX_SUB_SEQ)) && select_net_write(i) ) {
                // TODO: DUP code!
                
                if(debug_trace) {
                    vlog(LOG_INFO, "Sending LWS...");
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
                    vlog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                    linker_term = TERM_NONFATAL;
                }
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                info.channel[i].up_len += len_ret;
            }
        } // for each chan_num loop end ([i])
        // <<< END SEND FCI

       CHKCPU(9); 
        
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
            udp_struct->lport = info.channel[1].lport;
            udp_struct->rport = info.channel[1].rport;
            //if (get_udp_stats(udp_struct, 1)) {
            //    vlog(LOG_INFO, "udp stat lport %d dport %d tx_q %d rx_q %d drops %d ", udp_struct->lport, udp_struct->rport, udp_struct->tx_q,
            //            udp_struct->rx_q, udp_struct->drops);
            //}
            cubic_t_max = t_from_W(RSR_TOP, info.send_q_limit_cubic_max, info.B, info.C);
            info.cubic_t_max_u = t_from_W(RSR_TOP, info.W_u_max, info.Bu, info.Cu); // TODO: place it everywhere whenever W_u_max changes??
            if(shm_conn_info->write_buf[1].possible_seq_lost[info.process_num] > shm_conn_info->write_buf[1].last_received_seq[info.process_num]) {
                vlog(LOG_INFO, "WARNING Fixing psl %d > lrs %d to last received seq", shm_conn_info->write_buf[1].possible_seq_lost[info.process_num], shm_conn_info->write_buf[1].last_received_seq[info.process_num]);
                shm_conn_info->write_buf[1].possible_seq_lost[info.process_num] = shm_conn_info->write_buf[1].last_received_seq[info.process_num];
            }
            if (info.check_shm) { // impossible to work (remove!?)
                sem_wait(&(shm_conn_info->AG_flags_sem));
                uint32_t chan_mask = shm_conn_info->channels_mask;
                if (shm_conn_info->need_to_exit & (1 << info.process_num)) {
                    linker_term = TERM_NONFATAL;
                    vlog(LOG_INFO, "Need to exit by peer");
                }
                sem_post(&(shm_conn_info->AG_flags_sem));
                for (uint32_t i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                    if (!(chan_mask & (1 << i))) {
                        if (last_channels_mask & (1 << i)) {
    #ifdef DEBUGG
                            vlog(LOG_INFO, "Sending FRAME_DEAD_CHANNEL for %i", i);
    #endif
                            uint32_t i_n = htonl(i);
                            uint16_t flag_n = htons(FRAME_DEAD_CHANNEL);
                            memcpy(buf, &i_n, sizeof(uint32_t));
                            memcpy(buf, &flag_n, sizeof(uint16_t));
                            int len_ret = proto_write(info.channel[0].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                            if (len_ret < 0) {
                                vlog(LOG_ERR, "Could not send FRAME_DEAD_CHANNEL; exit");
                                linker_term = TERM_NONFATAL;
                            }
                        }
                    }
                }
                last_channels_mask = chan_mask;
                if (shm_conn_info->session_hash_remote != info.session_hash_remote) {
                    vlog(LOG_INFO, "Need to exit by hash compare; exit");
                    linker_term = TERM_NONFATAL;
                }
            }

            if ((get_ds_ts(info.current_time) - last_net_read_ds) > lfd_host->MAX_IDLE_TIMEOUT*100) {
                vlog(LOG_INFO, "Session %s network timeout", lfd_host->host);
                break;
            }

            info.encap_streams = NumberOfSetBits(info.encap_streams_bitcnt);
            info.encap_streams_bitcnt= 0;
            // int stsum = 0;
            // int stmax=0;
            // for(int i=0;i<MAX_TCP_PHYSICAL_CHANNELS;i++) {//   WARN unsync but seems dont care
            //     stsum+=shm_conn_info->streams[i];
            //     if(stmax<shm_conn_info->streams[i]) {
            //         stmax = shm_conn_info->streams[i];
            //     }
            //     shm_conn_info->streams[i]=0;
            // }
            // if((stsum-stmax) > (stmax/20)) {
            //     shm_conn_info->single_stream=0;
            // } else {
            //     shm_conn_info->single_stream=1;
            // }
            
            set_IDLE();

            // head detect code
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) SPEED_REDETECT_TV), >=)) {
                sem_wait(&(shm_conn_info->stats_sem));
                redetect_head_unsynced(chan_mask, -1);
                sem_post(&(shm_conn_info->stats_sem));
            }
            #ifdef CLIENTONLY
            timersub(&info.current_time, &shm_conn_info->last_head, &tv_tmp_tmp_tmp);
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {800,0}), >=)) {
                vlog(LOG_ERR, "WARNING! last_head too high psl %d > lrs %d", seq_num, info.exact_rtt);
                sq_control = 0;
            } else {
                sq_control = 1;
            }
            #endif
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
                    shm_conn_info->stats[info.process_num].time_lag_remote = time_lag_local.time_lag;
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed =
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt / time_passed;
                    sem_post(&(shm_conn_info->stats_sem));
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt = 0;
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed =
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt / (time_passed);
                    info.channel[i].download = shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed;
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt = 0;
#ifdef TRACE
                    vlog(LOG_INFO, "upload speed %"PRIu32" kb/s physical channel %d logical channel %d",
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed, info.process_num, i);
                    vlog(LOG_INFO, "download speed %"PRIu32" kb/s physical channel %d logical channel %d",
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed, info.process_num, i);
#endif
                    // speed in packets/sec calculation
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packet_speed =
                            (shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets / tv_tmp.tv_sec);
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets = 0;
#ifdef TRACE
                    vlog(LOG_INFO, "download speed %"PRIu32" packet/s physical channel %d logical channel %d lport %d rport %d",
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

                //todo send time_lag for all process(PHYSICAL CHANNELS)
                uint32_t time_lag_remote;
                uint16_t pid_remote;
                if(send_q_eff_mean > 1000) { // TODO: invent a more neat way to start sending buf_len (>0? changed?)// TODO removeL this was due to bug two lines below. Now fixed
                    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                        if(buf_len_sent[i] == my_miss_packets_max) continue;
                        buf_len_sent[i] = my_miss_packets_max;
                        sem_wait(&(shm_conn_info->stats_sem));
                        /* If pid is null --> link didn't up --> continue*/
                        if (shm_conn_info->stats[i].pid == 0) {
                            sem_post(&(shm_conn_info->stats_sem));
                            continue;
                        }
                        if (debug_trace) {
                            vlog(LOG_INFO, "Sending time lag (now buf_len) for %i buf_len %i.", i, my_miss_packets_max);
                        }
                        time_lag_remote = shm_conn_info->stats[i].time_lag_remote;
                        /* we store my_miss_packet_max value in 12 upper bits 2^12 = 4096 mx is 4095*/
                        time_lag_remote &= 0xFFFFF; // shrink to 20bit
                        time_lag_remote = shm_conn_info->stats[i].time_lag_remote | (my_miss_packets_max << 20);
                        pid_remote = shm_conn_info->stats[i].pid_remote;
                        uint32_t tmp_host = shm_conn_info->miss_packets_max_send_counter++;
                        tmp_host &= 0xFFFF;
    //vlog(LOG_ERR, "DEBUGG tmp_host %"PRIu32"", tmp_host); //?????
                        sem_post(&(shm_conn_info->stats_sem));
                        // sem_wait(write_buf_sem);
                        tmp_host |= shm_conn_info->tflush_counter << 16;
                        shm_conn_info->tflush_counter = 0;
                        // sem_post(write_buf_sem);
    //                    vlog(LOG_ERR, "DEBUGG tmp_host packed %"PRIu32"", tmp_host); //?????
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
                            vlog(LOG_ERR, "Could not send time_lag + pid pkt; exit"); //?????
                            linker_term = TERM_NONFATAL; //?????
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret;
                        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                        info.channel[0].up_len += len_ret;
                    }
                }
                my_miss_packets_max = 0;
                if (delay_cnt == 0)
                    delay_cnt = 1;
                mean_delay = (delay_acc / delay_cnt);
#ifdef DEBUGG
                //vlog(LOG_INFO, "tick! cn: %s; md: %d, dacq: %d, w: %d, isl: %d, bl: %d, as: %d, bsn: %d, brn: %d, bsx: %d, drop: %d, rrqrx: %d, rxs: %d, ms: %d, rxmntf: %d, rxm_notf: %d, chok: %d, info.rtt: %d, lkdf: %d, msd: %d, ch: %d, chsdev: %d, chrdev: %d, mlh: %d, mrh: %d, mld: %d", lfd_host->host, channel_mode, dev_my_cnt, weight, incomplete_seq_len, buf_len, shm_conn_info->normal_senders, statb.bytes_sent_norm, statb.bytes_rcvd_norm, statb.bytes_sent_rx, statb.pkts_dropped, statb.rxmit_req_rx, statb.rxmits, statb.mode_switches, statb.rxm_ntf, statb.rxmits_notfound, statb.chok_not, info.info.rtt, (info.current_time.tv_sec - shm_conn_info->lock_time), mean_delay, info.channel_amount, std_dev(statb.bytes_sent_chan, info.channel_amount), std_dev(&statb.bytes_rcvd_chan[1], (info.channel_amount-1)), statb.max_latency_hit, statb.max_reorder_hit, statb.max_latency_drops);
                //vlog(LOG_INFO, "ti! s/r %d %d %d %d %d %d / %d %d %d %d %d %d", statb.bytes_rcvd_chan[0],statb.bytes_rcvd_chan[1],statb.bytes_rcvd_chan[2],statb.bytes_rcvd_chan[3],statb.bytes_rcvd_chan[4],statb.bytes_rcvd_chan[5], statb.bytes_sent_chan[0],statb.bytes_sent_chan[1],statb.bytes_sent_chan[2],statb.bytes_sent_chan[3],statb.bytes_sent_chan[4],statb.bytes_sent_chan[5] );
#endif
                dev_my_cnt = 0;
                last_tick = info.current_time.tv_sec;
                shm_conn_info->alive = info.current_time.tv_sec;
                delay_acc = 0;
                delay_cnt = 0;

                for (i = 1; i < info.channel_amount; i++) {
                    // sem_wait(&(shm_conn_info->write_buf_sem));
                    uint32_t last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
                    uint32_t last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
                    // sem_post(&(shm_conn_info->write_buf_sem));
                    if (((info.current_time.tv_sec - last_lws_notified_tmp) > LWS_NOTIFY_PEROID) && (last_written_seq_tmp > last_last_written_seq[i])) {
                        if(!select_net_write(i)) continue;
                        // TODO: DUP code!
                        if(debug_trace) {
                            vlog(LOG_INFO, "Sending LWS...");
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
                            vlog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                            linker_term = TERM_NONFATAL;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                        info.channel[i].up_len += len_ret;
                    }
                }
            
            
            
            
             // do llist checks
            
            alive_physical_channels = 0;
            int check_result=0;
            
            // sem_wait(&(shm_conn_info->AG_flags_sem));
            uint32_t chan_mask = shm_conn_info->channels_mask;
            // sem_post(&(shm_conn_info->AG_flags_sem));
            
            
            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) { 
                if (chan_mask & (1 << i)) {
                    alive_physical_channels++;
                }
            }
            if (alive_physical_channels == 0) {
                vlog(LOG_ERR, "ASSERT All physical channels dead!!!");
                alive_physical_channels = 1;
            }
            if(shm_conn_info->t_model_rtt100 > MAX_NETWORK_STALL_MS * 100) {
                ms2tv(&tv_tmp, shm_conn_info->t_model_rtt100 / 100);
                sem_wait(&(shm_conn_info->write_buf_sem));
                shm_conn_info->max_network_stall = tv_tmp;
                sem_post(&(shm_conn_info->write_buf_sem));
            } else {
                sem_wait(&(shm_conn_info->write_buf_sem));
                shm_conn_info->max_network_stall = (struct timeval) MAX_NETWORK_STALL;
                sem_post(&(shm_conn_info->write_buf_sem));
            }
            
            
               last_timing.tv_sec = info.current_time.tv_sec;
               last_timing.tv_usec = info.current_time.tv_usec;
          }
#ifdef TESTING
            //write test case here
#endif
            if(shm_conn_info->packet_debug_enabled) {
                debug_trace = 1;
            }
            fire_event(&my_events->tick);
        }
        // <<< END TICK
        


        /* Detect that we need to enter retransmit_send as soon as possible 
            (some packets left unsent AND we're not holding) */
        int need_retransmit = 0;
        if( (ag_flag == R_MODE) && (hold_mode == 0) ) { // WARNING: if AG_MODE? or of DROP mode?
            //sem_wait(&(shm_conn_info->common_sem));
            for (int i = 1; i < info.channel_amount; i++) {
                if(shm_conn_info->seq_counter[1] > last_sent_packet_num[1].seq_num) {
                    // WARNING! disabled push-to-top policy!
                    if( !((!info.head_channel) && PUSH_TO_TOP && ptt_allow_once && (shm_conn_info->dropping || shm_conn_info->head_lossing)) && !check_delivery_time(SKIP_SENDING_CLD_DIV)) {
                        // noop?
                    } else {
                        need_retransmit = 1; 
                    }
                    break;
                }
            }
            //sem_post(&(shm_conn_info->common_sem));
        }
        // gettimeofday(&info.current_time, NULL); // TODO: required??
        
        

        //check redundancy code packet's timer
#ifdef SUM_SEND
        gettimeofday(&info.current_time, NULL );
        // for (int i = 1; i <= info.channel_amount; i++) {
        {
            int i = 1;
            for (int selection = 0; selection < SELECTION_NUM; selection++) {
                int flag = 0, len_sum;
                //int tmp = shm_conn_info->t_model_rtt100;
                int tmp = 100000;
                tv_tmp.tv_sec = tmp / 100000;
                tv_tmp.tv_usec = (tmp % 100000) * 10;
                sem_wait(&(shm_conn_info->common_sem)); // critical_sem
                shm_conn_info->packet_code[selection][i].timer.timer_time = tv_tmp;
                if (fast_check_timer(&shm_conn_info->packet_code[selection][i].timer, &info.current_time)
                        && (shm_conn_info->packet_code[selection][i].len_sum > 0)) {
#ifdef CODE_LOG
                    vlog(LOG_INFO, "raise REDUNDANT_CODE_TIMER_TIME add FRAME_REDUNDANCY_CODE to fast resend selection %d seq start %u stop %u  cur %u len %i time passed %u", selection, shm_conn_info->packet_code[selection][i].start_seq, shm_conn_info->packet_code[selection][i].stop_seq, shm_conn_info->packet_code[selection][i].current_seq, shm_conn_info->packet_code[selection][i].len_sum,tv2ms(&info.current_time) - tv2ms(&shm_conn_info->packet_code[selection][i].timer.start_time));
#endif
                    shm_conn_info->packet_code[selection][i].stop_seq = shm_conn_info->packet_code[selection][i].current_seq;
                    len_sum = pack_redundancy_packet_code(buf2, &shm_conn_info->packet_code[selection][i],
                            shm_conn_info->packet_code[selection][i].stop_seq, selection, FRAME_REDUNDANCY_CODE);
                    fast_update_timer(&shm_conn_info->packet_code[selection][i].timer, &info.current_time);
                    flag = 1;

                }

                sem_post(&(shm_conn_info->common_sem)); // critical_sem
                if (flag) {
                    len_sum = pack_packet(i, buf2, len_sum, 0, 0 /*local seq*/, FRAME_REDUNDANCY_CODE);
                    if (info.channel[i].local_seq_num == (UINT32_MAX - 1)) {
                        info.channel[i].local_seq_num = 0;
                    }
#ifdef CODE_LOG
                    vlog(LOG_ERR, "add redund code to fast_resend");
#endif
                    sem_wait(&(shm_conn_info->resend_buf_sem)); // critical_sem
                    int idx = add_fast_resend_frame(i, buf2, len_sum | VTUN_BAD_FRAME, 0);
                    sem_post(&(shm_conn_info->resend_buf_sem)); // critical_sem
                    if (idx == -1) {
                        vlog(LOG_ERR, "ERROR: fast_resend_buf is full");
                    }

                }
                if (flag) {
                    need_retransmit = 1;
                }
                flag = 0;
            }
        }
#endif
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
        // removed sem here in a hope of atomic and non-critial sync
        chan_mask = shm_conn_info->channels_mask;
        // end removed sem
        FD_ZERO(&fdset_w);
        sem_wait(write_buf_sem); // critical_sem
        for (;;)
            if (info.last_sent_FLI_idx != shm_conn_info->loss_idx) {
                info.last_sent_FLI_idx++;
                if (info.last_sent_FLI_idx == LOSS_ARRAY) {
                    info.last_sent_FLI_idx = 0;
                }
                vlog(LOG_INFO, "FRAME_LOSS_INFO sending my idx %d shm idx %d time %d %d psl %d pbl %d", info.last_sent_FLI_idx,
                        shm_conn_info->loss_idx, shm_conn_info->loss[info.last_sent_FLI_idx].timestamp.tv_sec,
                        shm_conn_info->loss[info.last_sent_FLI_idx].timestamp.tv_usec, shm_conn_info->loss[info.last_sent_FLI_idx].psl,
                        shm_conn_info->loss[info.last_sent_FLI_idx].pbl);

                uint32_t tmp_h = htonl(info.last_sent_FLI_idx);
                memcpy(buf, &tmp_h, sizeof(uint32_t));
                tmp_h = htons(FRAME_LOSS_INFO);
                memcpy(buf + sizeof(uint32_t), &tmp_h, sizeof(uint16_t));
                tmp_h = htonl(shm_conn_info->loss[info.last_sent_FLI_idx].timestamp.tv_sec);
                memcpy(buf + sizeof(uint16_t) + sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->loss[info.last_sent_FLI_idx].timestamp.tv_usec);
                memcpy(buf + sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->loss[info.last_sent_FLI_idx].psl);
                memcpy(buf + sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->loss[info.last_sent_FLI_idx].pbl);
                memcpy(buf + sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->loss[info.last_sent_FLI_idx].sqn);
                memcpy(buf + sizeof(uint16_t) + 5 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                uint16_t tmp_s = htons(shm_conn_info->loss[info.last_sent_FLI_idx].who_lost);
                memcpy(buf + sizeof(uint16_t) + 6 * sizeof(uint32_t), &tmp_s, sizeof(uint16_t));

                fd_set fdset2;
                tv_tmp.tv_sec = 0;
                tv_tmp.tv_usec = 0;
                FD_ZERO(&fdset2);
                FD_SET(service_channel, &fdset2);
                if (select(service_channel + 1, NULL, &fdset2, NULL, &tv_tmp) > 0) {
                    if (proto_write(service_channel, buf, ((6 * sizeof(uint32_t) + 2 * sizeof(uint16_t)) | VTUN_BAD_FRAME)) < 0) {
                        vlog(LOG_ERR, "Could not send FLI pkt; exit %s(%d)", strerror(errno), errno);
                        close(prio_s);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                } else {
                    info.last_sent_FLI_idx--;
                    if (info.last_sent_FLI_idx < 0) {
                        info.last_sent_FLI_idx = LOSS_ARRAY - 1;
                    }
                    break;
                }
            } else
                break;
        for (;;)
            if (info.last_sent_FLLI_idx != shm_conn_info->l_loss_idx) {
                info.last_sent_FLLI_idx++;
                if (info.last_sent_FLLI_idx == LOSS_ARRAY) {
                    info.last_sent_FLLI_idx = 0;
                }
                vlog(LOG_INFO, "FRAME_L_LOSS_INFO sending sqn %lu ts %ld.%06ld", shm_conn_info->l_loss[info.last_sent_FLLI_idx].sqn, shm_conn_info->l_loss[info.last_sent_FLLI_idx].timestamp);
                uint32_t tmp_h = htonl(info.last_sent_FLLI_idx);
                memcpy(buf, &tmp_h, sizeof(uint32_t));
                tmp_h = htons(FRAME_L_LOSS_INFO);
                memcpy(buf + sizeof(uint32_t), &tmp_h, sizeof(uint16_t));
                tmp_h = htonl(shm_conn_info->l_loss[info.last_sent_FLLI_idx].timestamp.tv_sec);
                memcpy(buf + sizeof(uint16_t) + sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->l_loss[info.last_sent_FLLI_idx].timestamp.tv_usec);
                memcpy(buf + sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->l_loss[info.last_sent_FLLI_idx].psl);
                memcpy(buf + sizeof(uint16_t) + 3 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                tmp_h = htonl(shm_conn_info->l_loss[info.last_sent_FLLI_idx].pbl);
                memcpy(buf + sizeof(uint16_t) + 4 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                uint16_t tmp_16_h = htons(shm_conn_info->l_loss[info.last_sent_FLLI_idx].name);
                memcpy(buf + sizeof(uint16_t) + 5 * sizeof(uint32_t), &tmp_16_h, sizeof(uint16_t));
                tmp_h = htonl(shm_conn_info->l_loss[info.last_sent_FLLI_idx].sqn);
                memcpy(buf + sizeof(uint16_t) + 6 * sizeof(uint32_t), &tmp_h, sizeof(uint32_t));
                uint16_t tmp_s = htons(shm_conn_info->l_loss[info.last_sent_FLLI_idx].who_lost);
                memcpy(buf + sizeof(uint16_t) + 7 * sizeof(uint32_t), &tmp_s, sizeof(uint16_t));
                
                fd_set fdset2;
                tv_tmp.tv_sec = 0;
                tv_tmp.tv_usec = 0;
                FD_ZERO(&fdset2);
                FD_SET(service_channel, &fdset2);
                if (select(service_channel + 1, NULL, &fdset2, NULL, &tv_tmp) > 0) {
                    if (proto_write(service_channel, buf, ((7 * sizeof(uint32_t) + 3 * sizeof(uint16_t)) | VTUN_BAD_FRAME)) < 0) {
                        vlog(LOG_ERR, "Could not send FLLI pkt; exit %s(%d)", strerror(errno), errno);
                        close(prio_s);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                } else {
                    info.last_sent_FLLI_idx--;
                    if (info.last_sent_FLLI_idx < 0) {
                        info.last_sent_FLLI_idx = LOSS_ARRAY - 1;
                    }
                    break;
                }
            } else
                break;
        int next_token_ms;
        next_token_ms = 0;
        add_tokens(1, &next_token_ms);
        if (get_write_buf_wait_data(chan_mask, &next_token_ms) || need_retransmit || check_fast_resend()) { // TODO: need_retransmit here is because we think that it does continue almost immediately on select
            pfdset_w = &fdset_w;
            FD_SET(info.tun_device, pfdset_w);
        } else {
            pfdset_w = NULL;
        }
        sem_post(write_buf_sem); // critical_sem
        #ifdef FRTTDBG
            vlog(LOG_INFO, "next_token_ms %d", next_token_ms);
        #endif
        FD_ZERO(&fdset);
#ifdef DEBUGG
        vlog(LOG_INFO, "debug: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
#endif
        struct timespec sel_tv;
        if (((hold_mode == 0) || (drop_packet_flag == 1)) && (info.just_started_recv == 1)) {
            FD_SET(info.tun_device, &fdset);
            sel_tv.tv_sec = 0;
            if ((next_token_ms == 0) || (next_token_ms > (SELECT_SLEEP_USEC / 1000))) {
                sel_tv.tv_nsec = SELECT_SLEEP_USEC * 1000;
            } else {
                sel_tv.tv_nsec = next_token_ms * 1000 * 1000;
            }
        } else {
            sel_tv.tv_sec = get_info_time.tv_sec;
            if ((next_token_ms == 0) || (next_token_ms > (get_info_time.tv_usec / 1000))) {
                sel_tv.tv_nsec = get_info_time.tv_usec * 1000;
            } else {
                sel_tv.tv_nsec = next_token_ms * 1000 * 1000;
            }
#ifdef DEBUGG
            vlog(LOG_INFO, "tun read select skip");
            vlog(LOG_INFO, "debug: HOLD_MODE");
#endif
        }
        // for (i = 0; i < info.channel_amount; i++) {
        //     FD_SET(info.channel[i].descriptor, &fdset);
        // }
        
        FD_SET(info.channel[0].descriptor, &fdset);
        FD_SET(info.channel[1].descriptor, &fdset);

#ifdef DEBUGG
        struct timeval work_loop1, work_loop2;
        gettimeofday(&work_loop1, NULL );
#endif
#ifdef SYSLOG
        // CPU LAG >>>
        gettimeofday(&cpulag, NULL);
        timersub(&cpulag, &old_time, &tv_tmp_tmp_tmp);
        if(tv_tmp_tmp_tmp.tv_usec > SUPERLOOP_MAX_LAG_USEC) {
            vlog(LOG_INFO,"WARNING! CPU deficiency detected! Cycle lag: %ld.%06ld", tv_tmp_tmp_tmp.tv_sec, tv_tmp_tmp_tmp.tv_usec);
        }
        // <<< END CPU_LAG
#endif
main_select:
        select_tv_copy = tv;
        const struct timespec *sel_tvp = &sel_tv;
        select_check=1;
        len = pselect(maxfd + 1, &fdset, pfdset_w, NULL, sel_tvp, &unblock_mask);
        select_check=0;
#ifdef DEBUGG
if(drop_packet_flag) {
        //gettimeofday(&work_loop2, NULL );
        vlog(LOG_INFO, "First select time: us descriptors num: %i", length);
}
#endif

        gettimeofday(&old_time, NULL); // cpu-lag..

        if (len < 0) { // selecting from multiple processes does actually work...
            // errors are OK if signal is received... TODO: do we have any signals left???
            if( errno != EAGAIN && errno != EINTR ) {
                vlog(LOG_INFO, "eagain select err; exit");
                break;
            } else {
                //vlog(LOG_INFO, "else select err; continue norm");
                continue;
            }
        }

        gettimeofday(&info.current_time, NULL); // current time may be ruined by select... TODO: this is expensive call -> optimize by timeradd?

        if( !len ) {
            /* We are idle, lets check connection */
#ifdef DEBUGG
            vlog(LOG_INFO, "idle...");
#endif
                /* Send ECHO request */
                if((info.current_time.tv_sec - last_action) > lfd_host->PING_INTERVAL) {
                    if(ping_rcvd) {
                         ping_rcvd = 0;
                         last_ping = info.current_time.tv_sec;
                         vlog(LOG_INFO, "PING ...");
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
                                 vlog(LOG_ERR, "Could not send echo request chan %d reason %s (%d)", i, strerror(errno), errno);
                                 linker_term = TERM_NONFATAL;
                                 break;
                             }
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                        info.channel[i].up_len += len_ret;
                         }
                         last_action = info.current_time.tv_sec; // TODO: clean up last_action/or/last_ping wtf.
                    }
                }
            continue;
        }
        CHKCPU(1);
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
        // int alive_physical_channels = 0;
        // if (FD_ISSET(info.tun_device, &fdset_w)) {
        //     sem_wait(&(shm_conn_info->AG_flags_sem));
        //     uint32_t chan_mask = shm_conn_info->channels_mask;
        //     sem_post(&(shm_conn_info->AG_flags_sem));
        //     for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        //         if (chan_mask & (1 << i)) {
        //             alive_physical_channels++;
        //         }
        //     }
        //     if (alive_physical_channels == 0) {
        //         vlog(LOG_ERR, "ASSERT All physical channels dead!!!");
        //         alive_physical_channels = 1;
        //     }
        // }
        CHKCPU(11);
        //check all chans for being set..
        for (chan_num = 0; chan_num < info.channel_amount; chan_num++) {
            if (FD_ISSET(info.tun_device, &fdset_w)) {
                sem_wait(write_buf_sem); // critical_sem
                if (write_buf_check_n_flush(chan_num)) { //double flush if possible
                    //write_buf_check_n_flush(chan_num); // fix for #509
                }
                sem_post(write_buf_sem); // critical_sem
            }
        CHKCPU(111);
            fd0 = -1;
            if(FD_ISSET(info.channel[chan_num].descriptor, &fdset)) {
                if(shm_conn_info->write_buf[chan_num_virt].frames.rel_head == -1) { // protect from unnesessary lock in case of high-speed workload (buffer not empty)
                    sem_wait(write_buf_sem); // critical_sem
                    fprev = shm_conn_info->write_buf[chan_num_virt].frames.rel_head;
                    if(fprev == -1) { // don't panic ;-)
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = info.current_time.tv_sec;
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = info.current_time.tv_usec;
                    }
                    sem_post(write_buf_sem); // critical_sem
                }
                fd0=info.channel[chan_num].descriptor; // TODO Why this need????

                //net_counter++; // rxmit mode
                last_action = info.current_time.tv_sec;
                if (chan_num == 0) {
                    len = tcp_read(fd0, buf);
                } else {
                    len = udp_read(fd0, buf);
                }

        CHKCPU(112);
#ifdef DEBUGG
if(drop_packet_flag) {
                vlog(LOG_INFO, "data on net... chan %d", chan_num);
}
#endif
                if( len<= 0 ) {
                    if (len == 0) {
                        vlog(LOG_INFO, "proto_read return 0, the peer with %d has performed an orderly shutdown. TERM_NONFATAL", chan_num);
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                    if(len < 0) {
                         vlog(LOG_INFO, "sem_post! proto read <0; reason %s (%d)", strerror(errno), errno);
                         linker_term = TERM_NONFATAL;
                         break;
                    }
                    if(proto_err_cnt > 5) { // TODO XXX whu do we need this?? why doesnt proto_read just return <0???
                             vlog(LOG_INFO, "MAX proto read len==0 reached; exit!");
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
                vlog(LOG_INFO, "data on net... chan %d len %i", chan_num, length);
#endif
                if(debug_trace) {
                    vlog(LOG_INFO, "data on net... chan %d len %i", chan_num, len);
                }
        CHKCPU(12);
                shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].down_data_len_amt += len;
                if( fl ) { // a packet with flag, relatively rare
                    if( fl==VTUN_BAD_FRAME ) {
                        flag_var = ntohs(*((uint16_t *)(buf+(sizeof(uint32_t)))));
                        if(flag_var == FRAME_MODE_NORM) {
                            vlog(LOG_ERR, "ASSERT FAILED! received FRAME_MODE_NORM flag while not in MODE_RETRANSMIT mode!");
                            continue;
                        } else if (flag_var == FRAME_REDUNDANCY_CODE) {
#ifdef CODE_LOG
                            vlog(LOG_INFO, "FRAME_REDUNDANCY_CODE on net... chan %d len %i array index %i start_seq %"PRIu32"", chan_num, len, shm_conn_info->packet_code_bulk_counter,ntohl(*((uint32_t *)(buf))));
                            print_head_of_packet(buf + sizeof(uint32_t) + sizeof(uint16_t), "recv redund code",0, len - (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t)));
#endif
#ifdef SUM_SEND
                            uint32_t local_seq_num, last_recv_lsn, packet_recv_spd;
                            uint16_t mini_sum;
                            len = seqn_break_tail(buf, len, NULL, &flag_var, &local_seq_num, NULL, &last_recv_lsn, &packet_recv_spd);
                            /*
                            unsigned int lrs2;
                            if (lossed_consume(local_seq_num, 0, &lrs2, &info.channel[chan_num].local_seq_num_recv) == 0) { // TODO: lrs?? not updated!
                                info.channel[chan_num].loss_time = info.current_time;
                            }
                            */
                            info.channel[1].last_recv_time = info.current_time;
                            sem_wait(write_buf_sem);
                            int sumIndex = add_redundancy_packet_code(&shm_conn_info->packet_code_recived[chan_num][0],
                                    &shm_conn_info->packet_code_bulk_counter, buf, len);
                            uint32_t lostSeq = frame_llist_getLostPacket_byRange(&shm_conn_info->write_buf[chan_num].frames,&shm_conn_info->wb_just_write_frames[chan_num],
                                    shm_conn_info->frames_buf, &shm_conn_info->packet_code_recived[chan_num][sumIndex]);
                            vlog(LOG_INFO, "FRAME_REDUNDANCY_CODE start_seq %"PRIu32" stop_seq %"PRIu32" LostAmount %d",
                                    shm_conn_info->packet_code_recived[chan_num][sumIndex].start_seq,
                                    shm_conn_info->packet_code_recived[chan_num][sumIndex].stop_seq,
                                    shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount);
                            if (shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount == 1) {
//#ifdef CODE_LOG
                                vlog(LOG_INFO, "Uniq lostSeq %u found lws %lu", lostSeq, shm_conn_info->write_buf[chan_num].last_written_seq );
//#endif
                                int packet_index = check_n_repair_packet_code(&shm_conn_info->packet_code_recived[chan_num][0],
                                        &shm_conn_info->wb_just_write_frames[chan_num], &shm_conn_info->write_buf[chan_num].frames,
                                        shm_conn_info->frames_buf, lostSeq);
                                if (packet_index > -1) {
                                    shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount = 0;
                                    if (shm_conn_info->packet_code_recived[chan_num][packet_index].sum[0] != 0x45) {
                                        print_head_of_packet(shm_conn_info->packet_code_recived[chan_num][packet_index].sum,
                                                "ASSERT BAD packet repaired ", lostSeq, shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum);
                                    } else {
                                        vlog(LOG_INFO, "{\"name\":\"%s\",\"repaired_seq_num\":%"PRIu32", \"place\": 2}", lfd_host->host, lostSeq);
#ifdef CODE_LOG
                                    print_head_of_packet(shm_conn_info->packet_code_recived[chan_num][packet_index].sum, "repaired ", lostSeq, shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum);
#endif
                                    // TODO: assert here
                                    write_buf_add(chan_num, shm_conn_info->packet_code_recived[chan_num][packet_index].sum,
                                            shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum, lostSeq, incomplete_seq_buf, &buf_len,
                                            info.pid, &succ_flag);
                                    }
                                }
                            }
                            sem_post(write_buf_sem);
#endif
                            continue;
                        } else if (flag_var == FRAME_MODE_RXMIT) {
                            // okay
                        } else if (flag_var == FRAME_JUST_STARTED) {
                            // the opposite end has zeroed counters; zero mine!
                            uint32_t session_hash_remote = ntohl(*((uint32_t *) (buf)));
                            vlog(LOG_INFO, "received FRAME_JUST_STARTED; receive remote hash - %u", session_hash_remote);
                            info.just_started_recv = 1;
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            if (shm_conn_info->session_hash_remote != session_hash_remote) {
                                shm_conn_info->session_hash_remote = session_hash_remote;
                                uint32_t chan_mask = shm_conn_info->channels_mask;
                                vlog(LOG_INFO, "zeroing counters old - %u new remote hash - %u",shm_conn_info->session_hash_remote, session_hash_remote );
                                shm_conn_info->tokens_lastadd_tv = info.current_time;
                                sem_post(&(shm_conn_info->AG_flags_sem));
                                info.session_hash_remote = session_hash_remote;
                                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
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
                                    frame_llist_init(&shm_conn_info->wb_just_write_frames[i]);
                                    frame_llist_fill(&(shm_conn_info->wb_free_frames), shm_conn_info->frames_buf, FRAME_BUF_SIZE);
                                }
                                shm_conn_info->max_network_stall = (struct timeval) MAX_NETWORK_STALL;
                                memset(shm_conn_info->w_stream_pkts, 0, sizeof(shm_conn_info->w_stream_pkts));
                                sem_post(&(shm_conn_info->write_buf_sem));
                                sem_wait(&(shm_conn_info->resend_buf_sem));
                                for (i = 0; i < RESEND_BUF_SIZE; i++) {
                                    if (shm_conn_info->resend_frames_buf[i].chan_num == chan_num)
                                        shm_conn_info->resend_frames_buf[i].seq_num = 0;
                                }
                                memset(shm_conn_info->resend_frames_buf, 0, sizeof(struct frame_seq) * RESEND_BUF_SIZE);
                                memset(shm_conn_info->fast_resend_buf, 0, sizeof(struct frame_seq) * MAX_TCP_PHYSICAL_CHANNELS);
                                memset(shm_conn_info->write_buf_hashtable, 0, sizeof(shm_conn_info->write_buf_hashtable));
                                shm_conn_info->resend_buf_idx = 0;
                                shm_conn_info->fast_resend_buf_idx = 0;
                                shm_conn_info->latest_la_sqn = 0;
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
                                vlog(LOG_ERR, "Could not set server address!");
                                linker_term = TERM_FATAL;
                                break;
                            }
                            inet_ntop(AF_INET, &rmaddr.sin_addr, ipstr, sizeof ipstr);
                            vlog(LOG_INFO, "Channels connecting to %s to create %d channels", ipstr, P_TCP_CONN_AMOUNT);
                            usleep(500000);

                            for (i = 1; i <= P_TCP_CONN_AMOUNT; i++) {
                                errno = 0;
                                if ((info.channel[i].descriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                                    vlog(LOG_ERR, "Can't create CHAN socket. %s(%d) chan %d", strerror(errno), errno, i);
                                    linker_term = TERM_FATAL;
                                    break;
                                }
                                if (lfd_host->RT_MARK != -1) {
                                    if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_MARK, &lfd_host->RT_MARK, sizeof(lfd_host->RT_MARK))) {
                                        vlog(LOG_ERR, "Client CHAN socket rt mark error %s(%d)", strerror(errno), errno);
                                        break_out = 1;
                                        break;
                                    }
                                }
                                /*
                                sendbuff = RCVBUF_SIZE;
                                // WARNING! This should be on sysadmin's duty to optimize!
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &sendbuff, sizeof(int)) == -1) {
                                    vlog(LOG_ERR, "WARNING! Can not set rmem (SO_RCVBUF) size. Performance will be poor.");
                                }
                                */


                                rmaddr.sin_port = htons(info.channel[i].rport);
                                connect(info.channel[i].descriptor, (struct sockaddr *)&rmaddr, sizeof(rmaddr));
                                // send PING request
                                udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                                usleep(500000);
                            }
                            if (i < P_TCP_CONN_AMOUNT) {
                                vlog(LOG_ERR, "Could not connect all requested tuns; exit");
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
                                vlog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                linker_term = TERM_NONFATAL;
                                break;
                            }
                            for (i = 0; i < info.channel_amount; i++) {
                                memset(&rmaddr, 0, sizeof(rmaddr));
                                memset(&localaddr, 0, sizeof(localaddr));
                                rmaddrlen = sizeof(rmaddr);
                                laddrlen = sizeof(localaddr);
                                if (getsockname(info.channel[i].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                                    vlog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                info.channel[i].lport = ntohs(localaddr.sin_port);
                                if (getpeername(info.channel[i].descriptor, (struct sockaddr *) (&rmaddr), &rmaddrlen) < 0) {
                                    vlog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                info.channel[i].rport = ntohs(rmaddr.sin_port);
                                vlog(LOG_INFO, "Client descriptor - %i logical channel - %i lport - %i rport - %i",info.channel[i].descriptor, i, info.channel[i].lport, info.channel[i].rport);
                            }
                            for(i = 1; i < info.channel_amount; i++) {
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_RCVTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
                                    vlog(LOG_ERR, "setsockopt failed");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                if (setsockopt(info.channel[i].descriptor, SOL_SOCKET, SO_SNDTIMEO, (char *) &socket_timeout, sizeof(socket_timeout)) < 0) {
                                    vlog(LOG_ERR, "setsockopt failed");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                            }
                            vlog(LOG_INFO,"Successfully set up %d connection channels", info.channel_amount);
                            continue;
                        } else if(flag_var == FRAME_LAST_WRITTEN_SEQ) {
                            PCS_aux++;
#ifdef DEBUGG
                            vlog(LOG_INFO, "received FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", ntohl(*((uint32_t *)buf)), chan_num);
#endif
                            if(debug_trace) {
                                vlog(LOG_INFO, "received FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", ntohl(*((uint32_t *)buf)), chan_num);
                            }
                            // TODO: no sync here!!?!?!
                            if( ntohl(*((uint32_t *)buf)) > shm_conn_info->write_buf[chan_num].remote_lws) shm_conn_info->write_buf[chan_num].remote_lws = ntohl(*((uint32_t *)buf));
                            continue;
						} else if (flag_var == FRAME_TIME_LAG) {
                            PCS_aux++;
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
                            vlog(LOG_INFO, "recv pid - %i packet_miss - %"PRIu32" tmp_h %"PRIu32"",time_lag_local.pid, miss_packets_max_tmp, tmp_h);
							vlog(LOG_INFO, "Miss packet counter was - %"PRIu32" recv - %"PRIu32"",shm_conn_info->miss_packets_max_recv_counter, miss_packets_max_recv_counter);
#endif
                            if ((miss_packets_max_recv_counter > shm_conn_info->miss_packets_max_recv_counter)) {
                                miss_packets_max = miss_packets_max_tmp;
                                shm_conn_info->miss_packets_max = miss_packets_max;
                                shm_conn_info->miss_packets_max_recv_counter = miss_packets_max_recv_counter;
#ifdef DEBUGG
                                vlog(LOG_INFO, "Miss packets(buf_len) for counter %u is %u apply", miss_packets_max_recv_counter, miss_packets_max_tmp);
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
                                vlog(LOG_INFO, "Time lag for pid: %i is %u", time_lag_local.pid, time_lag_local.time_lag);
                            }

							time_lag_local.time_lag = shm_conn_info->stats[info.process_num].time_lag;
							time_lag_local.pid = shm_conn_info->stats[info.process_num].pid;
							sem_post(&(shm_conn_info->stats_sem));
							continue;
                        } else if (flag_var == FRAME_DEAD_CHANNEL) {
                            PCS_aux++;
                            uint32_t chan_mask_h;
                            memcpy(&chan_mask_h, buf, sizeof(uint32_t));
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            shm_conn_info->channels_mask = ntohl(chan_mask_h);
                            sem_post(&(shm_conn_info->AG_flags_sem));
                        } else if ((flag_var == FRAME_LOSS_INFO) || (flag_var == FRAME_L_LOSS_INFO)) {
                            int psl;
                            uint32_t tmp_h;
                            struct timeval tv_tmp;
                            memcpy(&tmp_h, buf, sizeof(uint32_t));
                            int idx = ntohl(tmp_h);
                            //vlog(LOG_INFO, "FRAME_LOSS_INFO recv idx %d", idx);
                            memcpy(&tmp_h, buf + sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint32_t));
                            tv_tmp.tv_sec = ntohl(tmp_h);
                            memcpy(&tmp_h, buf + sizeof(uint16_t) + 2 * sizeof(uint32_t), sizeof(uint32_t));
                            tv_tmp.tv_usec = ntohl(tmp_h);
                            memcpy(&tmp_h, buf + sizeof(uint16_t) + 3 * sizeof(uint32_t), sizeof(uint32_t));
                            if (flag_var == FRAME_LOSS_INFO) {
                                psl = ntohl(tmp_h);
                            } else {
                                psl = ntohl(tmp_h);
                            }

                            memcpy(&tmp_h, buf + sizeof(uint16_t) + 4 * sizeof(uint32_t), sizeof(uint32_t));
                            if (flag_var == FRAME_LOSS_INFO) {
                                memcpy(&tmp_h, buf + sizeof(uint16_t) + 5 * sizeof(uint32_t), sizeof(uint32_t));
                                uint32_t sqn = ntohl(tmp_h);
                                uint16_t tmp_s;
                                memcpy(&tmp_s, buf + sizeof(uint16_t) + 6 * sizeof(uint32_t), sizeof(uint16_t));
                                int hsnum = (int)ntohs(tmp_s);
                                int who_lost = -1;
                                if(hsnum == -1) {
                                    vlog(LOG_INFO, "WARNING could not detect who lost %lu - sending unconditionally", sqn);
                                } else {
                                    who_lost = hsnum2pnum(hsnum);
                                }
                                //if((psl <= 2) && (who_lost != shm_conn_info->max_chan)) { // this is for fairness model #407
                                struct timeval cwr_diff;
                                timersub(&info.current_time, &shm_conn_info->cwr_tv, &cwr_diff);
                                
                            } else {
                                memcpy(&tmp_h, buf + sizeof(uint16_t) + 6 * sizeof(uint32_t), sizeof(uint32_t));
                                uint32_t sqn = ntohl(tmp_h);
                                uint16_t tmp16_n;
                                memcpy(&tmp16_n, buf + sizeof(uint16_t) + 5 * sizeof(uint32_t), sizeof(uint16_t));
                                uint16_t tmp = ntohs(tmp16_n);
                                char char_tmp[3] = { 0 };
                                memcpy(char_tmp, &tmp, sizeof(uint16_t));
                                memcpy(&tmp_s, buf + sizeof(uint16_t) + 7 * sizeof(uint32_t), sizeof(uint16_t));
                                int hsnum = (int)ntohs(tmp_s);
                                int who_lost = -1;
                                if(hsnum == -1) {
                                    vlog(LOG_INFO, "WARNING could not detect who lost %lu - not resending", sqn);
                                } else {
                                    who_lost = hsnum2pnum(hsnum);
                                    if(who_lost == -1) {
                                        vlog(LOG_ERR, "WARNING could not resolve who lost %lu - not resending", sqn);
                                    }
                                }
                                if(who_lost == info.process_num) {
                                    info.psl_count += psl;
                                    info.loss_event_count++;
                                }
                                sem_wait(&(shm_conn_info->stats_sem));
                                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                    if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead)) { // hope this works..
                                        if (strncmp(shm_conn_info->stats[i].name + strlen(shm_conn_info->stats[i].name) - 2, char_tmp, 2) == 0) {
                                            if((shm_conn_info->stats[i].l_pbl_recv != ntohl(tmp_h)) && (timercmp(&shm_conn_info->stats[i].plp_immune, &info.current_time, <=)) 
                                                && ((shm_conn_info->stats[info.process_num].exact_rtt < 800) || (i == info.process_num))) {
                                                    ms2tv(&loss_tv, shm_conn_info->stats[i].exact_rtt);
                                                    timeradd(&info.current_time, &loss_tv, &shm_conn_info->stats[i].plp_immune);
                                                    // TODO: this is totally unsynced and may introduce problems
                                                    shm_conn_info->stats[i].l_pbl_recv_saved = shm_conn_info->stats[i].l_pbl_recv;
                                                    shm_conn_info->stats[i].l_pbl_tmp_saved = shm_conn_info->stats[i].l_pbl_tmp;
                                                    // TODO: because of PLP restore procedure it may rewrite itself again - see FCI handler
                                                
                                                shm_conn_info->stats[i].l_pbl_recv = ntohl(tmp_h);
                                                shm_conn_info->stats[i].l_pbl_tmp = 0; // WARNING it may collide here!
                                                if(psl > PSL_RECOVERABLE && shm_conn_info->stats[i].l_pbl_recv > L_PBL_JOIN_EVENTS && shm_conn_info->stats[i].l_pbl_tmp_unrec > L_PBL_JOIN_EVENTS) {
                                                    // unrecoverable loss
                                                    if(shm_conn_info->stats[i].l_pbl_unrec_avg < INT32_MAX / PBL_SMOOTH_NUMERATOR) {
                                                        shm_conn_info->stats[i].l_pbl_unrec_avg = PBL_SMOOTH_NUMERATOR * shm_conn_info->stats[i].l_pbl_unrec_avg / PBL_SMOOTH_DENOMINATOR + shm_conn_info->stats[i].l_pbl_tmp_unrec / PBL_SMOOTH_DENOMINATOR;
                                                    } else {
                                                        shm_conn_info->stats[i].l_pbl_unrec_avg = INT32_MAX;
                                                    }
                                                    shm_conn_info->stats[i].l_pbl_tmp_unrec = 0;
                                                }
                                            }
                                            break;
                                        }

                                    }
                                }
                                sem_post(&(shm_conn_info->stats_sem));
                                if( psl <= UNRECOVERABLE_LOSS && who_lost > -1 && !shm_conn_info->is_single_channel) {
                                    if(info.min_rtt_chan == info.process_num) {
                                        // now do retransmit
                                        int mypid;
                                        uint32_t seqn;
                                        int cnt = 0;
                                        for(uint32_t sqn_s = sqn; sqn_s < sqn + psl; sqn_s++) {
                                            if(cnt > UNRECOVERABLE_LOSS) {
                                                vlog(LOG_ERR, "ASSERT FAILED!: looping at resend packet > UNRECOVERABLE_LOSS! sqn %lu sqn_s %lu psl %d", sqn, sqn_s, psl);
                                                break;
                                            }
                                            cnt++;
                                            sem_wait(&(shm_conn_info->resend_buf_sem));
                                            int lidx = -1;
                                            len = get_resend_frame_local_sqn(1, who_lost ,sqn_s, &seqn, &out2, &mypid, &lidx);
                                            if (len == -1) {
                                                vlog(LOG_INFO, "WARNING could not retransmit packet 2 %lu - not found", sqn_s);
                                                sem_post(&(shm_conn_info->resend_buf_sem));
                                            } else {
                                                memcpy(out_buf, out2, len);
                                                sem_post(&(shm_conn_info->resend_buf_sem));
                                                vlog(LOG_INFO, "resending packet 2 lsn %lu sqn %lu len %d", sqn_s, seqn, len);
                                                send_packet(1, out_buf, len);
                                                shm_conn_info->resend_frames_buf[lidx].local_seq_num[info.process_num] = info.channel[1].local_seq_num - 1; // in case it will be lost again
                                            }
                                        }
                                    }
                                }
                            }
                            
                            
                            continue;
                        } else if (flag_var == FRAME_CHANNEL_INFO) {
                            PCS_aux++;
                            uint32_t tmp32_n;
                            uint16_t tmp16_n;
                            int chan_num2;
                            memcpy(&tmp16_n, buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint16_t));
                            chan_num2 = (int)ntohs(tmp16_n);
                            if(chan_num2 >= 100) {
                                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                    shm_conn_info->stats[i].remote_head_channel = 0;
                                }
                                shm_conn_info->stats[info.process_num].remote_head_channel = 1;
                                if(chan_num2 >= 200) {
                                    shm_conn_info->last_head = info.current_time;
                                }
                                shm_conn_info->remote_head_pnum = info.process_num;
                            }
                            gettimeofday(&info.current_time, NULL);
                            memcpy(&info.channel[chan_num].send_q_time, &info.current_time, sizeof(struct timeval));
                            memcpy(&tmp16_n, buf, sizeof(uint16_t));
                            info.channel[chan_num].packet_recv = ntohs(tmp16_n); // unused 
                            memcpy(&tmp16_n, buf + sizeof(uint16_t), sizeof(uint16_t));
                            info.channel[chan_num].packet_loss = ntohs(tmp16_n); // FCI-only data only on loss
                            memcpy(&tmp32_n, buf + 3 * sizeof(uint16_t), sizeof(uint32_t));
                            info.channel[chan_num].packet_seq_num_acked = ntohl(tmp32_n); // each packet data here
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), sizeof(uint32_t)); // PCS send
                            info.PCS2_recv = ntohl(tmp32_n);
                            //vlog(LOG_ERR, "local seq %"PRIu32" recv seq %"PRIu32" chan_num %d ",info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked, chan_num);
                            // rtt calculation, TODO: DUP code below!
                            if( (info.rtt2_lsn[chan_num] != 0) && (info.channel[chan_num].packet_seq_num_acked > info.rtt2_lsn[chan_num])) {
                                //vlog(LOG_INFO,"WARNING! rtt2 calculated via FCI receive event!");
                                timersub(&info.current_time, &info.rtt2_tv[chan_num], &tv_tmp);
                                //info.rtt2 = tv2ms(&tv_tmp);
                                info.rtt2_lsn[chan_num] = 0;
                                info.srtt2_10 += ((int)tv2ms(&tv_tmp)*10 - info.srtt2_10) / 8;
                                info.srtt2_100 += ((int)tv2ms(&tv_tmp)*100 - info.srtt2_100) / 50;
                                info.rtt2 = info.srtt2_10 / 10; // check this!
                                if (info.rtt2 <= 0) info.rtt2 = 1;
                                int r_delta = (int)tv2ms(&tv_tmp) - info.srtt2_10 / 10;
                                if(r_delta > 0) {
                                    info.srtt2var = (3 * info.srtt2var  +  r_delta)/4;
                                } else {
                                    info.srtt2var = (3 * info.srtt2var  -  r_delta)/4;
                                }
                            }
                            
                            
                            memcpy(&tmp32_n, buf + 5 * sizeof(uint16_t) + 3 * sizeof(uint32_t), sizeof(uint32_t)); //ag_flag
                            shm_conn_info->ag_mask_recv = hsag_mask2ag_mask(ntohl(tmp32_n));
                            // we have received new mask
                            shm_conn_info->stats[info.process_num].agoff_immunity_tv.tv_sec = 0;
                            shm_conn_info->stats[info.process_num].agoff_immunity_tv.tv_usec = 0;
                            if(shm_conn_info->stats[info.process_num].recv_mode != (shm_conn_info->ag_mask_recv & (1 << info.process_num))) {
                                shm_conn_info->stats[info.process_num].recv_mode = (shm_conn_info->ag_mask_recv & (1 << info.process_num)) ? 1 : 0;
                            }
                            // TODO: check WTF is here ^^^vvv ???
                            for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                if( (i != info.process_num) && (shm_conn_info->stats[i].recv_mode != (shm_conn_info->ag_mask_recv & (1 << i))) ) { 
                                    // we are setting new mode for another channel
                                    if(shm_conn_info->stats[i].recv_mode == 1) { // AG_MODE -> R_MODE: set immunity timer
                                        struct timeval tv_dt;
                                        ms2tv(&tv_dt, shm_conn_info->stats[i].exact_rtt);
                                        timeradd(&info.current_time, &tv_dt, &shm_conn_info->stats[i].agoff_immunity_tv);
                                    }
                                    shm_conn_info->stats[i].recv_mode = (shm_conn_info->ag_mask_recv & (1 << i)) ? 1 : 0;
                                }
                            }
                                    
                            set_rttlag();
                            memcpy(&tmp16_n, buf + 5 * sizeof(uint16_t) + 4 * sizeof(uint32_t), sizeof(uint16_t)); // sqe_mean
                            shm_conn_info->stats[info.process_num].remote_sqe_mean_pkt = ntohs(tmp16_n);
                            
                            memcpy(&tmp16_n, buf + 6 * sizeof(uint16_t) + 4 * sizeof(uint32_t), sizeof(uint16_t)); //buf_len
                            int buf_len_recv = (int)ntohs(tmp16_n);
                            
                            memcpy(&tmp16_n, buf + 7 * sizeof(uint16_t) + 4 * sizeof(uint32_t), sizeof(uint16_t)); 
                            shm_conn_info->msbl_recv = ntohs(tmp16_n);
                            memcpy(&tmp32_n, buf + 8 * sizeof(uint16_t) + 4 * sizeof(uint32_t), sizeof(uint32_t)); 
                            shm_conn_info->stats[info.process_num].la_sqn = ntohl(tmp32_n);
                            memcpy(&tmp32_n, buf + 8 * sizeof(uint16_t) + 5 * sizeof(uint32_t), sizeof(uint32_t)); 
                            uint32_t remote_seq = ntohl(tmp32_n);
                            // vlog(LOG_ERR, "FRAME_CHANNEL_INFO testing lasqn %ld > %ld ", remote_seq, shm_conn_info->latest_la_sqn);
                            
                            if(remote_seq > shm_conn_info->latest_la_sqn) {
                                memcpy(&tmp16_n, buf + 4 * sizeof(uint16_t) + 3 * sizeof(uint32_t), sizeof(uint16_t)); // hsqs
                                shm_conn_info->head_send_q_shift_recv = (int16_t) ntohs(tmp16_n); // TODO parse hsqs here
                                shm_conn_info->buf_len_recv = buf_len_recv;
                                vlog(LOG_INFO, "Setting hsqs %d", (int16_t) ntohs(tmp16_n));
                                shm_conn_info->latest_la_sqn = remote_seq; 
                            }
                            
                            // now recalculate MAR is possible...
                            info.channel[chan_num].send_q =
                                    info.channel[chan_num].local_seq_num > info.channel[chan_num].packet_seq_num_acked ?
                                            1000 * (info.channel[chan_num].local_seq_num - info.channel[chan_num].packet_seq_num_acked) : 0;
                            //if (info.max_send_q < info.channel[chan_num].send_q) {
                            //    info.max_send_q = info.channel[chan_num].send_q;
                            //}
                            //vlog(LOG_INFO, "FCI send_q %d", info.channel[chan_num].send_q);
                            //if (info.channel[chan_num].send_q > 90000)
                            //    vlog(LOG_INFO, "channel %d mad_send_q %"PRIu32" local_seq_num %"PRIu32" packet_seq_num_acked %"PRIu32"",chan_num, info.channel[chan_num].send_q,info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked);

                            if(debug_trace) {
                                vlog(LOG_INFO, "FCI local seq %"PRIu32" recv seq %"PRIu32" chan_num %d ",info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked, chan_num);
                            }
                            //vlog(LOG_INFO, "FRAME_CHANNEL_INFO: Calculated send_q: %d, chan %d, pkt %d, drops: %d", info.channel[chan_num].send_q, chan_num, info.channel[chan_num].packet_seq_num_acked, drop_counter);
                            uint32_t my_max_send_q = 0;
                            for (int i = 1; i < info.channel_amount; i++) {
                                if (my_max_send_q < info.channel[i].send_q) {
                                    my_max_send_q = info.channel[i].send_q;
                                    my_max_send_q_chan_num = i;
                                }
                            }
                            if ((info.channel[chan_num].packet_loss == -1) && (info.Wmax_saved != 0)) { 
                                vlog(LOG_INFO, "Undoing congestion control: Wmax %d", info.Wmax_saved);
                                info.send_q_limit_cubic_max = info.Wmax_saved;
                                loss_time = info.Wmax_tv;
                                info.Wmax_saved = 0;
                            } else if ((info.channel[chan_num].packet_loss == -1) && (info.Wmax_saved == 0)) {
                                vlog(LOG_INFO, "Cannot undo congestion: Wmax %d", info.Wmax_saved);
                            }
                            
                            if((info.channel[chan_num].packet_loss == -1) && (shm_conn_info->stats[info.process_num].l_pbl_tmp_saved != 0)) {
                                vlog(LOG_INFO, "Undoing PLP drop: l_pbl_recv %d", shm_conn_info->stats[info.process_num].l_pbl_recv_saved);
                                // TODO: unsynced
                                shm_conn_info->stats[info.process_num].l_pbl_recv = shm_conn_info->stats[info.process_num].l_pbl_recv_saved;
                                shm_conn_info->stats[info.process_num].l_pbl_tmp = shm_conn_info->stats[info.process_num].l_pbl_tmp_saved; 
                                ms2tv(&loss_tv, 1100); // TODO: a very dumb channel may fail this
                                timeradd(&info.current_time, &loss_tv, &shm_conn_info->stats[info.process_num].plp_immune);
                                shm_conn_info->stats[info.process_num].l_pbl_tmp_saved = 0;
                            } else if ((info.channel[chan_num].packet_loss == -1) && (shm_conn_info->stats[info.process_num].l_pbl_tmp_saved == 0)) {
                                vlog(LOG_INFO, "Cannot undo PLP drop: l_pbl_recv %d", shm_conn_info->stats[info.process_num].l_pbl_recv_saved);
                            }
                                
                                
                            
                            //Для чего нужен подсчет значения потерь через info.channel[chan_num].packet_loss ( возможно ложное срабатывание в дальнейшем
                            if (info.channel[chan_num].packet_loss > 0 && timercmp(&loss_immune, &info.current_time, <=)) { // 2 pkts loss THR is prep for loss recovery
                                // TODO: need to get L_PBL somehow here - see dumbass method at FCI send
                                vlog(LOG_INFO, "RECEIVED approved loss %"PRId16" chan_num %d send_q %"PRIu32"", info.channel[chan_num].packet_loss, chan_num,
                                        info.channel[chan_num].send_q);
                                loss_time = info.current_time; // received loss event time
                                info.p_lost++;
                                sem_wait(&(shm_conn_info->stats_sem));
                                shm_conn_info->stats[info.process_num].real_loss_time = info.current_time; // received loss event time
                                if(info.head_channel) {
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
                                                vlog(LOG_INFO, "Head changed to %d due to ACS>ACSh: %d > %d", ch_max_ACS_ch, ch_max_ACS, shm_conn_info->stats[info.process_num].ACK_speed);
                                                shm_conn_info->max_chan = ch_max_ACS_ch; // we found chan with better ACS (10% corridor)
                                            } else if ( percent_delta_equal(shm_conn_info->stats[info.process_num].ACK_speed, ch_max_ACS, 10)
                                                    && (ch_max_ACS_W > shm_conn_info->stats[info.process_num].W_cubic)) {
                                                // check Wh/Wi here
                                                // our process has smaller window with same speed; assume we're not the best now
                                                vlog(LOG_INFO, "Head changed to %d due to W>Wh: %d > %d", ch_max_ACS_ch, ch_max_ACS_W, shm_conn_info->stats[info.process_num].W_cubic);
                                                shm_conn_info->max_chan = ch_max_ACS_ch;
                                            } else {
                                                vlog(LOG_INFO, "Head (real) lossing after idle");
                                                shm_conn_info->idle = 0;
                                                shm_conn_info->head_lossing = 1;
                                            }
                                        } else {
                                            // we are the ONLY channel, drop flags
                                            vlog(LOG_INFO, "Head (only) lossing after idle");
                                            shm_conn_info->idle = 0;
                                            shm_conn_info->head_lossing = 1;
                                        }
                                    } else {
                                       // vlog(LOG_INFO, "Head lossing");
                                        shm_conn_info->head_lossing = 1;
                                    }
                                }
                                sem_post(&(shm_conn_info->stats_sem));
                                ms2tv(&loss_tv, info.exact_rtt);
                                timeradd(&info.current_time, &loss_tv, &loss_immune);
                                if(0 && info.head_channel) {
                                    info.send_q_limit_cubic_max = info.max_send_q; // fast-converge to flow (head now always converges!)
                                    info.W_u_max = info.max_send_q_u;
                                    info.cubic_t_max_u = t_from_W(RSR_TOP, info.W_u_max, info.Bu, info.Cu);
                                } else {
                                    //if (info.channel[my_max_send_q_chan_num].send_q >= info.send_q_limit_cubic_max) {
                                    if (!info.xlm && info.max_send_q >= info.send_q_limit_cubic_max) {
                                    // if (send_q_eff_mean + send_q_eff_var/2 >= info.send_q_limit_cubic_max) {
                                        info.Wmax_saved = info.send_q_limit_cubic_max;
                                        info.Wmax_tv = loss_time;
                                        //info.send_q_limit_cubic_max = info.channel[my_max_send_q_chan_num].send_q;
                                        // if(info.max_send_q > info.send_q_limit_cubic) {
                                            info.send_q_limit_cubic_max = info.max_send_q;
                                            // info.send_q_limit_cubic_max = send_q_eff_mean + send_q_eff_var/2;
                                        // } else {
                                        //     info.send_q_limit_cubic_max = info.send_q_limit_cubic;
                                        // }
                                        if(info.channel[chan_num].packet_loss > PSL_RECOVERABLE) {
                                            info.W_u_max = info.max_send_q_u;
                                            info.cubic_t_max_u = t_from_W(RSR_TOP, info.W_u_max, info.Bu, info.Cu);
                                        }
                                    } else {
                                        //info.send_q_limit_cubic_max = (int) ((double)info.channel[my_max_send_q_chan_num].send_q * (2.0 - info.B) / 2.0);
                                        // if(info.max_send_q > info.send_q_limit_cubic) {
                                            if(info.xlm) {
                                                info.send_q_limit_cubic_max = info.max_send_q / 2;
                                            } else {
                                                info.send_q_limit_cubic_max = (int) ((double)info.max_send_q * (2.0 - info.B) / 2.0);
                                            }
                                            // info.send_q_limit_cubic_max = (int) ((double)send_q_eff_var * (2.0 - info.B) / 2.0);
                                        // } else {
                                        //     info.send_q_limit_cubic_max = (int) ((double)info.send_q_limit_cubic * (2.0 - info.B) / 2.0);
                                        // }
                                        if(info.channel[chan_num].packet_loss > PSL_RECOVERABLE) {
                                            info.W_u_max = (int) ((double)info.max_send_q_u * (2.0 - info.Bu) / 2.0);
                                            info.cubic_t_max_u = t_from_W(RSR_TOP, info.W_u_max, info.Bu, info.Cu);
                                        }
                                    }
                                }
                                if(info.send_q_limit_cubic_max / info.eff_len < LOSS_SEND_Q_MAX) {
                                    //shm_conn_info->stats[info.process_num].loss_send_q = info.send_q_limit_cubic_max / info.eff_len; // packets in network at loss
                                    shm_conn_info->stats[info.process_num].loss_send_q = shm_conn_info->stats[info.process_num].sqe_mean_lossq / info.eff_len; // SQE expreiment
                                } else {
                                    shm_conn_info->stats[info.process_num].loss_send_q = LOSS_SEND_Q_MAX;
                                } 
                                // now set all the chans that have undefined loss_send_q
                                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                    if ((chan_mask & (1 << i)) && (!shm_conn_info->stats[i].channel_dead) &&
                                        (shm_conn_info->stats[i].loss_send_q == LOSS_SEND_Q_UNKNOWN)) {
                                            shm_conn_info->stats[i].loss_send_q = shm_conn_info->stats[info.process_num].loss_send_q;
                                    }
                                }
                                            
                                // t = 0;
                                // info.max_send_q = 0;
                                // //waste Cubic recalc
                                // sem_wait(&(shm_conn_info->stats_sem));
                                // set_W_unsync(t);
                                // sem_post(&(shm_conn_info->stats_sem));
                                if(info.channel[chan_num].packet_loss > PSL_RECOVERABLE) {
                                    info.u_loss_tv = info.current_time;
                                    info.max_send_q_u = 0;
                                    shm_conn_info->stats[info.process_num].W_cubic_u = cubic_recalculate(0, info.W_u_max, info.Bu, info.Cu);
                                }
                                    
                                //waste Cubic recalc end
                            } else {
                                timersub(&(info.current_time), &loss_time, &t_tv);
                                t = t_tv.tv_sec * 1000 + t_tv.tv_usec / 1000;
                                t = t / CUBIC_T_DIV;
                                t = t > cubic_t_max ? cubic_t_max : t; // 200s limit
                            }
                            
                            info.max_send_q_avg = (uint32_t) ((int32_t) info.max_send_q_avg  // unused
                                    - ((int32_t) info.max_send_q_avg - (int32_t) my_max_send_q) / 4);

#if !defined(DEBUGG)
                            info.max_send_q_max = my_max_send_q > info.max_send_q_max ? my_max_send_q : info.max_send_q_max;
                            info.max_send_q_min = my_max_send_q < info.max_send_q_min ? my_max_send_q : info.max_send_q_min;
#endif
                            // local seq_num
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint32_t));
                            uint32_t local_seq_tmp = ntohl(tmp32_n); 
                            
                            unsigned int lrs2;
                            if (lossed_consume(local_seq_tmp, 0, &lrs2, &info.channel[chan_num].local_seq_num_recv) == 0) { // TODO: lrs?? not updated!
                                info.channel[chan_num].loss_time = info.current_time;
                            }
                            info.channel[1].last_recv_time = info.current_time;
                            
                            //if (local_seq_tmp > info.channel[chan_num].local_seq_num_recv) {
                            //    info.channel[chan_num].local_seq_num_recv = local_seq_tmp;
                            //}
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
                                vlog(LOG_INFO, "channel %d speed %"PRIu32" Speed_avg %"PRIu32"",chan_num, info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);
                            }
#endif
                            //vlog(LOG_INFO, "FCI spd %d %d", info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);
                            sem_wait(&(shm_conn_info->stats_sem));
                            /* store in shm */
                            // set_W_unsync(t); // not required to recalculate here; will be more predictable
                            shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].send_q_loss = info.channel[chan_num].send_q; // never ever used!! TODO remove
                            //if (my_max_send_q < info.rsr) {
                            //    drop_packet_flag = 0;
                            //}
                            shm_conn_info->stats[info.process_num].my_max_send_q_chan_num = my_max_send_q_chan_num;
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
                            vlog(LOG_INFO,
                                    "FRAME_CHANNEL_INFO recv chan_num %d send_q %"PRIu32" packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" recv upload %"PRIu32" send_q %"PRIu32"",
                                    chan_num, info.channel[chan_num].send_q, info.channel[chan_num].packet_recv, (int16_t)info.channel[chan_num].packet_loss,
                                    info.channel[chan_num].packet_seq_num_acked, info.channel[chan_num].packet_recv_period, info.channel[chan_num].packet_recv_upload, info.channel[chan_num].send_q);
#endif

                            if (info.channel[chan_num].packet_loss != 0) {
                                fire_event(&my_events->loss);
                            }
                            continue;
                        } else {
							vlog(LOG_ERR, "WARNING! unknown frame mode received: %du, real flag - %u!", (unsigned int) flag_var, ntohs(*((uint16_t *)(buf+(sizeof(uint32_t)))))) ;
					}
                        vlog(LOG_ERR, "Cannot resend frame %"PRIu32"; chan %d coz remomed api", ntohl(*((uint32_t *)buf)), chan_num);
                        continue;

                    } // bad frame end
        CHKCPU(14);
                    if( fl==VTUN_ECHO_REQ ) {
                        PCS_aux++;
                        /* Send ECHO reply */
                        if(!select_net_write(chan_num)) {
                            vlog(LOG_ERR, "Could not send echo reply due to net not selecting");
                            continue;
                        }
                        last_net_read_ds = get_ds_ts(info.current_time); 
                        if(debug_trace) {
                            vlog(LOG_INFO, "sending PONG...");
                        }
                        int len_ret;
                        if (chan_num == 0) {
                            len_ret = proto_write(info.channel[chan_num].descriptor, buf, VTUN_ECHO_REP);
                        } else {
                            // send pong reply
                            len_ret = udp_write(info.channel[chan_num].descriptor, buf, VTUN_ECHO_REP);
                        }
                        if ( len_ret < 0) {
                            vlog(LOG_ERR, "Could not send echo reply");
                            linker_term = TERM_NONFATAL;
                            break;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_data_len_amt += len_ret;
                        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                        info.channel[chan_num].up_len += len_ret;
                        continue;
                    }
                    if( fl==VTUN_ECHO_REP ) {
                        PCS_aux++;
                        /* Just ignore ECHO reply */
                        if(debug_trace) {
                            vlog(LOG_INFO, "... was echo reply");
                        }
                        
                        if(chan_num == 0) ping_rcvd = 1;
                        last_net_read_ds = get_ds_ts(info.current_time); 
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
                        vlog(LOG_INFO,"Connection close requested by other side daemon");
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                } else {
                    
        CHKCPU(15);
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
                    shm_conn_info->stats[info.process_num].pbl_lossed_cnt++;
                    last_net_read_ds = get_ds_ts(info.current_time); 
                    statb.bytes_rcvd_norm+=len;
                    statb.bytes_rcvd_chan[chan_num] += len;
                    out = buf; // wtf?
                    uint32_t local_seq_tmp;
                    uint16_t mini_sum;
                    uint32_t last_recv_lsn;
                    uint32_t packet_recv_spd;
                    flag_var = 0;
                    CHKCPU(2);
                    len = seqn_break_tail(out, len, &seq_num, &flag_var, &local_seq_tmp, &mini_sum, &last_recv_lsn, &packet_recv_spd);
#ifdef CODE_LOG
                    vlog(LOG_INFO, "PKT local seq num %"PRIu32" seq_num %"PRIu32"", local_seq_tmp, seq_num);
#endif
                    // rtt calculation
                    if( (info.rtt2_lsn[chan_num] != 0) && (last_recv_lsn > info.rtt2_lsn[chan_num])) {
                        timersub(&info.current_time, &info.rtt2_tv[chan_num], &tv_tmp);
                        //info.rtt2 = tv2ms(&tv_tmp);
                        info.rtt2_lsn[chan_num] = 0;
                        info.srtt2_10 += ((int)tv2ms(&tv_tmp)*10 - info.srtt2_10) / 8;
                        info.srtt2_100 += ((int)tv2ms(&tv_tmp)*100 - info.srtt2_100) / 50;
                        info.rtt2 = info.srtt2_10 / 10; // check this!
                        if (info.rtt2 <= 0) info.rtt2 = 1;
                        int r_delta = (int)tv2ms(&tv_tmp) - info.srtt2_10 / 10;
                        if(r_delta > 0) {
                            info.srtt2var = (3 * info.srtt2var  +  r_delta)/4;
                        } else {
                            info.srtt2var = (3 * info.srtt2var  -  r_delta)/4;
                        }
                    }

                    // if ((start_of_train != 0) && (chan_num == 1)) {

                    //     if (last_recv_lsn >= end_of_train) {
                    //         uint32_t packet_lag = last_recv_lsn - start_of_train;
                    //         start_of_train = 0;
                    //         //if(packet_lag > (TRAIN_PKTS + TRAIN_PKTS/2)) {
                    //         //    vlog(LOG_ERR, "WARNING Train calc wrong! packet_lag %d need train restart ASAP", packet_lag);
                    //         //    sem_wait(&(shm_conn_info->common_sem));
                    //         //    shm_conn_info->last_flood_sent.tv_sec = 0;
                    //         //    sem_post(&(shm_conn_info->common_sem));
                    //         //} else {
                    //             timersub(&info.current_time, &flood_start_time, &info.bdp1);
                    //         //}

                    //         // Now set max_chan -->
                    //         // sem_wait(&(shm_conn_info->AG_flags_sem));
                    //         uint32_t chan_mask = shm_conn_info->channels_mask;
                    //         shm_conn_info->stats[info.process_num].bdp1 = info.bdp1;
                    //         // sem_post(&(shm_conn_info->AG_flags_sem));
                    //         sem_wait(&(shm_conn_info->stats_sem));
                    //         //shm_conn_info->bdp1[info.process_num] = info.bdp1;
                    //         // now find max_chan
                    //         set_max_chan(chan_mask);
                    //         sem_post(&(shm_conn_info->stats_sem));
                    //         // <-- end max_chan set
                            
                    //         vlog(LOG_INFO, "%s paket_lag %"PRIu32" bdp %"PRIu32"%"PRIu32"us %"PRIu32"ms",  lfd_host->host, packet_lag, info.bdp1.tv_sec,
                    //                 info.bdp1.tv_usec, tv2ms(&info.bdp1));
                    //     }
                    // }

                    CHKCPU(21);
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
                    //if(info.max_send_q < info.channel[chan_num].send_q) {
                    //    info.max_send_q = info.channel[chan_num].send_q;
                    //}

#ifdef DEBUGG
if(drop_packet_flag) {
                    vlog(LOG_INFO, "PKT send_q %d:.local_seq_num=%d, last_recv_lsn=%d", info.channel[chan_num].send_q, info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked);
}
#endif
              //      vlog(LOG_INFO, "PKT send_q %d", info.channel[chan_num].send_q);
                    // the following is to calculate my_max_send_q_chan_num only
                    uint32_t my_max_send_q = 0;
                    for (int i = 1; i < info.channel_amount; i++) {
                        if (my_max_send_q < info.channel[i].send_q) {
                            my_max_send_q = info.channel[i].send_q;
                            my_max_send_q_chan_num = i;
                        }
                    }
                    CHKCPU(26);

                    // ACS
                    info.channel[chan_num].packet_recv_upload = packet_recv_spd; // each packet data
                    info.channel[chan_num].packet_recv_upload_avg =
                            info.channel[chan_num].packet_recv_upload > info.channel[chan_num].packet_recv_upload_avg ?
                                    (info.channel[chan_num].packet_recv_upload - info.channel[chan_num].packet_recv_upload_avg) / 4
                                            + info.channel[chan_num].packet_recv_upload_avg :
                                    info.channel[chan_num].packet_recv_upload_avg
                                            - (info.channel[chan_num].packet_recv_upload_avg - info.channel[chan_num].packet_recv_upload) / 4;

                    sem_wait(&(shm_conn_info->stats_sem)); // critical_sem
                    if (my_max_send_q_chan_num == chan_num) {
                        //shm_conn_info->stats[info.process_num].ACK_speed = info.channel[chan_num].packet_recv_upload_avg == 0 ? 1 : info.channel[chan_num].packet_recv_upload_avg;
                        info.packet_recv_upload_avg = shm_conn_info->stats[info.process_num].ACK_speed;
                    }
                    shm_conn_info->stats[info.process_num].max_send_q = my_max_send_q;
                    shm_conn_info->stats[info.process_num].rtt2 = info.rtt2; // TODO: do this copy only if RTT2 recalculated (does not happen each frame)
                    shm_conn_info->stats[info.process_num].srtt2_10 = info.srtt2_10; // TODO: do this copy only if RTT2 recalculated (does not happen each frame)
                    shm_conn_info->stats[info.process_num].srtt2_100 = info.srtt2_100; // TODO: do this copy only if RTT2 recalculated (does not happen each frame)
                    sem_post(&(shm_conn_info->stats_sem)); // critical_sem

                    //vlog(LOG_INFO, "PKT spd %d %d", info.channel[chan_num].packet_recv_upload, info.channel[chan_num].packet_recv_upload_avg);

                    /* Accumulate loss packet*/
                    uint16_t mini_sum_check = (uint16_t)(seq_num + local_seq_tmp + last_recv_lsn);
                    
                    if(mini_sum != mini_sum_check) { // TODO: remove!
                        vlog(LOG_ERR, "PACKET CHECKSUM ERROR chan %d, seq_num %lu, %"PRId16" != %"PRId16"", chan_num, seq_num, ntohs(mini_sum), mini_sum_check);
                        continue;
                    }
                    
                    CHKCPU(27);
                    // this is loss detection -->
                    if(shm_conn_info->seq_num_unrecoverable_loss == 0 && seq_num != 0) { 
                            // prevent unrecoverable loss from being set to 0 by lossed_consume
                        vlog(LOG_ERR, "WARNING! detected unrecoverable loss of 0 packets, fixing to seq %ld", seq_num);
                        shm_conn_info->seq_num_unrecoverable_loss = seq_num;
                    }
                    unsigned int lrs;
                    if(lossed_consume(local_seq_tmp, seq_num, &lrs, &info.channel[chan_num].local_seq_num_recv) == 0) {
                        info.channel[chan_num].loss_time = info.current_time;
                        shm_conn_info->write_buf[chan_num].packet_lost_state[info.process_num] = 0; // no need to sync
                    }
                    sem_wait(write_buf_sem); // critical_sem
                    shm_conn_info->write_buf[chan_num].last_received_seq[info.process_num] = lrs;
                    
                    info.channel[chan_num].packet_recv_counter++;
#ifdef DEBUGG
if(drop_packet_flag) {
                    vlog(LOG_INFO, "Receive frame ... chan %d local seq %"PRIu32" seq_num %"PRIu32" recv counter  %"PRIu16" len %d loss is %"PRId16"", chan_num, info.channel[chan_num].local_seq_num_recv,seq_num, info.channel[chan_num].packet_recv_counter, length, (int16_t)info.channel[chan_num].packet_loss_counter);
}
#endif
                    if(debug_trace) {
                        vlog(LOG_INFO, "Receive frame ... chan %d local seq %"PRIu32" seq_num %"PRIu32" recv counter  %"PRIu16" len %d loss is %"PRId16"", chan_num, info.channel[chan_num].local_seq_num_recv,seq_num, info.channel[chan_num].packet_recv_counter, len, (int16_t)info.channel[chan_num].packet_loss_counter);
                    }
                    CHKCPU(28);
                    // HOLY CRAP! remove this! --->>>
                    // introduced virtual chan_num to be able to process
                    //    congestion-avoided priority resend frames
                    if(chan_num == 0) { // reserved aux channel
                         if(flag_var == 0) { // this is a workaround for some bug... TODO!!
                              vlog(LOG_ERR,"BUG! flag_var == 0 received on chan 0! sqn %"PRIu32", len %d. DROPPING",seq_num, len);
                              sem_post(write_buf_sem); // critical_sem
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
                    CHKCPU(3);

//                    print_head_of_packet(out, "recv packet",seq_num, len);

                    succ_flag = 0;
                    int newPacket = 0;
                    if(shm_conn_info->flushed_packet[seq_num % FLUSHED_PACKET_ARRAY_SIZE] != seq_num){
                        newPacket = 1;
                    }
                    incomplete_seq_len = write_buf_add(chan_num_virt, out, len, seq_num, incomplete_seq_buf, &buf_len, info.pid, &succ_flag);
                    my_miss_packets = buf_len;
                    my_miss_packets_max = my_miss_packets_max < buf_len ? buf_len : my_miss_packets_max;
                    if(succ_flag == -2) statb.pkts_dropped++; // TODO: optimize out to wba
                    if(buf_len == 1) { // to avoid dropping first out-of order packet in sequence
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = info.current_time.tv_sec;
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = info.current_time.tv_usec;
                    }
#ifdef SUM_SEND
                    int sumIndex = get_packet_code(&shm_conn_info->packet_code_recived[chan_num][0], &shm_conn_info->packet_code_bulk_counter, seq_num);
                    if (sumIndex != -1) {
                        if (newPacket) {
                            shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount--;
                        }
#ifdef CODE_LOG
                        vlog(LOG_INFO, "LostAmount %d", shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount);
#endif
                        if (shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount == 1) {
                            uint32_t lostSeq = frame_llist_getLostPacket_byRange(&shm_conn_info->write_buf[chan_num].frames,
                                    &shm_conn_info->wb_just_write_frames[chan_num], shm_conn_info->frames_buf,
                                    &shm_conn_info->packet_code_recived[chan_num][sumIndex]);
#ifdef CODE_LOG
                            vlog(LOG_INFO, "packet after sum Uniq lostSeq %u found", lostSeq);
#endif
                            int packet_index = check_n_repair_packet_code(&shm_conn_info->packet_code_recived[chan_num][0],
                                    &shm_conn_info->wb_just_write_frames[chan_num], &shm_conn_info->write_buf[chan_num].frames,
                                    shm_conn_info->frames_buf, lostSeq);
                            if (packet_index > -1) {
                                shm_conn_info->packet_code_recived[chan_num][sumIndex].lostAmount = 0;
                                if (shm_conn_info->packet_code_recived[chan_num][packet_index].sum[0] != 0x45) {
                                    print_head_of_packet(shm_conn_info->packet_code_recived[chan_num][packet_index].sum, "ASSERT BAD packet after sum repaired ", lostSeq,
                                                                            shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum);
                                } else {
                                    vlog(LOG_INFO, "{\"name\":\"%s\",\"repaired_seq_num\":%"PRIu32", \"place\": 1}", lfd_host->host, lostSeq);
                                    
#ifdef CODE_LOG
                                print_head_of_packet(shm_conn_info->packet_code_recived[chan_num][packet_index].sum, "packet after sum repaired ", lostSeq,
                                        shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum);
#endif
                                }
                                write_buf_add(chan_num, shm_conn_info->packet_code_recived[chan_num][packet_index].sum,
                                        shm_conn_info->packet_code_recived[chan_num][packet_index].len_sum, lostSeq, incomplete_seq_buf, &buf_len,
                                        info.pid, &succ_flag);
                            }
                        }
                    }
#endif
                    struct timeval last_write_time_tmp = shm_conn_info->write_buf[chan_num_virt].last_write_time;
                    int cond_flag = shm_conn_info->write_buf[chan_num_virt].last_written_seq > (last_last_written_seq[chan_num_virt] + lfd_host->FRAME_COUNT_SEND_LWS) ? 1 : 0;
                    if(cond_flag) {
                        if(debug_trace) {
                            vlog(LOG_INFO, "sending FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", shm_conn_info->write_buf[chan_num_virt].last_written_seq, chan_num_virt);
                        }
                        *((uint32_t *)buf) = htonl(shm_conn_info->write_buf[chan_num_virt].last_written_seq);
                        last_last_written_seq[chan_num_virt] = shm_conn_info->write_buf[chan_num_virt].last_written_seq;
                        shm_conn_info->write_buf[chan_num_virt].last_lws_notified = info.current_time.tv_sec;
                    }
                    sem_post(write_buf_sem); // critical_sem
#ifdef DEBUGG
                    gettimeofday(&work_loop2, NULL );
                    vlog(LOG_INFO, "write_buf_add time: %"PRIu32" us", (long int) ((work_loop2.tv_sec - work_loop1.tv_sec) * 1000000 + (work_loop2.tv_usec - work_loop1.tv_usec)));
#endif
                    if(incomplete_seq_len == -1) {
                        vlog(LOG_ERR, "ASSERT FAILED! free write buf assert failed on chan %d", chan_num_virt);
                        buf_len = 100000; // flush the sh*t
                    }

                    CHKCPU(31);
                    if(buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) {
                        vlog(LOG_ERR, "WARNING! MAX_ALLOWED_BUF_LEN reached! Flushing... chan %d", chan_num_virt);
                    }

                    // check for initialization
                    if (!info.just_started_recv) {
                        continue;
                    }

                    // if (FD_ISSET(info.tun_device, &fdset_w)) {
                    //     int write_out_max = buf_len / alive_physical_channels;
                    //     if(write_out_max > WRITE_OUT_MAX) write_out_max = WRITE_OUT_MAX;
                    //     if(write_out_max < 2) write_out_max = 2;
                    //     sem_wait(write_buf_sem); // critical_sem
                    //     for (int i = 0; i < write_out_max; i++) {
                    //         if (!write_buf_check_n_flush(chan_num_virt)) {
                    //             break;
                    //         }
                    //     }
                    //     sem_post(write_buf_sem); // critical_sem
                    // }
                    CHKCPU(32);
                    // send lws(last written sequence number) to remote side
                    if(cond_flag && select_net_write(chan_num_virt)) { // waste select!
                        
                        *((uint16_t *)(buf+sizeof(uint32_t))) = htons(FRAME_LAST_WRITTEN_SEQ);
                        // send LWS - 2
                        int len_ret = udp_write(info.channel[chan_num_virt].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vlog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                            linker_term = TERM_NONFATAL;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num_virt].up_data_len_amt += len_ret;
                        shm_conn_info->stats[info.process_num].packet_upload_cnt++;
                        info.channel[chan_num_virt].up_len += len_ret;
                        // TODO: introduce periodic send via each channel. On channel use stop some of resend_buf will remain locked
                        continue;
                    }

                    CHKCPU(33);
                    lfd_host->stat.byte_in += len; // the counter became completely wrong

                } // end load frame processing

            } // if fd0>0

        // if we could not create logical channels YET. We can't send data from tun to net. Hope to create later...
            if ((info.channel_amount <= 1) || (info.just_started_recv == 0)) { // only service channel available
#ifdef DEBUGG
            vlog(LOG_INFO, "Logical channels have not created. Hope to create later... ");
#endif
            if(timercmp(&tv, &select_tv_copy, ==)) { // means select was an immediate return
                // we either did not connect channels or did not receive FRAME_JUST_STATRTED
                // FJS is sent by TCP, so we should wait a bit and exit if we fail to get it at last
                // fill in all structs for immediate read
                FD_ZERO(&fdset_w);
                FD_ZERO(&fdset);
                pfdset_w = NULL;
                tv.tv_sec = 0;
                tv.tv_usec = 1000; // one ms to wait
                for (i = 0; i < info.channel_amount; i++) {
                    FD_SET(info.channel[i].descriptor, &fdset);
                }
                usleep(20000);
                info.select_immediate++;
                if(info.select_immediate > 1000) { // wait 20 seconds in total, then exit
                    vlog(LOG_ERR, "Timeout waiting for FRAME_JUST_STATRTED or channels to create");
                    linker_term = TERM_NONFATAL;
                    break;
                } else {
                    goto main_select;
                }
            }
            continue;
        }
        /* Pass data from write_buff to TUN device */

        // I suspect write_buf_sem race condition here... double-check!


        CHKCPU(4);
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
        sem_wait(&shm_conn_info->hard_sem); // critical_sem // TODO: REMOVE
        if (ag_flag == R_MODE) {
            // int lim = ((info.rsr < info.send_q_limit_cubic) ? info.rsr : info.send_q_limit_cubic);
            // int n_to_send = (lim - send_q_eff) / 1000;
            // if(n_to_send < 0) {
            //     n_to_send = 0;
            // }
            len = retransmit_send(out2);
        CHKCPU(41);
            if (len == CONTINUE_ERROR) {
#ifdef DEBUGG
                vlog(LOG_INFO, "debug: R_MODE continue err");
#endif
                len = 0;
            } else if (len == BREAK_ERROR) {
                vlog(LOG_INFO, "retransmit_send() BREAK_ERROR");
                linker_term = TERM_NONFATAL;
//            break;
            } else if ((len == LASTPACKETMY_NOTIFY) | (len == HAVE_FAST_RESEND_FRAME)) { // if this physical channel had sent last packet
#ifdef DEBUGG
                    vlog(LOG_INFO, "debug: R_MODE main send");
#endif
                if( (drop_packet_flag == 1) && (drop_counter > 0) ) {
                    len = 0; // shittyhold - should never kick in again!    
                    vlog(LOG_INFO, "shit! hold!");
                } else {
                len = select_devread_send(buf, out2);
        CHKCPU(42);
                }
                
                if (len > 0) {
                } else if (len == BREAK_ERROR) {
                    vlog(LOG_INFO, "select_devread_send() R_MODE BREAK_ERROR");
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
        vlog(LOG_INFO, "debug: AG_MODE");
#endif
            if( (drop_packet_flag == 1) && (drop_counter > 0) ) {
                    len = 0; // shittyhold // never
                    vlog(LOG_INFO, "shit! hold!");
            } else {
            len = select_devread_send(buf, out2);
        CHKCPU(43);
            }
            if (len > 0) {
                dirty_seq_num++;
#ifdef DEBUGG
                vlog(LOG_INFO, "Dirty seq_num - %u", dirty_seq_num);
#endif
            } else if (len == BREAK_ERROR) {
                vlog(LOG_INFO, "select_devread_send() AG_MODE BREAK_ERROR");
                linker_term = TERM_NONFATAL;
            } else if (len == CONTINUE_ERROR) {
#ifdef DEBUGG
                vlog(LOG_INFO, "select_devread_send() CONTINUE");
#endif
                len = 0;
            } else if (len == TRYWAIT_NOTIFY) {
#ifdef DEBUGG
                vlog(LOG_INFO, "select_devread_send() TRYWAIT_NOTIFY");
#endif
                len = 0;
            } else if (len == NET_WRITE_BUSY_NOTIFY) {
#ifdef DEBUGG
                vlog(LOG_INFO, "select_devread_send() NET_WRITE_BUSY_NOTIFY");
#endif
                len = 0;
            } else if (len == SEND_Q_NOTIFY) {
#ifdef DEBUGG
                vlog(LOG_INFO, "select_devread_send() SEND_Q_NOTIFY");
#endif
                len = 0;
            }
        }

        CHKCPU(5);
        //todo #flood_code need to move
//         int flood_flag = 0;
//         sem_wait(&(shm_conn_info->common_sem));
//         if (shm_conn_info->flood_flag[info.process_num])
//             flood_flag = TRAIN_PKTS;
//         shm_conn_info->flood_flag[info.process_num] = 0;
//         sem_post(&(shm_conn_info->common_sem));
//         uint32_t local_seq_num_p;
//         uint16_t tmp_flag=0, gg1;
//         uint32_t  gg2, gg3;
//         if (flood_flag > 0 && linker_term != TERM_NONFATAL) {
//             gettimeofday(&flood_start_time, NULL );
//             start_of_train = info.channel[1].local_seq_num;
//             end_of_train = start_of_train + flood_flag;
//             sem_wait(&(shm_conn_info->resend_buf_sem));
//             uint32_t seq_tmp;
//             get_last_packet_seq_num(1, &seq_tmp);
//             int sender_pid;
//             char *out;
//             int len = get_resend_frame(1, &seq_tmp, &out, &sender_pid );
//             if (len == -1) {
//                 len = get_last_packet(1, &last_sent_packet_num[1].seq_num, &out, &sender_pid);
//             }
//             if (len == -1) {
//                 vlog(LOG_ERR, "WARNING Cannot send train");
//             } else {
//                 memcpy(buf, out, len);
//             }
//             if(len < 900) {
//                 vlog(LOG_ERR, "WARNING Train car too small to load track!");
//             }
//             sem_post(&(shm_conn_info->resend_buf_sem));
//             for (; flood_flag > 0; flood_flag--) {
//                 len = seqn_break_tail(buf, len, &seq_tmp, &tmp_flag, &local_seq_num_p, &gg1, &gg2, &gg3); // last four unused
//                 len = pack_packet(1, buf, len, seq_tmp, info.channel[1].local_seq_num, 0);
//                 info.channel[1].packet_recv_counter = 0;
//                 // send DATA
//                 int len_ret = udp_write(info.channel[1].descriptor, buf, len);
// //                vlog(LOG_INFO, "send train process %i packet num %i local_seq %"PRIu32"", info.process_num, flood_flag,
// //                        info.channel[1].local_seq_num);
//                 info.channel[1].local_seq_num++;
//             }
//         }
        sem_post(&shm_conn_info->hard_sem); // critical_sem


        gettimeofday(&info.current_time, NULL);
        last_action = info.current_time.tv_sec;
        lfd_host->stat.comp_out += len;
        
        CHKCPU(6);
    }
    
finish_loop:

    free_timer(recv_n_loss_send_timer);
    free_timer(send_q_limit_change_timer);
    free_timer(s_q_lim_drop_timer);
    free_timer(packet_speed_timer);
    free_timer(head_channel_switch_timer);

    sem_wait(&(shm_conn_info->AG_flags_sem));
    shm_conn_info->channels_mask &= ~(1 << info.process_num); // del channel num from binary mask
    shm_conn_info->need_to_exit &= ~(1 << info.process_num);
    shm_conn_info->hold_mask &= ~(1 << info.process_num); // set bin mask to zero (send not allowed)
    shm_conn_info->ag_mask &= ~(1 << info.process_num); // set bin mask to zero
    sem_post(&(shm_conn_info->AG_flags_sem));
#ifdef JSON
    vlog(LOG_INFO,"{\"name\":\"%s\",\"exit\":1}", lfd_host->host);
#endif

    vlog(LOG_INFO, "process_name - %s p_chan_num : %i,  exiting linker loop TERM=%i", lfd_host->host, info.process_num, linker_term);
    if( !linker_term && errno )
        vlog(LOG_INFO,"Reason: %s (%d)", strerror(errno), errno);

    if (linker_term == VTUN_SIG_TERM) {
        lfd_host->persist = 0;
    }
    if(channel_mode == MODE_NORMAL) { // may quit with different mode
        shm_conn_info->normal_senders--; // TODO HERE: add all possible checks for sudden deaths!!!
    }

    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].pid = 0;
    shm_conn_info->stats[info.process_num].name[0] = 0;
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
        vlog(LOG_ERR,"ERROR: cannot free buf: CORRUPT!");
        lfd_free(save_buf);
    } else {
        lfd_free(buf);
    }
    if(save_out_buf != out_buf) {
        vlog(LOG_ERR,"ERROR: cannot free out_buf: CORRUPT!");
        lfd_free(save_out_buf);
    } else {
        lfd_free(out_buf);
    }

    /*memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = SIG_DFL;
    //sa.sa_flags   = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);*/
    
#ifdef PROF
    chdir("/");
#endif

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

    vlog_init();
    // these are for retransmit mode... to be removed
    retransmit_count = 0;
    channel_mode = MODE_NORMAL;
    hold_mode = 0; // 1 - hold 0 - normal
    force_hold_mode = 1;
    incomplete_seq_len = 0;
    my_miss_packets_max = 0; // in ms; calculated here
    miss_packets_max = 0; // get from another side
    proto_err_cnt = 0;
    my_max_send_q_chan_num = 0;
    my_max_send_q = 0;
    max_reorder_byte = 0;
    last_channels_mask = 0;
    info.B = 0.2;
    info.Bu = 0.2;
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
        info.channel_amount = P_TCP_CONN_AMOUNT + 1; // current here number of channels include service_channel
        info.channel = calloc(info.channel_amount, sizeof(*(info.channel)));
        if (info.channel == NULL) {
            vlog(LOG_ERR, "Cannot allocate memory for info.channel, process - %i, pid - %i",info.process_num, info.pid);
            return 0;
        }
        if (info.channel_amount > MAX_TCP_LOGICAL_CHANNELS) {
            vlog(LOG_ERR, "ASSERT! channel amount corrupt %i channels. Exit ", info.channel_amount);
            info.channel_amount = MAX_TCP_LOGICAL_CHANNELS;
            linker_term = TERM_NONFATAL;
            return 0;
        }
        chan_info = (struct channel_info *) calloc(info.channel_amount, sizeof(struct channel_info));
        if (chan_info == NULL ) {
            vlog(LOG_ERR, "Can't allocate array for struct chan_info for the linker");
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
            vlog(LOG_INFO, "debug: new channel_mask %xx0 add channel - %u", shm_conn_info->channels_mask, info.process_num);
#endif
    sem_post(&(shm_conn_info->AG_flags_sem));

    /* Create pid directory if need */
    if (mkdir(LINKFD_PID_DIR, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
        if (errno == EEXIST) {
            vlog(LOG_INFO, "%s already  exists :)", LINKFD_PID_DIR);
        } else {
            vlog(LOG_ERR, "Can't create lock directory %s: %s (%d)", LINKFD_PID_DIR, strerror(errno), errno);
        }
    }

    /* Write my pid into file */
    char pid_file_str[200], pid_str[20];
    sprintf(pid_file_str, "%s/%s", LINKFD_PID_DIR, lfd_host->host);
    int pid_file_fd = open(pid_file_str, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (pid_file_fd < 0) {
        vlog(LOG_ERR, "Can't create temp lock file %s", pid_file_str);
    }
    int len = sprintf(pid_str, "%d\n", info.pid);
    if (write(pid_file_fd, pid_str, len) != len) {
        vlog(LOG_ERR, "Can't write PID %d to %s", info.pid, pid_file_str);
    }
    close(pid_file_fd);

    //old_prio=getpriority(PRIO_PROCESS,0);
    //setpriority(PRIO_PROCESS,0,LINKFD_PRIO);
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=SIG_IGN;
    sa.sa_flags=SA_NOCLDWAIT;
    sigaction(SIGCHLD,&sa,NULL);
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_term;
    sigaction(SIGTERM,&sa,&sa_oldterm);
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_term;
    sigaction(SIGINT,&sa,&sa_oldint);
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_hup;
    sigaction(SIGHUP,&sa,&sa_oldhup);
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler=sig_usr1;
    sigaction(SIGUSR1,&sa,&sa_oldusr1);


    sigemptyset (&block_mask);
    // sigemptyset (&unblock_mask);
    sigaddset (&block_mask, SIGTERM);
    sigaddset (&block_mask, SIGUSR1);
    // sigaddset (&block_mask, SIGCONT);
    sigaddset (&block_mask, SIGHUP);
    sigaddset (&block_mask, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &block_mask, &unblock_mask) < 0) {
        perror ("sigprocmask");
        return 1;
    }

#ifdef PROF
    sa.sa_handler=profexit;
    sigaction(SIGUSR2,&sa,NULL);
#endif

    /* Initialize statstic dumps */
    if( host->flags & VTUN_STAT ) {
        char file[40];
        sprintf(file,"%s/%.20s", VTUN_STAT_DIR, host->host);
        if( (host->stat.file=fopen(file, "a")) ) {
            setvbuf(host->stat.file, NULL, _IOLBF, 0);
            //alarm(VTUN_STAT_IVAL);
        } else
            vlog(LOG_ERR, "Can't open stats file %s", file);
    }

    io_init();

    lfd_linker();

    io_init();

    vlog_free();
    remove(pid_file_str); // rm file with my pid
    free(info.channel);
    free(chan_info);

    if( host->flags & VTUN_STAT ) {
        //alarm(0);
        if (host->stat.file)
            fclose(host->stat.file);
    }
    // I'm saying that I'm dead
    sem_wait(&(shm_conn_info->AG_flags_sem));
    uint32_t chan_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
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
    
    if (sigprocmask(SIG_SETMASK, &unblock_mask, NULL) < 0) {
        perror ("sigprocmask 2");
        return 1;
    }

    //setpriority(PRIO_PROCESS,0,old_prio);

    return linker_term;
}
