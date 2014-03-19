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
 * - dynamic buffer: fixed size in MB (e.g. 5MB), dynamic packet list (Start-Byte-Rel; End-Byte-Rel)
 *   this would require defragmenting ?? :-O better have buffer for smaller packets and bigger...?
 * - stable channels with stabilizing weights
 * - fix last_write_time thing
 * - fix rxmit mode
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

#define SEND_Q_LIMIT_MINIMAL 5000 // 7000 seems to work
#define SENQ_Q_LIMIT_THRESHOLD 7000
#define MAX_LATENCY_DROP { 0, 550000 }
#define MAX_REORDER_LATENCY { 0, 50000 } // is rtt * 2 actually, default
#define MAX_REORDER_LATENCY_MAX 999999 // usec
#define MAX_REORDER_LATENCY_MIN 200 // usec
#define MAX_REORDER_PERPATH 4
#define RSR_TOP 90000
#define SELECT_SLEEP_USEC 50000
#define FCI_P_INTERVAL 5 // interval in packets to send ACK. 7 ~ 7% speed loss, 5 ~ 15%, 0 ~ 45%

#define RSR_SMOOTH_GRAN 10 // ms granularity
#define RSR_SMOOTH_FULL 3000 // ms for full convergence
//#define NOCONTROL
//#define NO_ACK

// #define TIMEWARP

#ifdef TIMEWARP
    #define TW_MAX 10000000

    char *timewarp;
    int tw_cur;
#endif

#define JS_MAX 10000 // 10kb string len
char *js_buf;
int js_cur;

// flags:
uint8_t time_lag_ready;

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


int add_json(char *buf, int *pos, const char *name, const char *format, ...) {
    va_list args;
    int bs = 0;
    if (*pos > (JS_MAX/2)) return -1;
    bs = sprintf(buf + *pos, "\"%s\":\"", name);
    *pos = *pos + bs;
    
    va_start(args, format);
    bs = vsprintf(buf+*pos, format, args);
    va_end(args);
    
    *pos = *pos + bs;

    bs = sprintf(buf + *pos, "\",");
    *pos = *pos + bs;
    return bs;
}

int start_json(char *buf, int *pos) {
    int bs=0;
    memset(buf, 0, JS_MAX);
    struct timeval dt;
    gettimeofday(&dt, NULL);
    *pos = 0;

    bs = sprintf(buf, "%ld.%06ld: {", dt.tv_sec, dt.tv_usec);
    *pos = *pos + bs;
    return 0;
}

int print_json(char *buf, int *pos) {
    buf[*pos-1] = 0;
    vtun_syslog(LOG_INFO, "%s}", buf);
    return 0;
}

/*
int mma_init(struct * v_mma mma) {
    
}

int mma_add(struct v_mma mma, int val) {
    if()
    return 0;
}
*/

#ifdef TIMEWARP
int print_tw(char *buf, int *pos, const char *format, ...) {
    va_list args;
    int slen;
    struct timeval dt;
    gettimeofday(&dt, NULL);
    
    sprintf(buf + *pos, "\n%ld.%06ld:    ", dt.tv_sec, dt.tv_usec);
    *pos = *pos + 20;
    
    va_start(args, format);
    int out = vsprintf(buf+*pos, format, args);
    va_end(args);
    
    slen = strlen(buf+*pos);
    *pos = *pos + slen;
    if(*pos > TW_MAX - 10000) { // WARNING: 10000 max per line!
        sprintf(buf + *pos, "---- Overflow!\n");
        *pos = 0;
    }
    return out;
}

int flush_tw(char *buf, int *tw_cur) {
    // flush, memset
    int fd = open("/tmp/TIMEWARP.log", O_WRONLY | O_APPEND);
    int slen = strlen(buf);
    //vtun_syslog(LOG_INFO, "FLUSH! %d", slen);
    int len = write(fd, buf, slen);
    close(fd);
    memset(buf, 0, TW_MAX);
    *tw_cur = 0;
    return len;
}

int start_tw(char *buf, int *c) {
    memset(buf, 0, TW_MAX);
    *c = 0;
    return 0;
}
#endif



/********** Linker *************/
/* Termination flag */
static volatile sig_atomic_t linker_term;

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

int get_write_buf_wait_data() {
    // TODO WARNING: is it synchronized?
    struct timeval max_latency_drop = MAX_LATENCY_DROP, tv_tmp;
    uint32_t chan_mask = shm_conn_info->channels_mask;
    int alive_physical_channels;
    for (int i = 0; i < info.channel_amount; i++) {
        alive_physical_channels = 0;
        info.least_rx_seq[i] = UINT32_MAX;
        for(int p=0; p < MAX_TCP_PHYSICAL_CHANNELS; p++) {
            if (chan_mask & (1 << p)) {
                //if(shm_conn_info->stats[p].ag_flag_local == R_MODE) continue; // do not count retransmitting chans - they may be late!
                alive_physical_channels++;
                if (shm_conn_info->write_buf[i].last_received_seq[p] < info.least_rx_seq[i]) {
                    info.least_rx_seq[i] = shm_conn_info->write_buf[i].last_received_seq[p];
                }
            }
        }
        
        if (shm_conn_info->write_buf[i].frames.rel_head != -1) {
            timersub(&info.current_time, &shm_conn_info->write_buf[i].last_write_time, &tv_tmp);
            if (shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].seq_num
                    == (shm_conn_info->write_buf[i].last_written_seq + 1)) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "get_write_buf_wait_data(), next seq");
#endif
                return 1;
            } else if (timercmp(&tv_tmp, &max_latency_drop, >=)) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "get_write_buf_wait_data(), latency drop %ld.%06ld", tv_tmp.tv_sec, tv_tmp.tv_usec);
#endif
                return 1;
            } else if (shm_conn_info->write_buf[i].last_written_seq < info.least_rx_seq[i]) {
                // TODO: implement MAX_REORDER_LATENCY policy! 
                // seems done. check it -> implemented in that least_rx_seq does not update until reorder fixed
                return 1;
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

int get_resend_frame(int conn_num, uint32_t seq_num, char **out, int *sender_pid) {
    int i, len = -1;
    // TODO: we should be searching from most probable start place
    //   not to scan through the whole buffer to the end
    for(i=0; i<RESEND_BUF_SIZE; i++) { 
        if( (shm_conn_info->resend_frames_buf[i].seq_num == seq_num) &&
                (shm_conn_info->resend_frames_buf[i].chan_num == conn_num)) {

            len = shm_conn_info->resend_frames_buf[i].len;
            *((uint16_t *)(shm_conn_info->resend_frames_buf[i].out+LINKFD_FRAME_RESERV + (len+sizeof(uint32_t)))) = (uint16_t)htons(conn_num + FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
            *out = shm_conn_info->resend_frames_buf[i].out+LINKFD_FRAME_RESERV;
            *sender_pid = shm_conn_info->resend_frames_buf[i].sender_pid;
            break;
        }
    }
    return len;
}

int get_last_packet_seq_num(int chan_num, uint32_t *seq_num) {
    int j = shm_conn_info->resend_buf_idx;
    for (int i = 0; i < RESEND_BUF_SIZE; i++) {
        if (shm_conn_info->resend_frames_buf[j].chan_num == chan_num) {
            *seq_num = shm_conn_info->resend_frames_buf[j].seq_num;
            return 1;
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
            return 1;
        }
        j++;
    }
    return -1;
}

int seqn_break_tail(char *out, int len, uint32_t *seq_num, uint16_t *flag_var, uint32_t *local_seq_num, uint16_t *mini_sum, uint32_t *last_recv_lsn, uint32_t *packet_recv_spd) {
    *seq_num = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *flag_var = ntohs(*((uint16_t *)(&out[len - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *local_seq_num = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    *mini_sum = ntohs(*((uint16_t *)(&out[len - sizeof(uint16_t)- sizeof(uint32_t) - sizeof(uint32_t)])));
    
    *last_recv_lsn = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t) - sizeof(uint32_t)])));
    *packet_recv_spd = ntohl(*((uint32_t *)(&out[len - sizeof(uint32_t)])));
    return len - (sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint32_t));
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
int retransmit_send(char *out2) {
    if (hold_mode) {
        return CONTINUE_ERROR;
    }
    int len = 0, send_counter = 0, mypid;
    uint32_t top_seq_num, seq_num_tmp = 1, remote_lws = SEQ_START_VAL;
    sem_wait(&(shm_conn_info->resend_buf_sem));
    if (check_fast_resend()){
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
        if (remote_lws > top_seq_num) {
            shm_conn_info->write_buf[i].remote_lws = top_seq_num; // ????top_seq_num - 1
            remote_lws = top_seq_num;
        }
        sem_post(&(shm_conn_info->write_buf_sem));
        if ((last_sent_packet_num[i].seq_num + 1) <= remote_lws) {
            last_sent_packet_num[i].seq_num = remote_lws;
        }

        if (((top_seq_num - last_sent_packet_num[i].seq_num) <= 0) || (top_seq_num == SEQ_START_VAL)) {
#ifdef DEBUGG
           vtun_syslog(LOG_INFO, "debug: retransmit_send skipping logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
            // TODO MOVE THE FOLLOWING LINE TO DEBUG! --vvv
            if (top_seq_num < last_sent_packet_num[i].seq_num) vtun_syslog(LOG_INFO, "WARNING! impossible: chan#%i last sent seq_num %"PRIu32" is > top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
           continue;
        }
        last_sent_packet_num[i].seq_num++;
 

#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: logical channel #%i my last seq_num %"PRIu32" top seq_num %"PRIu32"", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
        sem_wait(&(shm_conn_info->resend_buf_sem));
        len = get_resend_frame(i, last_sent_packet_num[i].seq_num, &out2, &mypid);
          if (len == -1) {
            int succ = get_oldest_packet_seq_num(i, &seq_num_tmp);
            if (succ == -1) {
                sem_post(&(shm_conn_info->resend_buf_sem));
                last_sent_packet_num[i].seq_num = top_seq_num;
                vtun_syslog(LOG_INFO, "R_MODE can't found frame for chan %d seq %"PRIu32" ... continue", i, last_sent_packet_num[i].seq_num);
                continue;
            }
            last_sent_packet_num[i].seq_num = seq_num_tmp;
            len = get_resend_frame(i, last_sent_packet_num[i].seq_num, &out2, &mypid);
        }
        if (len == -1) {
            sem_post(&(shm_conn_info->resend_buf_sem));
            vtun_syslog(LOG_ERR, "ERROR R_MODE can't found frame for chan %d seq %"PRIu32" ... continue", i, last_sent_packet_num[i].seq_num);
            last_sent_packet_num[i].seq_num = top_seq_num;
            continue;
        }
        memcpy(out_buf, out2, len);
        sem_post(&(shm_conn_info->resend_buf_sem));
        if (last_sent_packet_num[i].num_resend == 0) {
            last_sent_packet_num[i].num_resend++;
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "Resend frame ... chan %d start for seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, len);
#endif
        }
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %"PRIu32" len %d", i, last_sent_packet_num[i].seq_num, len);
#endif
        statb.bytes_sent_rx += len;
        if (drop_packet_flag == 0) { // do not send if in R_MODE and limit reached! TODO: this means it will skip sending data more than expected
            
            // TODO: add select() here!
            // TODO: optimize here
            uint32_t tmp_seq_counter;
            uint32_t local_seq_num_p;
            uint16_t tmp_flag;
            uint16_t sum;
            len = seqn_break_tail(out_buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
            len = pack_packet(i, out_buf, len, tmp_seq_counter, info.channel[i].local_seq_num, tmp_flag);
            // send DATA
            int len_ret = udp_write(info.channel[i].descriptor, out_buf, len);
            if ((len && len_ret) < 0) {
                vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", i, strerror(errno), errno);
                return BREAK_ERROR;
            }
            info.channel[i].local_seq_num++;
        
            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
            info.channel[i].up_len += len_ret;
            info.channel[i].up_packets++;
            info.channel[i].bytes_put++;
            info.byte_r_mode += len_ret;
        }
        send_counter++;
    }
    
    if (send_counter == 0) 
        return LASTPACKETMY_NOTIFY;
        
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
    sem_wait(&(shm_conn_info->resend_buf_sem));
    idx = get_fast_resend_frame(&chan_num, buf, &len, &tmp_seq_counter);
    sem_post(&(shm_conn_info->resend_buf_sem));
    if (idx == -1) {
        if (!FD_ISSET(info.tun_device, &fdset)) {
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: Nothing to read from tun device (first FD_ISSET)");
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
        if (drop_packet_flag == 1) {
            drop_counter++;
            #ifdef TIMEWARP
                print_tw(timewarp, &tw_cur, "drop packet");
            #endif
            if (drop_counter>1000) drop_counter=0;
            //#ifdef DEBUGG
            
            vtun_syslog(LOG_INFO, "drop_packet_flag info.rsr %d info.W %d, max_send_q %d, send_q_eff %d", info.rsr, info.send_q_limit_cubic, my_max_send_q, send_q_eff);
            //#endif

            return CONTINUE_ERROR;
        }
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
        idx = add_fast_resend_frame(chan_num, buf, len, tmp_seq_counter);
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

    // now add correct mini_sum and local_seq_num
    //if(!new_packet) {
        uint32_t local_seq_num_p;
        uint16_t tmp_flag;
        uint16_t sum;
        len = seqn_break_tail(buf, len, &tmp_seq_counter, &tmp_flag, &local_seq_num_p, &sum, &local_seq_num_p, &local_seq_num_p); // last four unused
        len = pack_packet(chan_num, buf, len, tmp_seq_counter, info.channel[chan_num].local_seq_num, tmp_flag);
    //}

    struct timeval send1; // need for mean_delay calculation (legacy)
    struct timeval send2; // need for mean_delay calculation (legacy)
    gettimeofday(&send1, NULL );
    // send DATA
    int len_ret = udp_write(info.channel[chan_num].descriptor, buf, len);
    if ((len && len_ret) < 0) {
        vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
        return BREAK_ERROR;
    }
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
    info.byte_efficient += len_ret;

    last_sent_packet_num[chan_num].seq_num = tmp_seq_counter;
//    last_sent_packet_num[chan_num].num_resend = 0;
    return len;
}

int write_buf_check_n_flush(int logical_channel) {
    int fprev = -1;
    int fold = -1;
    int len;
    struct timeval max_latency_drop = MAX_LATENCY_DROP, tv_tmp;
    fprev = shm_conn_info->write_buf[logical_channel].frames.rel_head;
    shm_conn_info->write_buf[logical_channel].complete_seq_quantity = 0;
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
        timersub(&info.current_time, &shm_conn_info->frames_buf[fprev].time_stamp, &tv_tmp);
        int cond_flag = shm_conn_info->frames_buf[fprev].seq_num == (shm_conn_info->write_buf[logical_channel].last_written_seq + 1) ? 1 : 0;
        if (cond_flag || (buf_len > lfd_host->MAX_ALLOWED_BUF_LEN)
                      || ( timercmp(&tv_tmp, &max_latency_drop, >=))
                      || ( shm_conn_info->write_buf[logical_channel].last_written_seq < info.least_rx_seq[logical_channel] )) {
            if (!cond_flag) {
                shm_conn_info->tflush_counter += shm_conn_info->frames_buf[fprev].seq_num
                        - (shm_conn_info->write_buf[logical_channel].last_written_seq + 1);
                if(buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) {
                    vtun_syslog(LOG_INFO, "MAX_ALLOWED_BUF_LEN tflush_counter %"PRIu32" %d",  shm_conn_info->tflush_counter, incomplete_seq_len);
                } else if (timercmp(&tv_tmp, &max_latency_drop, >=)) {
                    vtun_syslog(LOG_INFO, "MAX_LATENCY_DROP tflush_counter %"PRIu32" %d",  shm_conn_info->tflush_counter, incomplete_seq_len);
                } else if (shm_conn_info->write_buf[logical_channel].last_written_seq < info.least_rx_seq[logical_channel]) {
                    vtun_syslog(LOG_INFO, "LOSS tflush_counter %"PRIu32" %d",  shm_conn_info->tflush_counter, incomplete_seq_len);
                }
            }
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
                    return;
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
    // place into correct position first..
    int i = shm_conn_info->write_buf[conn_num].frames.rel_head, n;
    int newf;
    uint32_t istart;
    int j=0;

    if(info.channel[conn_num].local_seq_num_beforeloss == 0) {
        shm_conn_info->write_buf[conn_num].last_received_seq[info.process_num] = seq_num;
    } else {
        shm_conn_info->write_buf[conn_num].last_received_seq_shadow[info.process_num] = seq_num;
    }

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
    acnt = 0;
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

/**
                                   .__  __         .__                  
_____     ____       ________  _  _|__|/  |_  ____ |  |__   ___________ 
\__  \   / ___\     /  ___/\ \/ \/ /  \   __\/ ___\|  |  \_/ __ \_  __ \
 / __ \_/ /_/  >    \___ \  \     /|  ||  | \  \___|   Y  \  ___/|  | \/
(____  /\___  /____/____  >  \/\_/ |__||__|  \___  >___|  /\___  >__|   
     \//_____/_____/    \/                       \/     \/     \/       
 * Modes switcher and socket status collector
 * @return - 0 for R_MODE and 1 for AG_MODE
 */

int ag_switcher() {
#ifdef TRACE
    vtun_syslog(LOG_INFO, "Process %i is calling ag_switcher()", info.process_num);
#endif
    for (int i = 0; i < info.channel_amount; i++) {
        chan_info[i].rport = info.channel[i].rport;
        chan_info[i].lport = info.channel[i].lport;
#ifdef TRACE
        vtun_syslog(LOG_INFO, "Process %i logic channel - %i lport - %i rport %i", info.process_num, i, chan_info[i].lport, info.channel[i].rport);
#endif
    }
    int max_speed_chan = 0;
    uint32_t max_speed = 0;
    sem_wait(&(shm_conn_info->stats_sem));
    for (int i = 1; i < info.channel_amount; i++) {
        if (max_speed < shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed) {
            max_speed = shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed;
            max_speed_chan = i;
        }
    }
    shm_conn_info->stats[info.process_num].max_upload_speed = max_speed;
    sem_post(&(shm_conn_info->stats_sem));
    if (max_speed == 0) {
        max_speed_chan = my_max_speed_chan;
    } else {
        my_max_speed_chan = max_speed_chan;
    }

    struct timeval ag_curtime, time_sub_tmp;
    gettimeofday(&ag_curtime, NULL );

    uint32_t my_max_send_q = info.channel[my_max_send_q_chan_num].send_q;

    uint32_t bytes_pass = 0;

    timersub(&ag_curtime, &info.channel[my_max_send_q_chan_num].send_q_time, &time_sub_tmp);
    //bytes_pass = time_sub_tmp.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].ACK_speed_avg
    //        + (time_sub_tmp.tv_usec * info.channel[my_max_send_q_chan_num].ACK_speed_avg) / 1000;
    bytes_pass = time_sub_tmp.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].packet_recv_upload
            + (time_sub_tmp.tv_usec * info.channel[my_max_send_q_chan_num].packet_recv_upload) / 1000;

    /*int32_t*/ send_q_eff = my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000 - bytes_pass;
#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "net_model chan %i max_send_q %"PRIu32" put %"PRIu32" pass %"PRIu32"", my_max_send_q_chan_num, my_max_send_q,
            info.channel[my_max_send_q_chan_num].bytes_put, bytes_pass);
#endif

    int speed_success = 0;

    /* ACK_coming_speed recalculation */
    int skip_time_usec = info.rtt / 10 * 1000;
    skip_time_usec = skip_time_usec > 999000 ? 999000 : skip_time_usec;
    skip_time_usec = skip_time_usec < 5000 ? 5000 : skip_time_usec;
    for (int i = 0; i < info.channel_amount; i++) {
        int ACK_coming_speed = speed_algo_ack_speed(&(info.channel[i].get_tcp_info_time_old), &info.channel[i].send_q_time, info.channel[i].send_q_old,
                info.channel[i].send_q, info.channel[i].up_packets * 1000, skip_time_usec);
        if ((ACK_coming_speed >= 0) || (ACK_coming_speed == SPEED_ALGO_OVERFLOW) || (ACK_coming_speed == SPEED_ALGO_EPIC_SLOW)) {
            if (ACK_coming_speed >= 0) {
                info.channel[i].ACK_speed_avg *= 100;
                ACK_coming_speed *= 100;
                info.channel[i].ACK_speed_avg += (ACK_coming_speed - info.channel[i].ACK_speed_avg) / 40;
                info.channel[i].ACK_speed_avg /= 100;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "ACK_speed_avg %u logical channel %i", info.channel[i].ACK_speed_avg, i);
#endif
            } else if (ACK_coming_speed == SPEED_ALGO_OVERFLOW) {
                vtun_syslog(LOG_ERR, "WARNING - sent_bytes value is overflow, zeroing ACK_coming_speed");
                info.channel[i].ACK_speed_avg *= 100;
                info.channel[i].ACK_speed_avg -= info.channel[i].ACK_speed_avg / 40;
                info.channel[i].ACK_speed_avg /= 100;
            } else if (ACK_coming_speed == SPEED_ALGO_EPIC_SLOW) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "WARNING - Speed was slow much time logical channel %i", i);
#endif
                info.channel[i].ACK_speed_avg = 0;
            }
            memcpy(&(info.channel[i].get_tcp_info_time_old), &info.channel[i].send_q_time, sizeof(info.channel[i].send_q_time));
            info.channel[i].send_q_old = info.channel[i].send_q;
            info.channel[i].up_len = 0;
            info.channel[i].up_packets = 0;
            info.channel[i].ACK_speed_avg = info.channel[i].ACK_speed_avg == 0 ? 1 : info.channel[i].ACK_speed_avg;
            info.channel[i].magic_rtt =
                    info.channel[i].ACK_speed_avg == 0 ? info.channel[i].send_q / 1 : info.channel[i].send_q / info.channel[i].ACK_speed_avg;
            if (i != 0) {
                speed_success++;
            }
        }
#ifdef DEBUGG
        else if (ACK_coming_speed == SPEED_ALGO_SLOW_SPEED) {
            vtun_syslog(LOG_WARNING, "WARNING - speed very slow, need to wait more bytes");
        } else if (ACK_coming_speed == SPEED_ALGO_HIGH_SPEED) {
            vtun_syslog(LOG_WARNING, "WARNING - speed very high, need to wait more time");
        } else if (ACK_coming_speed == SPEED_ALGO_EPIC_SLOW) {
            vtun_syslog(LOG_WARNING, "WARNING - speed very slow much time!!!");
        }
#endif
    }

    /*if (speed_success) {
        ACK_coming_speed_avg = info.channel[my_max_send_q_chan_num].ACK_speed_avg;
        magic_rtt_avg = info.channel[my_max_send_q_chan_num].magic_rtt;
        
        */
    sem_wait(&(shm_conn_info->AG_flags_sem));
    uint32_t chan_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
    sem_wait(&(shm_conn_info->stats_sem));
    miss_packets_max = shm_conn_info->miss_packets_max;
        
    int send_q_limit_grow;
    int high_speed_chan = 31;
    for (int i = 0; i < 32; i++) {
        /* look for first alive channel*/
        if (chan_mask & (1 << i)) {
#ifdef TRACE
        vtun_syslog(LOG_INFO, "First alive channel %i",i);
#endif
            high_speed_chan = i;
            break;
        }
    }
    /* find high speed channel */
    for (int i = 0; i < 32; i++) {
#ifdef TRACE
        vtun_syslog(LOG_INFO, "Checking channel %i",i);
#endif
        /* check alive channel*/
        if (chan_mask & (1 << i)) {
            high_speed_chan = shm_conn_info->stats[i].ACK_speed > shm_conn_info->stats[high_speed_chan].ACK_speed ? i : high_speed_chan;
#ifdef TRACE
        vtun_syslog(LOG_INFO, "Channel %i alive",i);
#endif
        }
    }
    /*ag switching enable*/

    int ACK_speed_high_speed = shm_conn_info->stats[high_speed_chan].ACK_speed == 0 ? 1 : shm_conn_info->stats[high_speed_chan].ACK_speed;
    int EBL = (90) * 1300;
    if (high_speed_chan == info.process_num) {
        send_q_limit_grow = (EBL - send_q_limit) / 2;
    } else {
        // TODO: use WEIGHT_SCALE config variable instead of '100'. Current scale is 2 (100).
        send_q_limit_grow = (((((int) (shm_conn_info->stats[high_speed_chan].max_send_q_avg)) * shm_conn_info->stats[info.process_num].ACK_speed)
                / ACK_speed_high_speed) - send_q_limit) / 2;
        vtun_syslog(LOG_INFO, "maxest send_q %d my speed %"PRId32" hi speed %d", shm_conn_info->stats[high_speed_chan].max_send_q_avg, shm_conn_info->stats[info.process_num].ACK_speed, ACK_speed_high_speed);

    }
    sem_post(&(shm_conn_info->stats_sem));

    vtun_syslog(LOG_INFO, "send_q lim grow %d last send_q_lim %"PRId32"",send_q_limit_grow, send_q_limit);

    send_q_limit_grow = send_q_limit_grow > 20000 ? 20000 : send_q_limit_grow;
    send_q_limit += send_q_limit_grow;
    send_q_limit = send_q_limit < 20 ? 20 : send_q_limit;
    vtun_syslog(LOG_INFO, "send_q lim new %"PRId32"", send_q_limit);



    int hold_mode_previous = hold_mode;
    vtun_syslog(LOG_INFO, "send_q eff %"PRIu32" lim %"PRId32"", send_q_eff, send_q_limit);
    if (((int) send_q_eff) < send_q_limit) {
        //hold_mode = 0;
    } else {
        //hold_mode = 1;
        //force_hold_mode = 0;
    }
    vtun_syslog(LOG_INFO, "hold_mode %d", hold_mode);

    max_reorder_byte = lfd_host->MAX_REORDER * chan_info[my_max_send_q_chan_num].mss;
    info.max_send_q_calc = (chan_info[my_max_send_q_chan_num].mss * chan_info[my_max_send_q_chan_num].cwnd) / 1000;
#if defined(DEBUGG) && defined(JSON)
// 
#endif
    if (send_q_limit > SEND_Q_LIMIT_MINIMAL) {
        return AG_MODE;
    }
    return R_MODE;
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
    int ping_req_ts[MAX_TCP_LOGICAL_CHANNELS] = {0}; // in us
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

    if( !(buf = lfd_alloc(VTUN_FRAME_SIZE2)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker");
        return 0;
    }
    if( !(out_buf = lfd_alloc(VTUN_FRAME_SIZE2)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate out buffer for the linker");
        return 0;
    }
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
    if(info.srv) {
        /** Server accepted all logical channel here and get and send pid */
        // now read one single byte
        vtun_syslog(LOG_INFO,"Waiting for client to request channels...");
		read_n(service_channel, buf, sizeof(uint16_t)+sizeof(uint16_t));
        info.channel_amount = ntohs(*((uint16_t *) buf)); // include info channel
        if (info.channel_amount > MAX_TCP_LOGICAL_CHANNELS) {
            vtun_syslog(LOG_ERR, "Client ask for %i channels. Exit ", info.channel_amount);
            info.channel_amount = MAX_TCP_LOGICAL_CHANNELS;
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

        for (int i = 1; i < info.channel_amount; i++) {
            // try to bind to portnum my_num+smth:
            memset(&my_addr, 0, sizeof(my_addr));
            my_addr.sin_addr.s_addr = INADDR_ANY;
            memset(&rmaddr, 0, sizeof(rmaddr));
            my_addr.sin_family = AF_INET;
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

//            prio_opt = 1;
//            setsockopt(prio_s, SOL_SOCKET, SO_REUSEADDR, &prio_opt, sizeof(prio_opt));

            if (bind(info.channel[i].descriptor, (struct sockaddr *) &my_addr, sizeof(my_addr))) {
                vtun_syslog(LOG_ERR, "Can't bind to the Channels socket");
                return -1;
            }

            // now get my port number
            laddrlen = sizeof(localaddr);
            if (getsockname(info.channel[i].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                vtun_syslog(LOG_ERR, "My port socket getsockname error; retry %s(%d)", strerror(errno), errno);
                close(prio_s);
                return 0;
            }

            vtun_syslog(LOG_INFO, "Prio bound to temp port %d; sending notification", ntohs(localaddr.sin_port));

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
    vtun_syslog(LOG_INFO,"\"{\"name\":\"%s\",\"exit\":1}", lfd_host->host);
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
    struct timeval recv_n_loss_time = { 0, 500000 };
    set_timer(recv_n_loss_send_timer, &recv_n_loss_time);

    struct timer_obj *send_q_limit_change_timer = create_timer();
    struct timeval send_q_limit_change_time = { 0, 500000 };
    set_timer(send_q_limit_change_timer, &send_q_limit_change_time);

    struct timer_obj *s_q_lim_drop_timer = create_timer();
    update_timer(s_q_lim_drop_timer);

    struct timer_obj *cubic_log_timer = create_timer();
    struct timeval cubic_log_time = { 0, 1000 };
    set_timer(cubic_log_timer, &cubic_log_time);

    struct timer_obj *packet_speed_timer = create_timer();
    struct timeval packet_speed_timer_time = { 0, 500000 };
    set_timer(packet_speed_timer, &packet_speed_timer_time);

    struct timer_obj *hold_timer = create_timer();
    struct timeval hold_timer_time = { 999999, 0 };
    set_timer(hold_timer, &hold_timer_time);

    struct timer_obj *head_channel_switch_timer = create_timer();
    struct timeval head_channel_switch_timer_time = { 0, 0 };
    set_timer(head_channel_switch_timer, &head_channel_switch_timer_time);

    struct timeval t_tv;
    struct timeval loss_time, loss_immune, loss_tv = { 0, 0 };
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
    info.C = C_LOW/2;
    info.max_send_q = 0;

    gettimeofday(&info.cycle_last, NULL); // for info.rsr smooth avg
    int ag_flag_local = R_MODE;
    
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].ag_flag_local = ag_flag_local;
    sem_post(&(shm_conn_info->stats_sem));
    
    info.rsr = RSR_TOP;
    info.send_q_limit = RSR_TOP;
    info.send_q_limit_cubic_max = RSR_TOP;
    int magic_speed = 0;

    struct timeval max_reorder_latency = MAX_REORDER_LATENCY; // is rtt * 2 actually

    for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
        info.channel[i].local_seq_num_beforeloss = 0;
    }
    
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
//        usleep(100); // todo need to tune; Is it necessary? I don't know


        errno = 0;
        gettimeofday(&info.current_time, NULL);

        uint32_t my_max_send_q = info.channel[my_max_send_q_chan_num].send_q;

        uint32_t bytes_pass = 0;

        timersub(&info.current_time, &info.channel[my_max_send_q_chan_num].send_q_time, &t_tv);
        //bytes_pass = time_sub_tmp.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].ACK_speed_avg
        //        + (time_sub_tmp.tv_usec * info.channel[my_max_send_q_chan_num].ACK_speed_avg) / 1000;
        
        int upload_eff = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        if(upload_eff < 10) upload_eff = 100000; // 1000kpkts default start speed
        
        bytes_pass = ((t_tv.tv_sec * upload_eff
                + ((t_tv.tv_usec/10) * upload_eff) / 100000)*3)/10;

        uint32_t speed_log = info.channel[my_max_send_q_chan_num].packet_recv_upload_avg;
        
        int32_t send_q_eff = //my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000;
            (my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000) > bytes_pass ?
                    my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000 - bytes_pass : 0;

#ifdef TIMEWARP      
        if(my_max_send_q < send_q_min) {
            send_q_min = my_max_send_q;
            
            print_tw(timewarp, &tw_cur, "send_q_min %d", send_q_min);
            flush_tw(timewarp, &tw_cur);

        }
        if(send_q_eff < send_q_eff_min) {
            send_q_eff_min = send_q_eff;

            print_tw(timewarp, &tw_cur, "send_q_eff_min %d", send_q_eff_min);
            flush_tw(timewarp, &tw_cur);
            
        }
#endif
        int max_chan=info.process_num;
        int32_t max_speed=0;
        int32_t min_speed=(INT32_MAX - 1);
        sem_wait(&(shm_conn_info->AG_flags_sem));
        uint32_t chan_mask = shm_conn_info->channels_mask;
        sem_post(&(shm_conn_info->AG_flags_sem));
        
        int32_t max_wspd = 0;
        int32_t min_wspd = 1e9;
        if(info.rtt == 0) {
            info.rtt = 1;
        }
        int32_t my_wspd = info.send_q_limit_cubic / info.rtt; // TODO HERE: compute it then choose C
        
        sem_wait(&(shm_conn_info->stats_sem));
        shm_conn_info->stats[info.process_num].max_send_q = send_q_eff;

        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if (chan_mask & (1 << i)) {
                //vtun_syslog(LOG_INFO, "send_q  %"PRIu32" rtt %d", shm_conn_info->stats[i].max_send_q, shm_conn_info->stats[i].rtt_phys_avg);
                if (shm_conn_info->stats[i].ACK_speed == 0) {
                    continue;
                }
                if (shm_conn_info->stats[i].ACK_speed > max_speed) {
                    max_speed = shm_conn_info->stats[i].ACK_speed;
                    max_chan = i;
                }
                if (shm_conn_info->stats[i].ACK_speed < min_speed) {
                    min_speed = shm_conn_info->stats[i].ACK_speed;
                }
                
                if ( (shm_conn_info->stats[i].W_cubic / shm_conn_info->stats[i].rtt_phys_avg) > max_wspd) {
                    max_wspd = (shm_conn_info->stats[i].W_cubic / shm_conn_info->stats[i].rtt_phys_avg);
                    //max_chan = i; //?
                }
                if ((shm_conn_info->stats[i].W_cubic / shm_conn_info->stats[i].rtt_phys_avg) < min_wspd) {
                    min_wspd = (shm_conn_info->stats[i].W_cubic / shm_conn_info->stats[i].rtt_phys_avg);
                }
                
            }

        }

        if (min_speed != (INT32_MAX - 1)) {
            /* vtun_syslog(LOG_INFO, "send_q  %"PRIu32" rtt %d speed %d", shm_conn_info->stats[info.process_num].max_send_q,
             shm_conn_info->stats[info.process_num].rtt_phys_avg,
             (shm_conn_info->stats[info.process_num].max_send_q * 1000000) / (shm_conn_info->stats[info.process_num].rtt_phys_avg));*/
            if (max_speed == info.packet_recv_upload_avg) {
//                info.C = C_HI;
                info.head_channel = 1;
            } else if (min_speed == info.packet_recv_upload_avg) {
//                info.C = C_LOW / 2;
                  info.head_channel = 0;
            } else {
//                info.C = C_MED / 2;
                   info.head_channel = 0;
            }
        }
        
        if( tv2ms(&t_tv) > (info.rtt*4) ) { // DDS detect:
            shm_conn_info->stats[info.process_num].ACK_speed = 0;
        }
        
        int32_t rtt_shift;
        // RSR section here
//      if (((shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[info.process_num].rtt_phys_avg) == max_speed) {
        if (info.head_channel) {
            info.rsr = RSR_TOP;
        } else {
            if (shm_conn_info->stats[max_chan].ACK_speed < 1000) {
                shm_conn_info->stats[max_chan].ACK_speed = 1000;
            }
            
            if (shm_conn_info->stats[info.process_num].ACK_speed < 1000) {
                shm_conn_info->stats[info.process_num].ACK_speed = 1000;
            }
            
            
            info.send_q_limit = (RSR_TOP * (shm_conn_info->stats[info.process_num].ACK_speed / 1000))
                                         / (shm_conn_info->stats[        max_chan].ACK_speed / 1000);
            
            
            rtt_shift = (shm_conn_info->stats[info.process_num].rtt_phys_avg - shm_conn_info->stats[max_chan].rtt_phys_avg) // dt in ms..
                                        * (shm_conn_info->stats[max_chan].ACK_speed / 1000); // convert spd from mp/s to mp/ms
            
            
            //vtun_syslog(LOG_INFO, "rtt my %d, rtt fast %d, ACS %d, rs %d",
            //            shm_conn_info->stats[info.process_num].rtt_phys_avg,
            //            shm_conn_info->stats[max_chan].rtt_phys_avg,
            //            shm_conn_info->stats[max_chan].ACK_speed,
            //            rtt_shift);
            
            //vtun_syslog(LOG_INFO, "pnum %d, sql %"PRId32", acs_our %"PRId32", acs_max %"PRId32", rtt_shift %"PRId32", rsr %"PRId32"",
            //            info.process_num,
            //        info.send_q_limit,
            //        shm_conn_info->stats[info.process_num].ACK_speed,
            //        shm_conn_info->stats[max_chan].ACK_speed,
            //        rtt_shift, info.rsr);
            
            
            //rtt_shift=0;
            
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
            
            
            timersub(&(info.current_time), &info.cycle_last, &t_tv);
            int32_t ms_passed = tv2ms(&t_tv);
            if(ms_passed > RSR_SMOOTH_GRAN) {
                if(ms_passed > RSR_SMOOTH_FULL) {
                    ms_passed = RSR_SMOOTH_FULL;
                }
                int rsr_shift = (info.send_q_limit - info.rsr) * ms_passed / RSR_SMOOTH_FULL;
                info.rsr += rsr_shift;
                //vtun_syslog(LOG_INFO, "pnum %d, rsr += send_q_limit %d - info.rsr %d * ms_passed %d / 3000 ( = %d )",
                //           info.process_num, info.send_q_limit, info.rsr, ms_passed, rsr_shift);
                gettimeofday(&info.cycle_last, NULL);
            }
            
            //vtun_syslog(LOG_INFO, "rsr %"PRIu32" rtt_shift %"PRId32" info.send_q_limit %"PRIu32" rtt 0 - %d rtt my - %d speed 0 - %"PRId32" my - %"PRId32"", rsr, rtt_shift, info.send_q_limit, shm_conn_info->stats[0].rtt_phys_avg, shm_conn_info->stats[info.process_num].rtt_phys_avg, shm_conn_info->stats[0].ACK_speed, shm_conn_info->stats[info.process_num].ACK_speed);
        }
        uint32_t tflush_counter_recv = shm_conn_info->tflush_counter_recv;
        

        timersub(&(info.current_time), &loss_time, &t_tv);
        int t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
        t = t / 100;
        t = t > 3000 ? 3000 : t; // 400s limit
        double K = cbrt((((double) info.send_q_limit_cubic_max) * info.B) / info.C);
        uint32_t limit_last = info.send_q_limit_cubic;
        info.send_q_limit_cubic = (uint32_t) (info.C * pow(((double) (t)) - K, 3) + info.send_q_limit_cubic_max);
        shm_conn_info->stats[info.process_num].W_cubic = info.send_q_limit_cubic;
        
        int32_t send_q_limit_cubic_apply = info.send_q_limit_cubic > RSR_TOP ? RSR_TOP : (int32_t)info.send_q_limit_cubic;
        if (send_q_limit_cubic_apply > RSR_TOP) {
            send_q_limit_cubic_apply = RSR_TOP;
        }
        if (send_q_limit_cubic_apply < SEND_Q_LIMIT_MINIMAL) {
            send_q_limit_cubic_apply = SEND_Q_LIMIT_MINIMAL-1;
        }
        
        // now choose ag_flag_local
        if(shm_conn_info->stats[max_chan].max_send_q < SENQ_Q_LIMIT_THRESHOLD) {
            magic_speed = 99999999;
        } else {
            magic_speed = (shm_conn_info->stats[max_chan].max_send_q / shm_conn_info->stats[max_chan].rtt_phys_avg) * 1000;
        }
        
        ag_flag_local = ( (info.rsr <= SENQ_Q_LIMIT_THRESHOLD) || (send_q_limit_cubic_apply <= SENQ_Q_LIMIT_THRESHOLD) ? R_MODE : AG_MODE);
        if( max_speed * 10 < magic_speed * 7 ) ag_flag_local = R_MODE;
        shm_conn_info->stats[info.process_num].ag_flag_local = ag_flag_local;
        
        sem_post(&(shm_conn_info->stats_sem));
        
        //vtun_syslog(LOG_INFO, "K %f = cbrt((((double) %d) * %f ) / %f)", K, info.send_q_limit_cubic_max, info.B, info.C);
        //vtun_syslog(LOG_INFO, "W_cubic= %d = ( info.C %f * pow(((double) (t= %d )) - K = %f, 3) + info.send_q_limit_cubic_max= %d )", info.send_q_limit_cubic, info.C, t, K, info.send_q_limit_cubic_max);
        /*if (info.send_q_limit_cubic > 90000) {
            vtun_syslog(LOG_ERR, "overflow_test W_max %"PRIu32" B %f C %f K %f t %d W was %"PRIu32" now %"PRIu32" ", info.send_q_limit_cubic_max, info.B, info.C, K,
                    t, limit_last, info.send_q_limit_cubic);
            vtun_syslog(LOG_INFO, "overflow_test send_q_limit_cubic %"PRIu32" send_q_limit %"PRIu32"  max_chan %d", info.send_q_limit_cubic, info.send_q_limit,
                    max_chan);
        }*/
        
        

        int hold_mode_previous = hold_mode;
        
        if(ag_flag_local == AG_MODE) {
            if(info.head_channel) {
                hold_mode = 0; // no hold whatsoever;
                if (send_q_eff > info.rsr) {
                    drop_packet_flag = 1;
                    //vtun_syslog(LOG_INFO, "AG_MODE DROP!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d (  %d)", send_q_eff, info.rsr, send_q_limit_cubic_apply,info.send_q_limit_cubic );
                } else {
                    drop_packet_flag = 0;
                }
            } else {
                if ( (send_q_eff > info.rsr) || (send_q_eff > send_q_limit_cubic_apply)) {
                    //vtun_syslog(LOG_INFO, "hold_mode!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d", send_q_eff, rsr, send_q_limit_cubic_apply);
                    hold_mode = 1;
                } else {
                    hold_mode = 0;
                }
            }
        } else { // R_MODE.. no intermediate modes.. yet ;-)
            if(info.head_channel) {
                if(send_q_eff > info.rsr) { // no cubic control on max speed chan!
                    //vtun_syslog(LOG_INFO, "R_MODE DROP HD!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    drop_packet_flag = 1;
                } else {
                    drop_packet_flag = 0;
                }
            } else {
                if((send_q_eff > send_q_limit_cubic_apply) || (send_q_eff > info.rsr)) {
                    //vtun_syslog(LOG_INFO, "R_MODE DROP!!! send_q_eff=%d, rsr=%d, send_q_limit_cubic_apply=%d ( %d )", send_q_eff, info.rsr, send_q_limit_cubic_apply, info.send_q_limit_cubic);
                    drop_packet_flag = 1;
                } else {
                    drop_packet_flag = 0;
                }
            }
        }
        //vtun_syslog(LOG_INFO, "debug0: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
        #ifdef NOCONTROL
        hold_mode = 0;
        drop_packet_flag = 0;
        #endif
        
        
        if (fast_check_timer(packet_speed_timer, &info.current_time)) {
            gettimeofday(&info.current_time, NULL );
            uint32_t tv, max_packets=0;
            tv = get_difference_timer(packet_speed_timer, &info.current_time)->tv_sec * 1000
                    + get_difference_timer(packet_speed_timer, &info.current_time)->tv_usec / 1000;
            if (tv != 0) {
                for (i = 1; i < info.channel_amount; i++) {
                    info.channel[i].packet_download = ((info.channel[i].down_packets * 100000) / tv)*10;
                    if (info.channel[i].down_packets > 0)
                        //vtun_syslog(LOG_INFO, "chan %d down packet speed %"PRIu32" packets %"PRIu32" time %"PRIu32" timer %"PRIu32"", i, info.channel[i].packet_download, info.channel[i].down_packets, tv, packet_speed_timer_time.tv_usec/1000);
                    if (max_packets<info.channel[i].down_packets) max_packets=info.channel[i].down_packets;
                    info.channel[i].down_packets = 0;
                }
                    if (packet_speed_timer_time.tv_usec < 700) packet_speed_timer_time.tv_usec += 20;
                if (max_packets<10){
                    set_timer(packet_speed_timer, &packet_speed_timer_time);
                } else if (max_packets>200){
                    if (packet_speed_timer_time.tv_usec > 400) packet_speed_timer_time.tv_usec -= 20;
                    set_timer(packet_speed_timer, &packet_speed_timer_time);
                } else {
                    update_timer(packet_speed_timer);
                }
            }
        }
        uint32_t hold_time = 0;
        if (hold_mode_previous != hold_mode) {
            if (hold_mode == 0) {
                hold_time = get_difference_timer(packet_speed_timer, &info.current_time)->tv_sec * 1000
                        + get_difference_timer(packet_speed_timer, &info.current_time)->tv_usec / 1000;
            } else {
                update_timer(hold_timer);
            }
        }
        if (check_timer(cubic_log_timer)) {
            update_timer(cubic_log_timer);
        } else if ((info.channel[my_max_send_q_chan_num].packet_loss != 0) || (drop_packet_flag != 0) || (hold_mode_previous != hold_mode)) {
            // noop
        }
        //vtun_syslog(LOG_INFO, "hold %d", hold_mode);
        timersub(&info.current_time, &get_info_time_last, &tv_tmp_tmp_tmp);
        int timercmp_result;
        timercmp_result = timercmp(&tv_tmp_tmp_tmp, &get_info_time, >=);
        int ag_switch_flag = 0;
        
        if ((dirty_seq_num % 6) == 0) {
            dirty_seq_num++;
            ag_switch_flag = 1;
        }
        
        if (timercmp_result || ag_switch_flag) {
//            info.mode = ag_switcher();
            get_info_time_last.tv_sec = info.current_time.tv_sec;
            get_info_time_last.tv_usec = info.current_time.tv_usec;
#if !defined(DEBUGG) && defined(JSON)
            // JSON LOGS HERE
            timersub(&info.current_time, &json_timer, &tv_tmp_tmp_tmp);
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, 500000}), >=)) {
                sem_wait(&(shm_conn_info->stats_sem));
                miss_packets_max = shm_conn_info->miss_packets_max;
                sem_post(&(shm_conn_info->stats_sem));
                sem_wait(&(shm_conn_info->AG_flags_sem));
                uint32_t AG_ready_flags_tmp = shm_conn_info->AG_ready_flag;
                sem_post(&(shm_conn_info->AG_flags_sem));
                
                start_json(js_buf, &js_cur);
                add_json(js_buf, &js_cur, "name", "%s", lfd_host->host);
                add_json(js_buf, &js_cur, "pnum", "%d", info.process_num);
                add_json(js_buf, &js_cur, "hd", "%d", info.head_channel);
                add_json(js_buf, &js_cur, "ag?", "%d", ag_flag_local);
                add_json(js_buf, &js_cur, "rtt", "%d", info.rtt);
                add_json(js_buf, &js_cur, "buf_len", "%d", my_miss_packets_max);
                add_json(js_buf, &js_cur, "buf_len_remote", "%d", miss_packets_max);
                add_json(js_buf, &js_cur, "rsr", "%d", info.rsr);
                add_json(js_buf, &js_cur, "W_cubic", "%d", info.send_q_limit_cubic);
                add_json(js_buf, &js_cur, "send_q", "%d", send_q_eff);
                add_json(js_buf, &js_cur, "ACS", "%d", info.packet_recv_upload_avg);
                add_json(js_buf, &js_cur, "magic_speed", "%d", magic_speed);
                add_json(js_buf, &js_cur, "upload", "%d", shm_conn_info->stats[info.process_num].speed_chan_data[my_max_send_q_chan_num].up_current_speed);
                add_json(js_buf, &js_cur, "drop", "%d", drop_counter);
                add_json(js_buf, &js_cur, "flush", "%d", shm_conn_info->tflush_counter);
                add_json(js_buf, &js_cur, "bytes_sent", "%d", (statb.bytes_sent_norm + statb.bytes_sent_rx));
                
                
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
                
                print_json(js_buf, &js_cur);
                
                json_timer.tv_sec = info.current_time.tv_sec;
                json_timer.tv_usec = info.current_time.tv_usec;
                info.max_send_q_max = 0;
                info.max_send_q_min = 120000;
            }
#endif
        }
        if (info.check_shm) {
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
        int timer_result = fast_check_timer(recv_n_loss_send_timer, &info.current_time);
#ifdef NO_ACK
        if(0){
#else
        for (i = 1; i < info.channel_amount; i++) {
#endif
            /*sending recv and loss data*/
            //if (((info.channel[i].packet_recv_counter > FCI_P_INTERVAL)) || timer_result) { // TODO: think through!
            if (((info.channel[i].local_seq_num_beforeloss != 0) && (info.channel[i].packet_recv_counter > FCI_P_INTERVAL)) || timer_result) { // TODO: think through!
                update_timer(recv_n_loss_send_timer);
                uint32_t tmp32_n;
                uint16_t tmp16_n;
                tmp16_n = htons((uint16_t)info.channel[i].packet_recv_counter); // amt of rcvd packets
                memcpy(buf, &tmp16_n, sizeof(uint16_t));
                if (info.channel[i].local_seq_num_beforeloss != 0) { // send only in this case
                    // check timer
                    if(info.channel[i].packet_loss_counter == 0) {
                        // send immediately & stop waiting
                        info.channel[i].local_seq_num_beforeloss = 0;
                        tmp16_n = 0;
                        sem_wait(&(shm_conn_info->write_buf_sem));
                        // dup of code below
                        shm_conn_info->write_buf[i].last_received_seq[info.process_num] = shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num];
                        shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num] = 0;
                        sem_post(&(shm_conn_info->write_buf_sem));
                    } else {
                        timersub(&info.current_time, &info.channel[i].loss_time, &tv_tmp);
                        if( ((info.channel[i].local_seq_num_recv - info.channel[i].local_seq_num_beforeloss) > MAX_REORDER_PERPATH) || 
                                        timercmp(&tv_tmp, &max_reorder_latency, >=) ) {
                            if( (info.channel[i].local_seq_num_beforeloss) > MAX_REORDER_PERPATH) {
                                vtun_syslog(LOG_INFO, "sedning loss by REORDER %hd", info.channel[i].packet_loss_counter);
                            } else {
                                vtun_syslog(LOG_INFO, "sedning loss by LATENCY %hd", info.channel[i].packet_loss_counter);
                            }
                            info.channel[i].local_seq_num_beforeloss = 0;
                            tmp16_n = htons((uint16_t)info.channel[i].packet_loss_counter); // amt of pkts lost till this moment
                            info.channel[i].packet_loss_counter = 0;
                            sem_wait(&(shm_conn_info->write_buf_sem));
                            // this is not required; just will make drop a bit faster in case of sudden stream stop/lag
                            shm_conn_info->write_buf[i].last_received_seq[info.process_num] = shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num];
                            shm_conn_info->write_buf[i].last_received_seq_shadow[info.process_num] = 0;
                            sem_post(&(shm_conn_info->write_buf_sem));
                        } else {
                            tmp16_n = 0; // amt of pkt loss
                        }
                    }
                } else {
                    tmp16_n = 0; // amt of pkt loss
                    info.channel[i].packet_loss_counter = 0;
                }
                memcpy(buf + sizeof(uint16_t), &tmp16_n, sizeof(uint16_t));
                tmp16_n = htons(FRAME_CHANNEL_INFO);  // flag
                memcpy(buf + 2 * sizeof(uint16_t), &tmp16_n, sizeof(uint16_t));
                tmp32_n = htonl(info.channel[i].local_seq_num_recv); // last received local seq_num
                memcpy(buf + 3 * sizeof(uint16_t), &tmp32_n, sizeof(uint32_t));
                tmp16_n = htons((uint16_t) i);
                memcpy(buf + 3 * sizeof(uint16_t) + sizeof(uint32_t), &tmp16_n, sizeof(uint16_t));
                struct timeval tmp_tv;
                timersub(&info.current_time, &info.channel[i].last_info_send_time, &tmp_tv);
                info.channel[i].last_info_send_time = info.current_time;
                tmp32_n = htonl(tmp_tv.tv_sec * 1000000 + tmp_tv.tv_usec);
                memcpy(buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // pkt recv period
                tmp32_n = htonl(info.channel[i].packet_download);
                memcpy(buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), &tmp32_n, sizeof(uint32_t)); // down speed per current chan

#ifdef DEBUGG
                vtun_syslog(LOG_ERR,
                        "FRAME_CHANNEL_INFO send chan_num %d packet_recv %"PRIu16" packet_loss %"PRId16" packet_seq_num_acked %"PRIu32" packet_recv_period %"PRIu32" ",
                        i, info.channel[i].packet_recv_counter, info.channel[i].packet_loss_counter,
                        (int16_t)info.channel[i].local_seq_num_recv, (uint32_t) (tmp_tv.tv_sec * 1000000 + tmp_tv.tv_usec));
#endif
                // send FCI
                int len_ret = udp_write(info.channel[i].descriptor, buf, ((4 * sizeof(uint16_t) + 3 * sizeof(uint32_t)) | VTUN_BAD_FRAME));
                if (len_ret < 0) {
                    vtun_syslog(LOG_ERR, "Could not send FRAME_CHANNEL_INFO; reason %s (%d)", strerror(errno), errno);
                    linker_term = TERM_NONFATAL;
                    break;
                }
                info.channel[i].packet_recv_counter = 0;
                
                shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret;
                info.channel[0].up_len += len_ret;
            }

             /* TODO write function for lws sending*/
        sem_wait(&(shm_conn_info->write_buf_sem));
        uint32_t last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
        uint32_t last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
        sem_post(&(shm_conn_info->write_buf_sem));
            if ((last_written_seq_tmp > (last_last_written_seq[i] + LWS_NOTIFY_MAX_SUB_SEQ))) {
            // TODO: DUP code!
            sem_wait(&(shm_conn_info->write_buf_sem));
            *((uint32_t *) buf) = htonl(shm_conn_info->write_buf[i].last_written_seq);
            last_last_written_seq[i] = shm_conn_info->write_buf[i].last_written_seq;
            shm_conn_info->write_buf[i].last_lws_notified = info.current_time.tv_sec;
            sem_post(&(shm_conn_info->write_buf_sem));
            *((uint16_t *) (buf + sizeof(uint32_t))) = htons(FRAME_LAST_WRITTEN_SEQ);
                // send LWS. TODO: Ever needed??
                int len_ret = udp_write(info.channel[i].descriptor, buf, ((sizeof(uint32_t) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                if (len_ret < 0) {
                vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                linker_term = TERM_NONFATAL;
            }
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                info.channel[i].up_len += len_ret;
        }
    }
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
           * This is the Tick module
           */
        if ( timercmp(&tv_tmp, &timer_resolution, >=)) {
            if ((info.current_time.tv_sec - last_net_read) > lfd_host->MAX_IDLE_TIMEOUT) {
                vtun_syslog(LOG_INFO, "Session %s network timeout", lfd_host->host);
                break;
            }
            if (info.just_started_recv == 1) {
                uint32_t time_passed = tv_tmp.tv_sec * 1000 + tv_tmp.tv_usec / 1000;
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
//               if(cur_time.tv_sec - last_tick >= lfd_host->TICK_SECS) {

                //time_lag = old last written time - new written time
                // calculate mean value and send time_lag to another side
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
                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                    sem_wait(&(shm_conn_info->stats_sem));
                    /* If pid is null --> link didn't up --> continue*/
                    if (shm_conn_info->stats[i].pid == 0) {
                        sem_post(&(shm_conn_info->stats_sem));
                        continue;
                    }
#ifdef DEBUGG
                    vtun_syslog(LOG_INFO, "DEBUGG Sending time lag for %i buf_len %i.", i, my_miss_packets_max);
#endif
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
                        // TODO: DUP code!
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
            
            
            for (int i = 0; i < 32; i++) {
                if (chan_mask & (1 << i)) {
                    alive_physical_channels++;
                }
            }
            if (alive_physical_channels == 0) {
                vtun_syslog(LOG_ERR, "ASSERT All physical channels dead!!!");
                alive_physical_channels = 1;
            }
            
            
            sem_wait(&(shm_conn_info->write_buf_sem));
            check_result = check_consistency_free(FRAME_BUF_SIZE, info.channel_amount, shm_conn_info->write_buf, &shm_conn_info->wb_free_frames, shm_conn_info->frames_buf);
            sem_post(&(shm_conn_info->write_buf_sem));
            if(check_result < 0) {
                vtun_syslog(LOG_ERR, "CHECK FAILED: write_buf broken: error %d", check_result);
            }
            
               last_timing.tv_sec = info.current_time.tv_sec;
               last_timing.tv_usec = info.current_time.tv_usec;
          }
        }

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
        FD_ZERO(&fdset_w);
        if (get_write_buf_wait_data()) {
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
        gettimeofday(&work_loop2, NULL );
        vtun_syslog(LOG_INFO, "First select time: %"PRIu32" us descriptors num: %i", (long int)((work_loop2.tv_sec-work_loop1.tv_sec)*1000000+(work_loop2.tv_usec-work_loop1.tv_usec)), len);
#endif
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

        if( !len ) {
            /* We are idle, lets check connection */
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "idle...");
#endif
                /* Send ECHO request */
                if((info.current_time.tv_sec - last_action) > lfd_host->PING_INTERVAL) {
                    if(ping_rcvd) {
                         ping_rcvd = 0;
                         gettimeofday(&info.current_time, NULL);
                         last_ping = info.current_time.tv_sec;
                         vtun_syslog(LOG_INFO, "PING ...");
                         // ping ALL channels! this is required due to 120-sec limitation on some NATs
                    for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                        ping_req_ts[i] = info.current_time.tv_sec * 1000 + info.current_time.tv_usec / 1000; //save time
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
                vtun_syslog(LOG_INFO, "data on net... chan %d", chan_num);
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
#ifdef DEBUGG
                            if (recv_lag) {
                                vtun_syslog(LOG_INFO, "Time lag for pid: %i is %u", time_lag_local.pid, time_lag_local.time_lag);
                            }
#endif
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
                            info.channel[chan_num].send_q_time = info.current_time; // TODO: possible segfault here
                            memcpy(&tmp16_n, buf, sizeof(uint16_t));
                            info.channel[chan_num].packet_recv = ntohs(tmp16_n); // unused 
                            memcpy(&tmp16_n, buf + sizeof(uint16_t), sizeof(uint16_t));
                            info.channel[chan_num].packet_loss = ntohs(tmp16_n); // FCI-only data only on loss
                            memcpy(&tmp32_n, buf + 3 * sizeof(uint16_t), sizeof(uint32_t));
                            info.channel[chan_num].packet_seq_num_acked = ntohl(tmp32_n); // each packet data here
                            //vtun_syslog(LOG_ERR, "local seq %"PRIu32" recv seq %"PRIu32" chan_num %d ",info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked, chan_num);
                            info.channel[chan_num].send_q =
                                    info.channel[chan_num].local_seq_num > info.channel[chan_num].packet_seq_num_acked ?
                                            1000 * (info.channel[chan_num].local_seq_num - info.channel[chan_num].packet_seq_num_acked) : 0;
                            if(info.max_send_q < info.channel[chan_num].send_q) {
                                info.max_send_q = info.channel[chan_num].send_q;
                            }
                            //if (info.channel[chan_num].send_q > 90000)
                            //    vtun_syslog(LOG_INFO, "channel %d mad_send_q %"PRIu32" local_seq_num %"PRIu32" packet_seq_num_acked %"PRIu32"",chan_num, info.channel[chan_num].send_q,info.channel[chan_num].local_seq_num, info.channel[chan_num].packet_seq_num_acked);
                            #ifdef TIMEWARP
                            print_tw(timewarp, &tw_cur, "FRAME_CHANNEL_INFO: Calculated send_q: %d, chan %d, pkt %d, drops: %d", info.channel[chan_num].send_q, chan_num, info.channel[chan_num].packet_seq_num_acked, drop_counter);
                            #endif
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
                                loss_time = info.current_time;
                                ms2tv(&loss_tv, info.rtt / 2);
                                timeradd(&info.current_time, &loss_tv, &loss_immune);
                                if (info.channel[my_max_send_q_chan_num].send_q >= info.send_q_limit_cubic_max) { 
                                    //info.send_q_limit_cubic_max = info.channel[my_max_send_q_chan_num].send_q;
                                    info.send_q_limit_cubic_max = info.max_send_q;
                                } else {
                                    //info.send_q_limit_cubic_max = (int) ((double)info.channel[my_max_send_q_chan_num].send_q * (2.0 - info.B) / 2.0);
                                    info.send_q_limit_cubic_max = (int) ((double)info.max_send_q * (2.0 - info.B) / 2.0);
                                }
                                t = 0;
                                info.max_send_q = 0;
                            } else {
                                timersub(&(info.current_time), &loss_time, &t_tv);
                                t = t_tv.tv_sec * 1000 + t_tv.tv_usec / 1000;
                                t = t / 500;
                                t = t > 2000 ? 2000 : t; // 200s limit
                            }
                            double K = cbrt((((double) info.send_q_limit_cubic_max) * info.B) / info.C);
                            uint32_t limit_last = info.send_q_limit_cubic;
                            info.send_q_limit_cubic = (uint32_t) (info.C * pow(((double) (t)) - K, 3) + info.send_q_limit_cubic_max);
                            //                        vtun_syslog(LOG_ERR, "W_max %"PRIu32" B %f C %f K %f t 0 W was %"PRIu32" now %"PRIu32" loss now", info.send_q_limit_cubic_max, info.B, info.C, K, limit_last, info.send_q_limit_cubic);
                            sem_wait(&(shm_conn_info->stats_sem));
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
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(uint32_t));
                            info.channel[chan_num].packet_recv_period = ntohl(tmp32_n); // unused
                            memcpy(&tmp32_n, buf + 4 * sizeof(uint16_t) + 2 * sizeof(uint32_t), sizeof(uint32_t));
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
                            sem_wait(&(shm_conn_info->stats_sem));
                            /* store in shm */
                            shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_recv_speed = // TODO: remove! never used
                                    info.channel[chan_num].packet_recv_upload;
                            if (my_max_send_q_chan_num == chan_num) {
                                shm_conn_info->stats[info.process_num].ACK_speed = info.channel[chan_num].packet_recv_upload_avg == 0 ? 1 : info.channel[chan_num].packet_recv_upload_avg;
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

                        sem_wait(resend_buf_sem);
                        len=get_resend_frame(chan_num, ntohl(*((uint32_t *)buf)), &out2, &sender_pid);
                        sem_post(resend_buf_sem);
                        
                        // drop the SQL
                        //send_q_limit = START_SQL;

                                                if(len <= 0) {
                            statb.rxmits_notfound++;
                            vtun_syslog(LOG_ERR, "Cannot resend frame: not found %"PRIu32"; rxm_notf %d chan %d", ntohl(*((uint32_t *)buf)), statb.rxmits_notfound, chan_num);
                            // this usually means that this link is slow to get resend request; the data is writen ok and wiped out
                            // so actually it is not a warning...
                            // - OR - resend buffer is too small; check configuration
                            continue;
                        }

                        if( ((lfd_host->flags & VTUN_PROT_MASK) == VTUN_TCP) && (sender_pid == info.pid)) {
                            vtun_syslog(LOG_INFO, "Will not resend my own data! It is on the way! frame len %d seq_num %"PRIu32" chan %d", len, ntohl(*((uint32_t *)buf)), chan_num);
                            continue;
                        }
                        vtun_syslog(LOG_ERR, "Resending bad frame len %d eq lu %d id %"PRIu32" chan %d", len, sizeof(uint32_t), ntohl(*((uint32_t *)buf)), chan_num);

                        lfd_host->stat.byte_out += len;
                        statb.rxmits++;

                        
                        // now set which channel it belongs to...
                        // TODO: this in fact rewrites CHANNEL_MODE making MODE_RETRANSMIT completely useless
                        //*( (uint16_t *) (out2 - sizeof(flag_var))) = chan_num + FLAGS_RESERVED;
                        // this does not work; done in get_resend_frame

                        gettimeofday(&send1, NULL);
                        int len_ret = proto_write(info.channel[0].descriptor, out2, len);
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "ERROR: cannot resend frame: write to chan %d", 0);
                            linker_term = TERM_NONFATAL;
                        }
                        gettimeofday(&send2, NULL);
                        shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret;
                        info.channel[0].up_len += len_ret;
                        info.byte_resend += len_ret;
#ifdef DEBUGG
                        if((long int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec)) > 100) vtun_syslog(LOG_INFO, "BRESEND DELAY: %"PRIu32" ms", (long int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec)));
#endif
                        delay_acc += (int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec));
                        delay_cnt++;

                        //vtun_syslog(LOG_INFO, "sending SIGUSR2 to %d", sender_pid);
                        continue;
                    }
                    if( fl==VTUN_ECHO_REQ ) {
                        /* Send ECHO reply */
                        last_net_read = info.current_time.tv_sec;
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "sending PONG...");
#endif
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
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "... was echo reply");
#endif
                        
                        if(chan_num == 0) ping_rcvd = 1;
                        last_net_read = info.current_time.tv_sec;
                        gettimeofday(&info.current_time, NULL);

                        if (chan_num == my_max_send_q_chan_num) {
                            info.rtt = (int) ((info.current_time.tv_sec * 1000 + info.current_time.tv_usec / 1000) - ping_req_ts[chan_num]); // ms
                            sem_wait(&(shm_conn_info->stats_sem));
                            shm_conn_info->stats[info.process_num].rtt_phys_avg += (info.rtt - shm_conn_info->stats[info.process_num].rtt_phys_avg) / 2;
                            if(shm_conn_info->stats[info.process_num].rtt_phys_avg == 0) {
                                shm_conn_info->stats[info.process_num].rtt_phys_avg = 1;
                            }
                            info.rtt = shm_conn_info->stats[info.process_num].rtt_phys_avg;
                            // now update max_reorder_latency
                            if(info.rtt >= 1000) {
                                max_reorder_latency.tv_sec = 0;
                                max_reorder_latency.tv_usec = MAX_REORDER_LATENCY_MAX;
                            } else if (info.rtt == 1) {
                                max_reorder_latency.tv_sec = 0;
                                max_reorder_latency.tv_usec = MAX_REORDER_LATENCY_MIN; // NOTE possible problem here? 
                            } else {
                                max_reorder_latency.tv_sec = 0;
                                max_reorder_latency.tv_usec = info.rtt * 1000;
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
                    
                     */
                    
                    gettimeofday(&info.current_time, NULL);
                    info.channel[chan_num].down_packets++; // accumulate number of packets
                    last_net_read = info.current_time.tv_sec;
                    statb.bytes_rcvd_norm+=len;
                    statb.bytes_rcvd_chan[chan_num] += len;
                    out = buf; // wtf?
                    uint32_t local_seq_tmp;
                    uint16_t mini_sum;
                    uint32_t last_recv_lsn;
                    uint32_t packet_recv_spd;
                    len = seqn_break_tail(out, len, &seq_num, &flag_var, &local_seq_tmp, &mini_sum, &last_recv_lsn, &packet_recv_spd);
                    
                    // calculate send_q and speed
                    // send_q
                    info.channel[chan_num].packet_seq_num_acked = last_recv_lsn;
                    info.channel[chan_num].send_q =
                                    info.channel[chan_num].local_seq_num > info.channel[chan_num].packet_seq_num_acked ?
                                            1000 * (info.channel[chan_num].local_seq_num - info.channel[chan_num].packet_seq_num_acked) : 0;
                    if(info.max_send_q < info.channel[chan_num].send_q) {
                        info.max_send_q = info.channel[chan_num].send_q;
                    }

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
                        shm_conn_info->stats[info.process_num].ACK_speed = info.channel[chan_num].packet_recv_upload_avg == 0 ? 1 : info.channel[chan_num].packet_recv_upload_avg;
                        info.packet_recv_upload_avg = shm_conn_info->stats[info.process_num].ACK_speed;
                    }
                    shm_conn_info->stats[info.process_num].max_send_q = my_max_send_q;
                    sem_post(&(shm_conn_info->stats_sem));

                    /* Accumulate loss packet*/
                    uint16_t mini_sum_check = (uint16_t)(seq_num + local_seq_tmp + last_recv_lsn);
                    
                    if(mini_sum != mini_sum_check) {
                        vtun_syslog(LOG_ERR, "PACKET CHECKSUM ERROR chan %d, seq_num %lu, %"PRId16" != %"PRId16"", chan_num, seq_num, ntohs(mini_sum), mini_sum_check);
                        continue;
                    }
                    
                    // this is loss detection -->
                    if (local_seq_tmp > (info.channel[chan_num].local_seq_num_recv + 1)) {
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "loss was %"PRId16"", info.channel[chan_num].packet_loss_counter);
#endif
                        
                        info.channel[chan_num].packet_loss_counter += (((int32_t) local_seq_tmp)
                                - ((int32_t) (info.channel[chan_num].local_seq_num_recv + 1)));
                        if(info.channel[chan_num].local_seq_num_beforeloss == 0) {
                            info.channel[chan_num].local_seq_num_beforeloss = info.channel[chan_num].local_seq_num_recv;
                        }

//#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "loss calced seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"",
                                    info.channel[chan_num].local_seq_num_recv, local_seq_tmp, info.channel[chan_num].packet_loss_counter, seq_num);
//#endif
                        if (local_seq_tmp > (info.channel[chan_num].local_seq_num_recv + 1000)) {
                            vtun_syslog(LOG_ERR, "BROKEN PKT TYPE 2 RECEIVED: seq was %"PRIu32" now %"PRIu32" loss is %"PRId16"", info.channel[chan_num].local_seq_num_recv,
                                local_seq_tmp, info.channel[chan_num].packet_loss_counter);
                        }
                    } else if (local_seq_tmp < info.channel[chan_num].local_seq_num_recv) {
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "loss was %"PRId16"", info.channel[chan_num].packet_loss_counter);
#endif
                        info.channel[chan_num].packet_loss_counter--;
//#ifdef DEBUGG

                        vtun_syslog(LOG_INFO, "loss calced seq was %"PRIu32" now %"PRIu32" loss is %"PRId16" seq_num is %"PRIu32"", info.channel[chan_num].local_seq_num_recv,
                                local_seq_tmp, (int)info.channel[chan_num].packet_loss_counter, seq_num);
//#endif
                    }

                    // this is normal operation -->
                    if (local_seq_tmp > info.channel[chan_num].local_seq_num_recv) {
                        info.channel[chan_num].local_seq_num_recv = local_seq_tmp;
                    }

                    info.channel[chan_num].packet_recv_counter++;
#ifdef DEBUGG
                    vtun_syslog(LOG_INFO, "Receive frame ... chan %d local seq %"PRIu32" seq_num %"PRIu32" recv counter  %"PRIu16" len %d loss is %"PRId16"", chan_num, info.channel[chan_num].local_seq_num_recv,seq_num, info.channel[chan_num].packet_recv_counter, len, (int16_t)info.channel[chan_num].packet_loss_counter);
#endif
                    // introduced virtual chan_num to be able to process
                    //    congestion-avoided priority resend frames
                    if(chan_num == 0) { // reserved aux channel
                         if(flag_var == 0) { // this is a workaround for some bug... TODO!!
                              vtun_syslog(LOG_ERR,"BUG! flag_var == 0 received on chan 0! sqn %"PRIu32", len %d. DROPPING",seq_num, len);
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
                    sem_wait(write_buf_sem);
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
                        sem_wait(write_buf_sem);
                        for (int i = 0; i < (buf_len / alive_physical_channels); i++) {
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
                    if(cond_flag) {
                        sem_wait(write_buf_sem);
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "sending FRAME_LAST_WRITTEN_SEQ lws %"PRIu32" chan %d", shm_conn_info->write_buf[chan_num_virt].last_written_seq, chan_num_virt);
#endif
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


/*
        gettimeofday(&info.current_time, NULL);

        my_max_send_q = info.channel[my_max_send_q_chan_num].send_q;

        bytes_pass = 0;

        timersub(&info.current_time, &info.channel[my_max_send_q_chan_num].send_q_time, &t_tv);
        //bytes_pass = time_sub_tmp.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].ACK_speed_avg
        //        + (time_sub_tmp.tv_usec * info.channel[my_max_send_q_chan_num].ACK_speed_avg) / 1000;
        bytes_pass = t_tv.tv_sec * 1000 * info.channel[my_max_send_q_chan_num].packet_recv_upload
                + (t_tv.tv_usec * info.channel[my_max_send_q_chan_num].packet_recv_upload) / 1000;

        send_q_eff =
            (my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000) > bytes_pass ?
                    my_max_send_q + info.channel[my_max_send_q_chan_num].bytes_put * 1000 - bytes_pass : 0;

        max_chan=info.process_num;
        max_speed=0;
        min_speed=(UINT32_MAX - 1);
        sem_wait(&(shm_conn_info->AG_flags_sem));
        chan_mask = shm_conn_info->channels_mask;
        sem_post(&(shm_conn_info->AG_flags_sem));

        sem_wait(&(shm_conn_info->stats_sem));
        shm_conn_info->stats[info.process_num].max_send_q = send_q_eff;

        for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
            if (chan_mask & (1 << i)) {
                //vtun_syslog(LOG_INFO, "send_q  %"PRIu32" rtt %d", shm_conn_info->stats[i].max_send_q, shm_conn_info->stats[i].rtt_phys_avg);
                if (shm_conn_info->stats[i].rtt_phys_avg == 0) {
                    continue;
                }
                if (((shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[i].rtt_phys_avg) > max_speed) {
                    max_speed = (shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[i].rtt_phys_avg;
                    max_chan = i;
                }
                if (((shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[i].rtt_phys_avg) < min_speed) {
                    min_speed = (shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[i].rtt_phys_avg;
                }
            }

        }
        if (info.process_num == 0)
            info.C = C_HI;
        else
            info.C = C_LOW/2;


        if ((min_speed != (UINT32_MAX - 1)) && (shm_conn_info->stats[info.process_num].rtt_phys_avg != 0)) {

            if (max_speed == (shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[info.process_num].rtt_phys_avg) {
            //    info.C = C_HI;
                i_am_max = 1;
            } else if (min_speed
                    == (shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[info.process_num].rtt_phys_avg) {
              //  info.C = C_LOW/2;
            } else {
               // info.C = C_MED/2;
            }
            if (((shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[info.process_num].rtt_phys_avg) == max_speed) {
                info.send_q_limit = 140000; //(shm_conn_info->stats[max_chan].max_send_q / max_speed);
            } else {
                info.send_q_limit = (shm_conn_info->stats[max_chan].max_send_q
                        * ((shm_conn_info->stats[info.process_num].max_send_q * 1000) / shm_conn_info->stats[info.process_num].rtt_phys_avg)
                        / max_speed);

            }
        }
        sem_post(&(shm_conn_info->stats_sem));

        timersub(&(info.current_time), &loss_time, &t_tv);
        t = t_tv.tv_sec * 1000 + t_tv.tv_usec/1000;
        t = t / 100;
        t = t > 2000 ? 2000 : t; // 200s limit
        K = cbrt((((double) info.send_q_limit_cubic_max) * info.B) / info.C);
        limit_last = info.send_q_limit_cubic;
        info.send_q_limit_cubic = (uint32_t) (info.C * pow(((double) (t)) - K, 3) + info.send_q_limit_cubic_max);

        send_q_limit_cubic_apply = info.send_q_limit_cubic > 90000 ? 90000 : info.send_q_limit_cubic;

        hold_mode_previous = hold_mode;
        if ((my_max_send_q < send_q_limit_cubic_apply)) {
            hold_mode = 0;
        } else {
            ho//ld_mode = 1;
        }
        if ((hold_mode_previous != hold_mode) && (hold_mode == 1) && (info.process_num == 0)) {
            drop_packet_flag = 1;
            info.channel[my_max_send_q_chan_num].packet_loss++;
        } else {
            drop_packet_flag = 0;
        }
        if (check_timer(cubic_log_timer)) {
            update_timer(cubic_log_timer);
            vtun_syslog(LOG_INFO,
                    "{\"cubic_info\":\"0\",\"name\":\"%s\", \"s_q_l\":\"%"PRIu32"\", \"W_cubic\":\"%"PRIu32"\", \"W_max\":\"%"PRIu32"\", \"s_q_e\":\"%"PRIu32"\", \"s_q\":\"%"PRIu32"\", \"loss\":\"%"PRId16"\", \"hold_mode\":\"%d\", \"max_chan\":\"%d\", \"process\":\"%d\", \"buf_len\":\"%d\", \"drop\":\"%d\", \"time\":\"%d\"}",
                    lfd_host->host, info.send_q_limit, send_q_limit_cubic_apply, info.send_q_limit_cubic_max, send_q_eff, my_max_send_q,
                    info.channel[my_max_send_q_chan_num].packet_loss, hold_mode, max_chan, info.process_num, miss_packets_max, drop_packet_flag, t);
        } else if ((info.channel[my_max_send_q_chan_num].packet_loss != 0) || (drop_packet_flag != 0) || (hold_mode_previous != hold_mode)) {
            vtun_syslog(LOG_INFO,
                    "{\"cubic_info\":\"0\",\"name\":\"%s\", \"s_q_l\":\"%"PRIu32"\", \"W_cubic\":\"%"PRIu32"\", \"W_max\":\"%"PRIu32"\", \"s_q_e\":\"%"PRIu32"\", \"s_q\":\"%"PRIu32"\", \"loss\":\"%"PRId16"\", \"hold_mode\":\"%d\", \"max_chan\":\"%d\", \"process\":\"%d\", \"buf_len\":\"%d\", \"drop\":\"%d\", \"time\":\"%d\"}",
                    lfd_host->host, info.send_q_limit, send_q_limit_cubic_apply, info.send_q_limit_cubic_max, send_q_eff, my_max_send_q,
                    info.channel[my_max_send_q_chan_num].packet_loss, hold_mode_previous, max_chan, info.process_num, miss_packets_max, drop_packet_flag, t);
            vtun_syslog(LOG_INFO,
                    "{\"cubic_info\":\"0\",\"name\":\"%s\", \"s_q_l\":\"%"PRIu32"\", \"W_cubic\":\"%"PRIu32"\", \"W_max\":\"%"PRIu32"\", \"s_q_e\":\"%"PRIu32"\", \"s_q\":\"%"PRIu32"\", \"loss\":\"%"PRId16"\", \"hold_mode\":\"%d\", \"max_chan\":\"%d\", \"process\":\"%d\", \"buf_len\":\"%d\", \"drop\":\"%d\", \"time\":\"%d\"}",
                    lfd_host->host, info.send_q_limit, send_q_limit_cubic_apply, info.send_q_limit_cubic_max, send_q_eff, my_max_send_q,
                    info.channel[my_max_send_q_chan_num].packet_loss, hold_mode, max_chan, info.process_num, miss_packets_max, drop_packet_flag, t);

        }


*/

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
        //if (ag_flag_local == R_MODE) {
        if(1) {
            len = retransmit_send(out2);
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
                len = select_devread_send(buf, out2);
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
            len = select_devread_send(buf, out2);
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
        sem_post(&shm_conn_info->hard_sem);
            //Check time interval and ping if need.
        if (((info.current_time.tv_sec - last_ping) > lfd_host->PING_INTERVAL) && (len <= 0)) {
				ping_rcvd = 0;
				gettimeofday(&info.current_time, NULL);

				last_ping = info.current_time.tv_sec;
#ifdef DEBUGG
				vtun_syslog(LOG_INFO, "PING2");
#endif
				// ping ALL channels! this is required due to 120-sec limitation on some NATs
            for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                ping_req_ts[i] = info.current_time.tv_sec * 1000 + info.current_time.tv_usec / 1000; //save time
                int len_ret;
                if (i == 0) {
                    len_ret = proto_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                } else {
                    // send ping request - 2
                    len_ret = udp_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
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
    sem_post(&(shm_conn_info->AG_flags_sem));
#ifdef JSON
    vtun_syslog(LOG_INFO,"{\"name\":\"%s\",\"exit\":1}", lfd_host->host);
#endif

    vtun_syslog(LOG_INFO, "process_name - %s p_chan_num : %i,  exiting linker loop", lfd_host->host, info.process_num);
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
    lfd_free(buf);
    lfd_free(out_buf);

    for (i = 0; i < info.channel_amount; i++) {
        close(info.channel[i].descriptor);
    }
    close(prio_s);

    if(linker_term == TERM_NONFATAL) linker_term = 0; // drop nonfatal flag

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
    memset(last_sent_packet_num, 0, sizeof(struct last_sent_packet) * MAX_TCP_LOGICAL_CHANNELS);
    memset(&info, 0, sizeof(struct phisical_status));
    rxmt_mode_request = 0; // flag
    weight = 0; // bigger weight more time to wait(weight == penalty)
    weight_cnt = 0;
    acnt = 0; // assert variable

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
    info.check_shm = 1;
    struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup, sa_oldusr1;
    int old_prio;
    /** Global initialization section for variable and another things*/

    lfd_host = host;
    info.srv = ss;
    shm_conn_info = ci;
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
