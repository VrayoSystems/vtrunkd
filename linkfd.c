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
#include "weight_calculation.h"
#include "net_structs.h"
#include "netlib.h"
#include "netlink_socket_info.h"
#include "speed_algo.h"

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

#define SEND_Q_LIMIT_MINIMAL 10000
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

// these are for retransmit mode... to be removed
short retransmit_count = 0;
char channel_mode = MODE_NORMAL;
int hold_mode = 0; // 1 - hold 0 - normal
int force_hold_mode = 1;
int buf_len, incomplete_seq_len = 0, rtt = 0, rtt_old=0, rtt_old_old=0;
int16_t my_miss_packets_max = 0; // in ms; calculated here
int16_t miss_packets_max = 0; // get from another side
int proto_err_cnt = 0;
int my_max_send_q_chan_num = 0;
uint32_t my_max_send_q = 0, max_reorder_byte = 0;
uint32_t last_channels_mask = 0;

/*Variables for the exact way of measuring speed*/
struct timeval send_q_read_time, send_q_read_timer = {0,0}, send_q_read_drop_time = {0, 100000}, send_q_mode_switch_time = {0,0};
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

struct time_lag_info time_lag_info_arr[MAX_TCP_LOGICAL_CHANNELS];
struct time_lag time_lag_local;
struct timeval cur_time; // current time source

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
       fprintf(lfd_host->stat.file,"%s %lu %lu %lu %lu\n", stm,
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
int missing_resend_buffer (int chan_num, unsigned long buf[], int *buf_len) {
    int i = shm_conn_info->write_buf[chan_num].frames.rel_head, n;
    unsigned long isq,nsq, k;
    int idx=0;
    int blen=0, lws, chs;

    if(i == -1) {
        *buf_len = 0;
        return 0;
    }

    lws = shm_conn_info->write_buf[chan_num].last_written_seq;
    chs = shm_conn_info->frames_buf[i].seq_num;


    if(  ( (chs - lws) >= FRAME_BUF_SIZE) || ( (lws - chs) >= FRAME_BUF_SIZE)) { // this one will not happen :-\
        vtun_syslog(LOG_ERR, "WARNING: frame difference too high: last w seq: %lu fbhead: %lu . FIXED. chs %d<->%d lws cn %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->write_buf[chan_num].frames_buf[i].seq_num, chs, lws, chan_num);
        shm_conn_info->write_buf[chan_num].last_written_seq = shm_conn_info->frames_buf[i].seq_num-1;
    }

    // fix for diff btw start
    for(k=1; k<(shm_conn_info->frames_buf[i].seq_num - shm_conn_info->write_buf[chan_num].last_written_seq); k++) {
        buf[idx] = shm_conn_info->write_buf[chan_num].last_written_seq + k;
        idx++;
        //vtun_syslog(LOG_INFO, "MRB: found in start : tot %d", idx);
        if(idx >= FRAME_BUF_SIZE) {
            vtun_syslog(LOG_ERR, "WARNING: MRB2 frame difference too high: last w seq: %lu fbhead: %lu . FIXED. chs %d<->%d lws ch %d", shm_conn_info->write_buf[chan_num].last_written_seq, shm_conn_info->frames_buf[i].seq_num, chs, lws, chan_num);
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
            //vtun_syslog(LOG_INFO, "MRB: scan2 %lu > %lu +1 ?", nsq, isq);
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
    for (int i = 0; i < info.channel_amount; i++) {
        if ((shm_conn_info->write_buf[i].frames.rel_head != -1) && (shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].seq_num == (shm_conn_info->write_buf[i].last_written_seq + 1))) {
#ifdef DEBUGG
                    vtun_syslog(LOG_INFO, "AAAAA select skip.. Data ready to be written on chan %d seq_num: %lu", i, shm_conn_info->frames_buf[shm_conn_info->write_buf[i].frames.rel_head].seq_num);
#endif
            return 1;
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

int get_resend_frame(int conn_num, unsigned long seq_num, char **out, int *sender_pid) {
    int i, len = -1;
    // TODO: we should be searching from most probable start place
    //   not to scan through the whole buffer to the end
    for(i=0; i<RESEND_BUF_SIZE; i++) { 
        if( (shm_conn_info->resend_frames_buf[i].seq_num == seq_num) &&
                (shm_conn_info->resend_frames_buf[i].chan_num == conn_num)) {

            len = shm_conn_info->resend_frames_buf[i].len;
            *((unsigned short *)(shm_conn_info->resend_frames_buf[i].out+LINKFD_FRAME_RESERV + (len-sizeof(unsigned short)))) = htons(conn_num + FLAGS_RESERVED); // WAS: channel-mode. TODO: RXMIT mode broken HERE!! // clean flags?
            *out = shm_conn_info->resend_frames_buf[i].out+LINKFD_FRAME_RESERV;
            *sender_pid = shm_conn_info->resend_frames_buf[i].sender_pid;
            break;
        }
    }
    return len;
}

int get_last_packet_seq_num(int chan_num, unsigned long *seq_num) {
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

int get_oldest_packet_seq_num(int chan_num, unsigned long *seq_num) {
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

int seqn_break_tail(char *out, int len, unsigned long *seq_num, unsigned short *flag_var) {
    *seq_num = ntohl(*((unsigned long *)(&out[len-sizeof(unsigned long)-sizeof(unsigned short)])));
    *flag_var = ntohs(*((unsigned short *)(&out[len-sizeof(unsigned short)])));
    return len-sizeof(unsigned long)-sizeof(unsigned short);
}

/**
 * Function for add flag and seq_num to packet
 */
int pack_packet(char *buf, int len, unsigned long seq_num, int flag) {
    unsigned long seq_num_n = htonl(seq_num);
    unsigned short flag_n = htons(flag);
    memcpy(buf + len, &seq_num_n, sizeof(unsigned long));
    memcpy(buf + len + sizeof(unsigned long), &flag_n, sizeof(unsigned short));
    return len + sizeof(unsigned long) + sizeof(unsigned short);
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
void seqn_add_tail(int conn_num, char *buf, int len, unsigned long seq_num, unsigned short flag, int sender_pid) {
    int newf = shm_conn_info->resend_buf_idx;

    shm_conn_info->resend_buf_idx++;
    if (shm_conn_info->resend_buf_idx == RESEND_BUF_SIZE) {
        vtun_syslog(LOG_INFO, "seqn_add_tail() resend_frames_buf loop end");
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
int add_fast_resend_frame(int conn_num, char *buf, int len, unsigned long seq_num) {
    if (shm_conn_info->fast_resend_buf_idx >= MAX_TCP_PHYSICAL_CHANNELS) {
        return -1; // fast_resend_buf is full
    }
    int i = shm_conn_info->fast_resend_buf_idx; // get next free index
    ++(shm_conn_info->fast_resend_buf_idx);
    unsigned short flag = MODE_NORMAL;
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
int get_fast_resend_frame(int *conn_num, char *buf, int *len, unsigned long *seq_num) {
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

/**
 * Function for trying resend
 */ 
int retransmit_send(char *out2) {
    if (hold_mode) {
        return CONTINUE_ERROR;
    }
    int len = 0, send_counter = 0, mypid;
    unsigned long top_seq_num, seq_num_tmp = 1, remote_lws = SEQ_START_VAL;
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
           vtun_syslog(LOG_INFO, "debug: retransmit_send skipping logical channel #%i my last seq_num %lu top seq_num %lu", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
            // TODO MOVE THE FOLLOWING LINE TO DEBUG! --vvv
            if (top_seq_num < last_sent_packet_num[i].seq_num) vtun_syslog(LOG_INFO, "WARNING! impossible: chan#%i last sent seq_num %lu is > top seq_num %lu", i, last_sent_packet_num[i].seq_num, top_seq_num);
           continue;
        }
        last_sent_packet_num[i].seq_num++;
 

#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: logical channel #%i my last seq_num %lu top seq_num %lu", i, last_sent_packet_num[i].seq_num, top_seq_num);
#endif
        sem_wait(&(shm_conn_info->resend_buf_sem));
        len = get_resend_frame(i, last_sent_packet_num[i].seq_num, &out2, &mypid);
          if (len == -1) {
            int succ = get_oldest_packet_seq_num(i, &seq_num_tmp);
            if (succ == -1) {
                sem_post(&(shm_conn_info->resend_buf_sem));
                last_sent_packet_num[i].seq_num = top_seq_num;
                vtun_syslog(LOG_INFO, "R_MODE can't found frame for chan %d seq %lu ... continue", i, last_sent_packet_num[i].seq_num);
                continue;
            }
            last_sent_packet_num[i].seq_num = seq_num_tmp;
            len = get_resend_frame(i, last_sent_packet_num[i].seq_num, &out2, &mypid);
        }
        if (len == -1) {
            sem_post(&(shm_conn_info->resend_buf_sem));
            vtun_syslog(LOG_ERR, "ERROR R_MODE can't found frame for chan %d seq %lu ... continue", i, last_sent_packet_num[i].seq_num);
            last_sent_packet_num[i].seq_num = top_seq_num;
            continue;
        }
        memcpy(out_buf, out2, len);
        sem_post(&(shm_conn_info->resend_buf_sem));
        if (last_sent_packet_num[i].num_resend == 0) {
            last_sent_packet_num[i].num_resend++;
            vtun_syslog(LOG_INFO, "Resend frame ... chan %d start for seq %lu len %d", i, last_sent_packet_num[i].seq_num, len);
        }
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: R_MODE resend frame ... chan %d seq %lu len %d", i, last_sent_packet_num[i].seq_num, len);
#endif
        statb.bytes_sent_rx += len;
        int len_ret = proto_write(info.channel[i].descriptor, out_buf, len);
        if ((len && len_ret) < 0) {
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", i, strerror(errno), errno);
#endif
            return CONTINUE_ERROR;
        }
        send_counter++;
        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
        info.channel[i].up_len += len_ret;
        info.byte_r_mode += len_ret;
    }
    
    if (send_counter == 0) 
        return LASTPACKETMY_NOTIFY;
        
    return 1;
}

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
    unsigned long tmp_seq_counter = 0;
    int chan_num;
    struct my_ip *ip;
    struct tcphdr *tcp;
    struct timeval tv;
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
        len = pack_packet(buf, len, tmp_seq_counter, channel_mode);
    }
#ifdef DEBUGG
    else {
        vtun_syslog(LOG_INFO, "Trying to send from fast resend buf chan_num - %i, len - %i, seq - %lu, packet amount - %i", chan_num, len, tmp_seq_counter, idx);
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
    vtun_syslog(LOG_INFO, "select_devread_send() frame ... chan %d seq %lu len %d", chan_num, tmp_seq_counter, len);
#endif
    struct timeval send1; // need for mean_delay calculation (legacy)
    struct timeval send2; // need for mean_delay calculation (legacy)
    gettimeofday(&send1, NULL );
    int len_ret = proto_write(info.channel[chan_num].descriptor, buf, len);
    if ((len && len_ret) < 0) {
        vtun_syslog(LOG_INFO, "error write to socket chan %d! reason: %s (%d)", chan_num, strerror(errno), errno);
        return BREAK_ERROR;
    }
    gettimeofday(&send2, NULL );

    delay_acc += (int) ((send2.tv_sec - send1.tv_sec) * 1000000 + (send2.tv_usec - send1.tv_usec)); // need for mean_delay calculation (legacy)
    delay_cnt++; // need for mean_delay calculation (legacy)
#ifdef DEBUGG
    if((delay_acc/delay_cnt) > 100) vtun_syslog(LOG_INFO, "SEND DELAY: %u us", (delay_acc/delay_cnt));
#endif

    shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].up_data_len_amt += len_ret;
    info.channel[chan_num].up_len += len_ret;
    info.byte_efficient += len_ret;

    last_sent_packet_num[chan_num].seq_num = tmp_seq_counter;
//    last_sent_packet_num[chan_num].num_resend = 0;
    return len;
}

int write_buf_add(int conn_num, char *out, int len, unsigned long seq_num, unsigned long incomplete_seq_buf[], int *buf_len, int mypid, char *succ_flag) {
    char *ptr;
    int mlen = 0;
#ifdef DEBUGG
    vtun_syslog(LOG_INFO, "write_buf_add called! len %d seq_num %lu chan %d", len, seq_num, conn_num);
#endif
    // place into correct position first..
    int i = shm_conn_info->write_buf[conn_num].frames.rel_head, n;
    int newf;
    unsigned long istart;
    int j=0;
/*
    if(conn_num <= 0) { // this is a workaround for some bug... TODO!!
            vtun_syslog(LOG_INFO, "BUG! write_buf_add called with broken chan_num %d: seq_num %lu len %d", conn_num, seq_num, len );
            *succ_flag = -2;
            return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
    }
 */
    if (( (seq_num > shm_conn_info->write_buf[conn_num].last_written_seq) &&
            (seq_num - shm_conn_info->write_buf[conn_num].last_written_seq) >= STRANGE_SEQ_FUTURE ) ||
            ( (seq_num < shm_conn_info->write_buf[conn_num].last_written_seq) &&
              (shm_conn_info->write_buf[conn_num].last_written_seq - seq_num) >= STRANGE_SEQ_PAST )) { // this ABS comparison makes checks in MRB unnesesary...
        vtun_syslog(LOG_INFO, "WARNING! DROP BROKEN PKT logical channel %i seq_num %lu lws %lu; diff is: %d >= 1000", conn_num, seq_num, shm_conn_info->write_buf[conn_num].last_written_seq, (seq_num - shm_conn_info->write_buf[conn_num].last_written_seq));
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
        vtun_syslog(LOG_INFO, "drop dup pkt seq_num %lu lws %lu", seq_num, shm_conn_info->write_buf[conn_num].last_written_seq);
#endif
        *succ_flag = -2;
        return missing_resend_buffer (conn_num, incomplete_seq_buf, buf_len);
    }
    // now check if we can find it in write buf current .. inline!
    acnt = 0;
    while( i > -1 ) {
        if(shm_conn_info->frames_buf[i].seq_num == seq_num) {
            vtun_syslog(LOG_INFO, "drop exist pkt seq_num %lu sitting in write_buf chan %i", seq_num, conn_num);
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
    //vtun_syslog(LOG_INFO, "TESTT %d lws: %lu", 12, shm_conn_info->write_buf.last_written_seq);
    shm_conn_info->frames_buf[newf].seq_num = seq_num;
    memcpy(shm_conn_info->frames_buf[newf].out, out, len);
    shm_conn_info->frames_buf[newf].len = len;
    shm_conn_info->frames_buf[newf].sender_pid = mypid;
    shm_conn_info->frames_buf[newf].physical_channel_num = info.process_num;
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
int check_sent (unsigned long seq_num, struct resent_chk sq_rq_buf[], int *sq_rq_pos, int chan_num) {
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
        vtun_syslog(LOG_INFO, "Process %i logic channel - %i lport - %i %i", info.process_num, i, chan_info[i].rport, info.channel[i].rport);
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

    gettimeofday(&(info.get_tcp_info_time), NULL);
    if(!get_format_tcp_info(chan_info, info.channel_amount)) {
        /*TODO may be need add error counter, because if we have one error
         * we can use previos values. But if we have two error running
         * we should take action */
        vtun_syslog(LOG_ERR, "Ag switcher - netlink return error");
    }
    /*find my max send_q*/
    my_max_send_q = 0;
    for (int i = 0; i < info.channel_amount; i++) {
#ifdef TRACE
        vtun_syslog(LOG_INFO, "Recv-Q %u Send-Q %u Logical channel %i", chan_info[i].recv_q, chan_info[i].send_q, i);
#endif
        if ((my_max_send_q < chan_info[i].send_q) && (i != 0)) {
            my_max_send_q = chan_info[i].send_q;
            my_max_send_q_chan_num = i;
        }
        info.channel[i].send_q = chan_info[i].send_q;
#ifdef TRACE
    vtun_syslog(LOG_INFO,"sended_bytes - %u",info.channel[i].up_len);
#endif
    }
    info.max_send_q_avg =
            info.max_send_q_avg > my_max_send_q ?
                    info.max_send_q_avg - (info.max_send_q_avg - my_max_send_q) / 4 : info.max_send_q_avg + (my_max_send_q - info.max_send_q_avg) / 4;
#if !defined(DEBUGG)
    info.max_send_q_max = my_max_send_q > info.max_send_q_max ? my_max_send_q : info.max_send_q_max;
    info.max_send_q_min = my_max_send_q < info.max_send_q_min ? my_max_send_q : info.max_send_q_min;
#endif
    /* store my max send_q in shm */
    sem_wait(&(shm_conn_info->stats_sem));
    shm_conn_info->stats[info.process_num].max_send_q = my_max_send_q;
    shm_conn_info->stats[info.process_num].max_send_q_avg = info.max_send_q_avg;
    sem_post(&(shm_conn_info->stats_sem));

    int speed_success = 0;

    /* ACK_coming_speed recalculation */
    int skip_time_usec = magic_rtt_avg / 10 * 1000;
    skip_time_usec = skip_time_usec > 999000 ? 999000 : skip_time_usec;
    skip_time_usec = skip_time_usec < 5000 ? 5000 : skip_time_usec;
    for (int i = 0; i < info.channel_amount; i++) {
        int ACK_coming_speed = speed_algo_ack_speed(&(info.channel[i].get_tcp_info_time_old), &(info.get_tcp_info_time), info.channel[i].send_q_old,
                info.channel[i].send_q, info.channel[i].up_len, skip_time_usec);
        if ((ACK_coming_speed >= 0) || (ACK_coming_speed == SPEED_ALGO_OVERFLOW) || (ACK_coming_speed == SPEED_ALGO_EPIC_SLOW)) {
            if (ACK_coming_speed >= 0) {
                info.channel[i].ACK_speed_avg += (ACK_coming_speed - info.channel[i].ACK_speed_avg) / 4;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "ACK_speed_avg %u logical channel %i", info.channel[i].ACK_speed_avg, i);
#endif
            } else if (ACK_coming_speed == SPEED_ALGO_OVERFLOW) {
                vtun_syslog(LOG_ERR, "WARNING - sent_bytes value is overflow, zeroing ACK_coming_speed");
                info.channel[i].ACK_speed_avg -= info.channel[i].ACK_speed_avg / 4;
            } else if (ACK_coming_speed == SPEED_ALGO_EPIC_SLOW) {
#ifdef DEBUGG
                vtun_syslog(LOG_ERR, "WARNING - Speed was slow much time logical channel %i", i);
#endif
                info.channel[i].ACK_speed_avg = 0;
            }
            memcpy(&(info.channel[i].get_tcp_info_time_old), &(info.get_tcp_info_time), sizeof(info.get_tcp_info_time));
            info.channel[i].send_q_old = info.channel[i].send_q;
            info.channel[i].up_len = 0;
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

    if (speed_success) {
        ACK_coming_speed_avg = info.channel[my_max_send_q_chan_num].ACK_speed_avg;
        magic_rtt_avg = info.channel[my_max_send_q_chan_num].magic_rtt;
        sem_wait(&(shm_conn_info->AG_flags_sem));
        uint32_t chan_mask = shm_conn_info->channels_mask;
        sem_post(&(shm_conn_info->AG_flags_sem));
        sem_wait(&(shm_conn_info->stats_sem));
        shm_conn_info->stats[info.process_num].ACK_speed = info.channel[my_max_send_q_chan_num].ACK_speed_avg;
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
        if (high_speed_chan == info.process_num) {
            sem_wait(&(shm_conn_info->AG_flags_sem));
            shm_conn_info->AG_ready_flag = ACK_coming_speed_avg > ((chan_info[my_max_send_q_chan_num].send * (1 - AG_FLOW_FACTOR)) / 1000) ? AG_MODE : R_MODE;
            sem_post(&(shm_conn_info->AG_flags_sem));
        }

        int ACK_speed_high_speed = shm_conn_info->stats[high_speed_chan].ACK_speed == 0 ? 1 : shm_conn_info->stats[high_speed_chan].ACK_speed;
        int EBL = (90 - (int) miss_packets_max) * 1300;
        if (high_speed_chan == info.process_num) {
            send_q_limit_grow = (EBL - send_q_limit) / 2;
        } else {
            // TODO: use WEIGHT_SCALE config variable instead of '100'. Current scale is 2 (100).
            send_q_limit_grow = (((((int) (shm_conn_info->stats[high_speed_chan].max_send_q_avg)) * shm_conn_info->stats[info.process_num].ACK_speed)
                    / ACK_speed_high_speed) - send_q_limit) / 2;
        }
        sem_post(&(shm_conn_info->stats_sem));
        send_q_limit_grow = send_q_limit_grow > 20000 ? 20000 : send_q_limit_grow;
        send_q_limit += send_q_limit_grow;
        send_q_limit = send_q_limit < 20 ? 20 : send_q_limit;
    }

    int hold_mode_previous = hold_mode;
    if ((((int) my_max_send_q) < send_q_limit)) {
        hold_mode = 0;
    } else {
        hold_mode = 1;
        force_hold_mode = 0;
    }

    max_reorder_byte = lfd_host->MAX_REORDER * chan_info[my_max_send_q_chan_num].mss;
    uint32_t send_q_c = chan_info[my_max_send_q_chan_num].mss * chan_info[my_max_send_q_chan_num].cwnd;
#if defined(DEBUGG) && defined(JSON)
    vtun_syslog(LOG_INFO,
            "{\"p_chan_num\":%i,\"name\":\"%s\",\"l_chan_num\":%i,\"max_reorder_byte\":%u,\"s_q_lim\":%i,\"s_q\":%u,\"s_q_min\":120000,\"rtt\":%f,\"rtt_var\":%f,\"my_rtt\":%i,\"magic_rtt\":%i,\"cwnd\":%u,\"isl\":%i,\"rxmits\":%i,\"r_buf_len\":%i,\"magic_upload\":%i,\"upload\":%i,\"download\":%i,\"hold_mode\":%i,\"ACS\":%u,\"R_MODE\":%i, \"AG_ready_flag\":%i, \"my_max_send_q_avg\":%u,\"buf_len\":%i, \"s_e\":%u, \"s_r_m\":%u, \"s_r\":%u}",
            info.process_num, lfd_host->host, my_max_send_q_chan_num, max_reorder_byte, send_q_limit, my_max_send_q, chan_info[my_max_send_q_chan_num].rtt,
            chan_info[my_max_send_q_chan_num].rtt_var, rtt, magic_rtt_avg, chan_info[my_max_send_q_chan_num].cwnd, incomplete_seq_len, statb.rxmits, buf_len,
            chan_info[my_max_send_q_chan_num].send,
            shm_conn_info->stats[info.process_num].speed_chan_data[my_max_send_q_chan_num].up_current_speed,
            shm_conn_info->stats[info.process_num].speed_chan_data[my_max_send_q_chan_num].down_current_speed, hold_mode, ACK_coming_speed_avg, info.mode, shm_conn_info->AG_ready_flag, info.max_send_q_avg, shm_conn_info->miss_packets_max, info.speed_efficient, info.speed_r_mode, info.speed_resend);
#endif
    if (send_q_limit > SEND_Q_LIMIT_MINIMAL) {
        return AG_MODE;
    }
    return R_MODE;
}

int lfd_linker(void)
{
    int service_channel = lfd_host->rmt_fd; //aka channel 0
    int len, len1, fl;
    int err=0;
    struct timeval tv;
    char *out, *out2 = NULL;
    char *buf; // in common for info packet
    unsigned long int seq_num;

    int maxfd;
    int imf;
    int fprev = -1;
    int fold = -1;
    unsigned long incomplete_seq_buf[FRAME_BUF_SIZE];
    send_q_limit = START_SQL; // was 55000
    
    unsigned short tmp_s;
    unsigned long tmp_l;

    sem_t *resend_buf_sem = &(shm_conn_info->resend_buf_sem);
    sem_t *write_buf_sem = &(shm_conn_info->write_buf_sem);

    struct timeval send1; // calculate send delay
    struct timeval send2;

    long int last_action = 0; // for ping; TODO: too many vars... this even has clone ->
    long int last_net_read = 0; // for timeout;

    struct resent_chk sq_rq_buf[RESENT_MEM]; // for check_sent
    int sq_rq_pos = 0; // for check_sent

    unsigned short flag_var; // packet struct part

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

    unsigned long last_last_written_seq[MAX_TCP_LOGICAL_CHANNELS]; // for LWS notification TODO: move this to write_buf!

    // ping stats
    long int ping_req_ts = 0;
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

    if( !(buf = lfd_alloc(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker");
        return 0;
    }
    if( !(out_buf = lfd_alloc(VTUN_FRAME_SIZE2+200)) ) {
        vtun_syslog(LOG_ERR,"Can't allocate out buffer for the linker");
        return 0;
    }
    memset(time_lag_info_arr, 0, sizeof(struct time_lag_info) * MAX_TCP_LOGICAL_CHANNELS);
    memset(last_last_written_seq, 0, sizeof(long) * MAX_TCP_LOGICAL_CHANNELS);
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

    if(info.srv) {
        /** Server accepted all logical channel here and get and send pid */
        // now read one single byte
        vtun_syslog(LOG_INFO,"Waiting for client to request channels...");
		read_n(service_channel, buf, sizeof(uint16_t)+sizeof(uint16_t));
        info.channel_amount = ntohs(*((uint16_t *) buf)); // include info channel
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

        // try to bind to portnum my_num+smth:
        memset(&my_addr, 0, sizeof(my_addr));
        my_addr.sin_addr.s_addr = INADDR_ANY;
        memset(&rmaddr, 0, sizeof(rmaddr));
        my_addr.sin_family = AF_INET;
        if( (prio_s=socket(AF_INET,SOCK_STREAM,0))== -1 ) {
            vtun_syslog(LOG_ERR,"Can't create Channels socket");
            return -1;
        }
int res123 = 0;
 // Get buffer size
 socklen_t optlen = sizeof(sendbuff);
 res123 = getsockopt(prio_s, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

 if(res123 == -1)
     vtun_syslog(LOG_ERR,"Error getsockopt one");
 else
     vtun_syslog(LOG_INFO,"send buffer size = %d\n", sendbuff);

        prio_opt=1;
        setsockopt(prio_s, SOL_SOCKET, SO_REUSEADDR, &prio_opt, sizeof(prio_opt));

        if( bind(prio_s,(struct sockaddr *)&my_addr,sizeof(my_addr)) ) {
            vtun_syslog(LOG_ERR,"Can't bind to the Channels socket");
            return -1;
        }
        if( listen(prio_s, 10) ) {
            vtun_syslog(LOG_ERR,"Can't listen on the Channels socket");
            return -1;
        }


        // now get my port number
        laddrlen = sizeof(localaddr);
        if(getsockname(prio_s, (struct sockaddr *)(&localaddr), &laddrlen) < 0) {
            vtun_syslog(LOG_ERR,"My port socket getsockname error; retry %s(%d)",
                        strerror(errno), errno);
            close(prio_s);
            return 0;
        }

        vtun_syslog(LOG_INFO,"Prio bound to temp port %d; sending notification", ntohs(localaddr.sin_port));

	tmp_s = ntohs(localaddr.sin_port);

        *((unsigned long *)buf) = htonl((unsigned long)tmp_s); // already in htons format...
        *((unsigned short *)(buf+sizeof(unsigned long))) = htons(FRAME_PRIO_PORT_NOTIFY);
        if(proto_write(service_channel, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
            vtun_syslog(LOG_ERR, "Could not send FRAME_PRIO_PORT_NOTIFY pkt; exit %s(%d)",
                        strerror(errno), errno);
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
//            alarm(CHAN_START_ACCEPT_TIMEOUT);
            if( (fd_tmp=accept(prio_s,(struct sockaddr *)&cl_addr,&prio_opt)) < 0 ) {
                vtun_syslog(LOG_ERR,"Channels socket accept error %s(%d)",
                            strerror(errno), errno);
                break_out = 1;
                break;
            }
            alarm(0);

            prio_opt=1;
            setsockopt(fd_tmp,SOL_SOCKET,SO_KEEPALIVE,&prio_opt,sizeof(prio_opt) );

            prio_opt=1;
            setsockopt(fd_tmp,IPPROTO_TCP,TCP_NODELAY,&prio_opt,sizeof(prio_opt) );
            
            rmaddrlen = sizeof(rmaddr);

            if(getsockname(fd_tmp, (struct sockaddr *)(&rmaddr), &rmaddrlen) < 0) {
                vtun_syslog(LOG_ERR,"Channels socket getsockname error; retry %s(%d)",
                            strerror(errno), errno );

                break_out = 1;
                break;
            }
            if(getpeername(fd_tmp, (struct sockaddr *)(&rmaddr), &rmaddrlen) < 0) {
                vtun_syslog(LOG_ERR,"Channels socket getpeername error; retry %s(%d)",
                            strerror(errno), errno );
                break_out = 1;
                break;
            }
            inet_ntop(AF_INET, &rmaddr.sin_addr, ipstr, sizeof ipstr);
            if(inet_addr(lfd_host->sopt.raddr) != rmaddr.sin_addr.s_addr) {
                vtun_syslog(LOG_ERR,"Socket IP addresses do not match: %s != %s", lfd_host->sopt.raddr, ipstr);
                break_out = 1;
                break;
            }
            info.channel[i].descriptor=fd_tmp;
        }
        info.channel[0].descriptor = service_channel;
        for (i = 0; i < info.channel_amount; i++) {
            if (getpeername(info.channel[i].descriptor, (struct sockaddr *) (&rmaddr), &rmaddrlen) < 0) {
                vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                linker_term = TERM_NONFATAL;
                break;
            }
            info.channel[i].rport = ntohs(rmaddr.sin_port);
            vtun_syslog(LOG_ERR, "Socket peer IP channel - %i port - %i", i, info.channel[i].rport);
        }
        if(break_out) {
            close(prio_s);
            for(; i>=0; i--) {
                close(info.channel[i].descriptor);
            }
            linker_term = TERM_NONFATAL;
            alarm(0);
        }

        for(; i>=0; i--) {
            if (maxfd < info.channel[i].descriptor) {
                maxfd = info.channel[i].descriptor;
            }
        }

        // Server another init section
        gettimeofday(&(info.get_tcp_info_time), NULL );
        for (int i = 0; i < info.channel_amount; i++) {
            memcpy(&(info.channel[i].get_tcp_info_time_old), &(info.get_tcp_info_time), sizeof(info.channel[i].get_tcp_info_time_old));
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
#ifdef DEBUGG
 		vtun_syslog(LOG_ERR,"Remote pid - %d, local pid - %d", time_lag_local.pid_remote, time_lag_local.pid);
#endif
 		info.channel_amount = 1; // now we'll accumulate here established logical channels
    }

    // we start in a normal mode...
    if(channel_mode == MODE_NORMAL) {
        shm_conn_info->normal_senders++;
        vtun_syslog(LOG_INFO, "normal sender added: now %d", shm_conn_info->normal_senders);
    }

    sem_wait(&(shm_conn_info->AG_flags_sem));
    *((unsigned long *) buf) = htonl(shm_conn_info->session_hash_this);
    sem_post(&(shm_conn_info->AG_flags_sem));
    *((unsigned short *) (buf + sizeof(unsigned long))) = htons(FRAME_JUST_STARTED);
    if (proto_write(service_channel, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME)) < 0) {
        vtun_syslog(LOG_ERR, "Could not send init pkt; exit");
        linker_term = TERM_NONFATAL;
    }

    shm_conn_info->stats[info.process_num].weight = lfd_host->START_WEIGHT;
    
    gettimeofday(&cur_time, NULL);
    last_action = cur_time.tv_sec;
    last_net_read = cur_time.tv_sec;
    shm_conn_info->lock_time = cur_time.tv_sec;
    
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
    sem_wait(&(shm_conn_info->AG_flags_sem));
    last_channels_mask = shm_conn_info->channels_mask;
    sem_post(&(shm_conn_info->AG_flags_sem));
/**
 * Main program loop
 */
    while( !linker_term ) {
//        usleep(100); // todo need to tune; Is it necessary? I don't know
        errno = 0;
        gettimeofday(&cur_time, NULL);
        timersub(&cur_time, &get_info_time_last, &tv_tmp_tmp_tmp);
        int timercmp_result;
        timercmp_result = timercmp(&tv_tmp_tmp_tmp, &get_info_time, >=);
        int ag_switch_flag = 0;
        
        if ((dirty_seq_num % 6) == 0) {
            dirty_seq_num++;
            ag_switch_flag = 1;
        }
        
        if (timercmp_result || ag_switch_flag) {
            info.mode = ag_switcher();
            get_info_time_last.tv_sec = cur_time.tv_sec;
            get_info_time_last.tv_usec = cur_time.tv_usec;
#if !defined(DEBUGG) && defined(JSON)
            timersub(&cur_time, &json_timer, &tv_tmp_tmp_tmp);
            if (timercmp(&tv_tmp_tmp_tmp, &((struct timeval) {0, 500000}), >=)) {
                sem_wait(&(shm_conn_info->stats_sem));
                miss_packets_max = shm_conn_info->miss_packets_max;
                sem_post(&(shm_conn_info->stats_sem));
                vtun_syslog(LOG_INFO,
                        "{\"name\":\"%s\",\"s_q_lim\":%i,\"s_q\":%u,\"s_q_min\":%u,\"s_q_max\":%u,\"rtt\":%f,\"my_rtt\":%i,\"cwnd\":%u,\"isl\":%i,\"r_buf_len\":%i,\"upload\":%i,\"hold_mode\":%i,\"ACS\":%u,\"R_MODE\":%i,\"buf_len\":%i, \"s_e\":%u, \"s_r_m\":%u, \"s_r\":%u}",
                        lfd_host->host, send_q_limit, info.max_send_q_avg, info.max_send_q_min, info.max_send_q_max, chan_info[my_max_send_q_chan_num].rtt,
                        rtt, chan_info[my_max_send_q_chan_num].cwnd, incomplete_seq_len, buf_len,
                        shm_conn_info->stats[info.process_num].speed_chan_data[my_max_send_q_chan_num].up_current_speed,
                        hold_mode, ACK_coming_speed_avg, info.mode, miss_packets_max, info.speed_efficient, info.speed_r_mode, info.speed_resend);
                json_timer.tv_sec = cur_time.tv_sec;
                json_timer.tv_usec = cur_time.tv_usec;
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
        /* TODO write function for lws sending*/
        for (i = 0; i < info.channel_amount; i++) {
        sem_wait(&(shm_conn_info->write_buf_sem));
        unsigned long last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
        unsigned long last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
        sem_post(&(shm_conn_info->write_buf_sem));
            if ((last_written_seq_tmp > (last_last_written_seq[i] + LWS_NOTIFY_MAX_SUB_SEQ))) {
            // TODO: DUP code!
            sem_wait(&(shm_conn_info->write_buf_sem));
            *((unsigned long *) buf) = htonl(shm_conn_info->write_buf[i].last_written_seq);
            last_last_written_seq[i] = shm_conn_info->write_buf[i].last_written_seq;
            shm_conn_info->write_buf[i].last_lws_notified = cur_time.tv_sec;
            sem_post(&(shm_conn_info->write_buf_sem));
            *((unsigned short *) (buf + sizeof(unsigned long))) = htons(FRAME_LAST_WRITTEN_SEQ);
                int len_ret = proto_write(info.channel[i].descriptor, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                if (len_ret < 0) {
                vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                linker_term = TERM_NONFATAL;
            }
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                info.channel[i].up_len += len_ret;
        }
    }
          // do an expensive thing
          timersub(&cur_time, &last_timing, &tv_tmp);
          /**
           * This is the Tick module
           */
          if( timercmp(&tv_tmp, &timer_resolution, >=) ) {
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
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed = shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt
                        / time_passed;
                sem_post(&(shm_conn_info->stats_sem));
                shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt = 0;
                shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed =
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt / (time_passed);
                shm_conn_info->stats[info.process_num].speed_chan_data[i].down_data_len_amt = 0;
#ifdef TRACE
                vtun_syslog(LOG_INFO, "upload speed %lu kb/s physical channel %d logical channel %d",
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_current_speed, info.process_num, i);
                vtun_syslog(LOG_INFO, "download speed %lu kb/s physical channel %d logical channel %d",
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].down_current_speed, info.process_num, i);
#endif
                // speed in packets/sec calculation
                shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packet_speed =
                        (shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets / tv_tmp.tv_sec);
                shm_conn_info->stats[info.process_num].speed_chan_data[i].down_packets = 0;
#ifdef TRACE
                vtun_syslog(LOG_INFO, "download speed %lu packet/s physical channel %d logical channel %d lport %d rport %d",
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
                    vtun_syslog(LOG_INFO, "Sending time lag for %i buf_len %i.", i, my_miss_packets_max);
#endif
					time_lag_remote = shm_conn_info->stats[i].time_lag_remote;
                    /* we store my_miss_packet_max value in 12 upper bits 2^12 = 4096 mx is 4095*/
                    time_lag_remote &= 0xFFFFF; // shrink to 20bit
                    time_lag_remote = shm_conn_info->stats[i].time_lag_remote | (my_miss_packets_max << 20);
                    my_miss_packets_max = 0;
					pid_remote = shm_conn_info->stats[i].pid_remote;
                    uint32_t miss_packet_counter_h = htonl(shm_conn_info->miss_packets_max_send_counter++);
					sem_post(&(shm_conn_info->stats_sem));
					uint32_t time_lag_remote_h = htonl(time_lag_remote); // we have two values in time_lag_remote(_h)
                    memcpy(buf, &time_lag_remote_h, sizeof(uint32_t));
                    uint16_t FRAME_TIME_LAG_h = htons(FRAME_TIME_LAG);
                    memcpy(buf + sizeof(uint32_t), &FRAME_TIME_LAG_h, sizeof(uint16_t));
                    uint16_t pid_remote_h = htons(pid_remote);
                    memcpy(buf + sizeof(uint32_t) + sizeof(uint16_t), &pid_remote_h, sizeof(uint16_t));
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
                   if(delay_cnt == 0) delay_cnt = 1;
                   mean_delay = (delay_acc/delay_cnt);
       #ifdef DEBUGG
                   vtun_syslog(LOG_INFO, "tick! cn: %s; md: %d, dacq: %d, w: %d, isl: %d, bl: %d, as: %d, bsn: %d, brn: %d, bsx: %d, drop: %d, rrqrx: %d, rxs: %d, ms: %d, rxmntf: %d, rxm_notf: %d, chok: %d, rtt: %d, lkdf: %d, msd: %d, ch: %d, chsdev: %d, chrdev: %d, mlh: %d, mrh: %d, mld: %d", lfd_host->host, channel_mode, dev_my_cnt, weight, incomplete_seq_len, buf_len, shm_conn_info->normal_senders, statb.bytes_sent_norm,  statb.bytes_rcvd_norm,  statb.bytes_sent_rx,  statb.pkts_dropped, statb.rxmit_req_rx,  statb.rxmits,  statb.mode_switches, statb.rxm_ntf, statb.rxmits_notfound, statb.chok_not, rtt, (cur_time.tv_sec - shm_conn_info->lock_time), mean_delay, info.channel_amount, std_dev(statb.bytes_sent_chan, info.channel_amount), std_dev(&statb.bytes_rcvd_chan[1], (info.channel_amount-1)), statb.max_latency_hit, statb.max_reorder_hit, statb.max_latency_drops);
                   vtun_syslog(LOG_INFO, "ti! s/r %d %d %d %d %d %d / %d %d %d %d %d %d", statb.bytes_rcvd_chan[0],statb.bytes_rcvd_chan[1],statb.bytes_rcvd_chan[2],statb.bytes_rcvd_chan[3],statb.bytes_rcvd_chan[4],statb.bytes_rcvd_chan[5],    statb.bytes_sent_chan[0],statb.bytes_sent_chan[1],statb.bytes_sent_chan[2],statb.bytes_sent_chan[3],statb.bytes_sent_chan[4],statb.bytes_sent_chan[5] );
       #endif
                   dev_my_cnt = 0;
                   last_tick = cur_time.tv_sec;
                   shm_conn_info->alive = cur_time.tv_sec;
                   delay_acc = 0;
                   delay_cnt = 0;
       
                      if( (cur_time.tv_sec - last_net_read) > lfd_host->MAX_IDLE_TIMEOUT ) {
                          vtun_syslog(LOG_INFO,"Session %s network timeout", lfd_host->host);
                          break;
                      }
                      
                for (i = 0; i < info.channel_amount; i++) {
                sem_wait(&(shm_conn_info->write_buf_sem));
                unsigned long last_lws_notified_tmp = shm_conn_info->write_buf[i].last_lws_notified;
                unsigned long last_written_seq_tmp = shm_conn_info->write_buf[i].last_written_seq;
                sem_post(&(shm_conn_info->write_buf_sem));
                if (((cur_time.tv_sec - last_lws_notified_tmp) > LWS_NOTIFY_PEROID) && (last_written_seq_tmp > last_last_written_seq[i])) {
                    // TODO: DUP code!
                    sem_wait(&(shm_conn_info->write_buf_sem));
                    *((unsigned long *) buf) = htonl(shm_conn_info->write_buf[i].last_written_seq);
                    last_last_written_seq[i] = shm_conn_info->write_buf[i].last_written_seq;
                    shm_conn_info->write_buf[i].last_lws_notified = cur_time.tv_sec;
                    sem_post(&(shm_conn_info->write_buf_sem));
                    *((unsigned short *) (buf + sizeof(unsigned long))) = htons(FRAME_LAST_WRITTEN_SEQ);
                    int len_ret = proto_write(info.channel[i].descriptor, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                    if (len_ret < 0) {
                        vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                        linker_term = TERM_NONFATAL;
                    }
                    shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                    info.channel[i].up_len += len_ret;
                }
            }
       
               // now check ALL connections
            for (i = 0; i < info.channel_amount; i++) {
                   sem_wait(&(shm_conn_info->write_buf_sem));
                   timersub(&cur_time, &shm_conn_info->write_buf[i].last_write_time, &tv_tmp);
                   sem_post(&(shm_conn_info->write_buf_sem));
                   if( timercmp(&tv_tmp, &max_latency, >=) ) {

                       sem_wait(write_buf_sem);

                       incomplete_seq_len = missing_resend_buffer(i, incomplete_seq_buf, &buf_len);

                       sem_post(write_buf_sem);

                       //vtun_syslog(LOG_INFO, "missing_resend_buf ret %d %d ", incomplete_seq_len, buf_len);
   
                       if(incomplete_seq_len) {
                           for(imf=0; imf < incomplete_seq_len; imf++) {
                               if(check_sent(incomplete_seq_buf[imf], sq_rq_buf, &sq_rq_pos, i)) continue;
                               tmp_l = htonl(incomplete_seq_buf[imf]);
                               memcpy(buf, &tmp_l, sizeof(unsigned long));
                               *((unsigned short *)(buf+sizeof(unsigned long))) = htons(FRAME_MODE_RXMIT);
                               vtun_syslog(LOG_INFO,"Requesting bad frame (MAX_LATENCY) id %lu chan %d", incomplete_seq_buf[imf], i); // TODO HERE: remove this (2 places) verbosity later!!
                               //statb.rxmit_req++;
                               statb.max_latency_hit++;
                            int len_ret = proto_write(info.channel[i].descriptor, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                            if (len_ret < 0) {
                                   err=1;
                                   vtun_syslog(LOG_ERR, "BAD_FRAME request resend ERROR chan %d", i);
                               }
                            shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                            info.channel[i].up_len += len_ret;
                           }
                           if(err) {
                               err = 0;
                               break;
                           }
                       }
                   }
               }


               
               last_timing.tv_sec = cur_time.tv_sec;
               last_timing.tv_usec = cur_time.tv_usec;
          }

                    /*
                     * Now do a select () from all devices and channels
                     */
        FD_ZERO(&fdset_w);
        if (get_write_buf_wait_data()) {
            pfdset_w = &fdset_w;
            FD_SET(info.tun_device, pfdset_w);
        } else {
            pfdset_w = NULL;
        }
        FD_ZERO(&fdset);
#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "debug: HOLD_MODE - %i just_started_recv - %i", hold_mode, info.just_started_recv);
#endif
        if ((hold_mode == 0) && (info.just_started_recv == 1)) {
            FD_SET(info.tun_device, &fdset);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
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
        vtun_syslog(LOG_INFO, "First select time: %lu us descriptors num: %i", (long int)((work_loop2.tv_sec-work_loop1.tv_sec)*1000000+(work_loop2.tv_usec-work_loop1.tv_usec)), len);
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
                if((cur_time.tv_sec - last_action) > lfd_host->PING_INTERVAL) {
                    if(ping_rcvd) {
                         ping_rcvd = 0;
                         gettimeofday(&cur_time, NULL);
                         ping_req_ts = ((cur_time.tv_sec) * 1000) + (cur_time.tv_usec / 1000);
                         last_ping = cur_time.tv_sec;
                         vtun_syslog(LOG_INFO, "PING ...");
                         // ping ALL channels! this is required due to 120-sec limitation on some NATs
                    for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                        int len_ret = proto_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                        if (len_ret < 0) {
                                 vtun_syslog(LOG_ERR, "Could not send echo request chan %d reason %s (%d)", i, strerror(errno), errno);
                                 break;
                             }
                        shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
                        info.channel[i].up_len += len_ret;
                         }
                         last_action = cur_time.tv_sec; // TODO: clean up last_action/or/last_ping wtf.
                    }
                }
            continue;
        }

        /*
             *
             *
             *
             * Read frames from network(service_channel), decode and pass them to
             * the local device (tun_device)
             *
             *
             *
             *
             * */
        //check all chans for being set..
        for (chan_num = 0; chan_num < info.channel_amount; chan_num++) {
            fd0 = -1;
            if(FD_ISSET(info.channel[chan_num].descriptor, &fdset)) {
                fd0=info.channel[chan_num].descriptor; // TODO Why this need????

                //net_counter++; // rxmit mode
                last_action = cur_time.tv_sec;
                

#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "data on net... chan %d", chan_num);
#endif
                if( (len=proto_read(fd0, buf)) <= 0 ) {
                    if (len == 0) {
                        vtun_syslog(LOG_INFO, "proto_read return 0, the peer has performed an orderly shutdown. TERM_NONFATAL");
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                    if(len < 0) {
                         vtun_syslog(LOG_INFO, "sem_post! proto read <0; reason %s (%d)", strerror(errno), errno);
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
                        flag_var = ntohs(*((unsigned short *)(buf+(sizeof(unsigned long)))));
                        if(flag_var == FRAME_MODE_NORM) {
                            vtun_syslog(LOG_ERR, "ASSERT FAILED! received FRAME_MODE_NORM flag while not in MODE_RETRANSMIT mode!");
                            continue;
                        } else if (flag_var == FRAME_MODE_RXMIT) {
                            // okay
                        } else if (flag_var == FRAME_JUST_STARTED) {
                            // the opposite end has zeroed counters; zero mine!
                            uint32_t session_hash_remote = ntohl(*((uint32_t *) (buf)));
                            vtun_syslog(LOG_INFO, "received FRAME_JUST_STARTED; zeroing counters new remote hash - %u", session_hash_remote);
                            info.just_started_recv = 1;
                            sem_wait(&(shm_conn_info->AG_flags_sem));
                            if (shm_conn_info->session_hash_remote != session_hash_remote) {
                                shm_conn_info->session_hash_remote = session_hash_remote;
                                uint32_t chan_mask = shm_conn_info->channels_mask;
                                sem_post(&(shm_conn_info->AG_flags_sem));
                                info.session_hash_remote = session_hash_remote;
                                for (int i = 0; i < 32; i++) {
                                    if ((i == info.process_num) || (!(chan_mask & (1 << i)))) {
                                        continue;
                                    }
                                    sem_wait(&(shm_conn_info->stats_sem));
                                    pid_t pid = shm_conn_info->stats[i].pid;
                                    sem_post(&(shm_conn_info->stats_sem));
                                    kill(pid, SIGUSR1);
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
                            // connect to port specified
                            if( server_addr(&rmaddr, lfd_host) < 0 ) {
                                vtun_syslog(LOG_ERR, "Could not set server address!");
                                linker_term = TERM_FATAL;
                                break;
                            }

                            tmp_s = (unsigned short) ntohl(*((unsigned long *)buf));
			    rmaddr.sin_port = htons(tmp_s);
                            inet_ntop(AF_INET, &rmaddr.sin_addr, ipstr, sizeof ipstr);
                            vtun_syslog(LOG_INFO, "Channels connecting to %s : %d to create %d channels", ipstr, ntohs(rmaddr.sin_port), lfd_host->TCP_CONN_AMOUNT);
                            usleep(500000);

                            for(i=1; i<=lfd_host->TCP_CONN_AMOUNT; i++) {
                                errno = 0;
                                for(j=0; j<30; j++) {
                                    if( (fd_tmp = socket(AF_INET,SOCK_STREAM,0))==-1 ) {
                                        vtun_syslog(LOG_ERR,"Can't create CHAN socket. %s(%d) chan %d try %d",
                                                    strerror(errno), errno, i, j);
                                        linker_term = TERM_FATAL;
                                        break;
                                    }

#ifndef W_O_SO_MARK
                                    if(lfd_host->RT_MARK != -1) {
                                        if (setsockopt(fd_tmp, SOL_SOCKET, SO_MARK, &lfd_host->RT_MARK, sizeof(lfd_host->RT_MARK))) {
                                            vtun_syslog(LOG_ERR,"Client CHAN socket rt mark error %s(%d)",
                                                        strerror(errno), errno);
                                            break_out = 1;
                                            break;
                                        }
                                    }
#endif


#ifdef DEBUGG
                                    vtun_syslog(LOG_INFO,"Connecting CHAN sock i %d j %d", i, j);
#endif
                                    /*
                                    //  TODO: not sure doubling is required here
                                    if( server_addr(&rmaddr, lfd_host) < 0 ) {
                                        vtun_syslog(LOG_ERR, "Could not set server address!");
                                        errno = -EINVAL;
                                        linker_term = TERM_FATAL;
                                        break;
                                    }

                                    //  TODO: not sure doubling is required here
			            rmaddr.sin_port = htons(tmp_s);
				    */
                                    if( connect_t(fd_tmp,(struct sockaddr *) &rmaddr, SUP_TCP_CONN_TIMEOUT_SECS) ) {
                                        vtun_syslog(LOG_INFO,"Connect CHAN failed. %s(%d) chan %d try %d",
                                                    strerror(errno), errno, i, j);
                                        close(fd_tmp);
                                        usleep(500000);
                                        continue;
                                    }
                                    break;
                                }
                                if((j==30 || j==0) && (errno != 0)) {
                                    vtun_syslog(LOG_INFO,"WTF j==30 || j==0");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }

                                prio_opt=1;
                                setsockopt(fd_tmp,SOL_SOCKET,SO_KEEPALIVE,&prio_opt,sizeof(prio_opt) );

                                prio_opt=1;
                                setsockopt(fd_tmp,IPPROTO_TCP,TCP_NODELAY,&prio_opt,sizeof(prio_opt) );

                                maxfd = (fd_tmp > maxfd ? (fd_tmp) : maxfd);
                                info.channel[i].descriptor = fd_tmp;
#ifdef DEBUGG
                                vtun_syslog(LOG_INFO,"CHAN sock connected");
#endif

                            }
                            if(i<lfd_host->TCP_CONN_AMOUNT) {
                                vtun_syslog(LOG_ERR,"Could not connect all requested tuns; exit");
                                linker_term = TERM_NONFATAL;
                                break;
                            }
                            info.channel_amount = i;
                            //double call for getcockname beacause frst call returned ZERO in addr
                            laddrlen = sizeof(localaddr);
                            if (getsockname(info.channel[0].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                                vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                linker_term = TERM_NONFATAL;
                                break;
                            }
                            for (i = 0; i < info.channel_amount; i++) {
                                if (getsockname(info.channel[0].descriptor, (struct sockaddr *) (&localaddr), &laddrlen) < 0) {
                                    vtun_syslog(LOG_ERR, "Channels socket getsockname error; retry %s(%d)", strerror(errno), errno);
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                info.channel[i].lport = ntohs(localaddr.sin_port);
                                vtun_syslog(LOG_INFO, " client logical channel - %i port - %i", i, info.channel[i].lport);
                            }
                            vtun_syslog(LOG_INFO,"Successfully set up %d connection channels", info.channel_amount);
                            continue;
                        } else if(flag_var == FRAME_LAST_WRITTEN_SEQ) {
#ifdef DEBUGG
                            vtun_syslog(LOG_INFO, "received FRAME_LAST_WRITTEN_SEQ lws %lu chan %d", ntohl(*((unsigned long *)buf)), chan_num);
#endif
                            if( ntohl(*((unsigned long *)buf)) > shm_conn_info->write_buf[chan_num].remote_lws) shm_conn_info->write_buf[chan_num].remote_lws = ntohl(*((unsigned long *)buf));
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
                            uint32_t miss_packets_max_recv_counter;
                            memcpy(&(miss_packets_max_recv_counter), buf + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(time_lag_local.pid), sizeof(uint32_t));
                            miss_packets_max_recv_counter = ntohl(miss_packets_max_recv_counter);
							sem_wait(&(shm_conn_info->stats_sem));
#ifdef DEBUGG
                            vtun_syslog(LOG_INFO, "recv pid - %i packet_miss - %u",time_lag_local.pid, miss_packets_max_tmp);
							vtun_syslog(LOG_INFO, "Miss packet counter was - %u recv - %u",shm_conn_info->miss_packets_max_recv_counter, miss_packets_max_recv_counter);
#endif
//                            if ((miss_packets_max_recv_counter > shm_conn_info->miss_packets_max_recv_counter)) {
                                shm_conn_info->miss_packets_max_recv_counter = miss_packets_max_recv_counter;
                                for (int i = 0; i < MAX_TCP_PHYSICAL_CHANNELS; i++) {
                                    if (time_lag_local.pid == shm_conn_info->stats[i].pid) {
                                        shm_conn_info->stats[i].time_lag = time_lag_local.time_lag;
                                        miss_packets_max = miss_packets_max_tmp;
                                        shm_conn_info->miss_packets_max = miss_packets_max;
                                        recv_lag = 1;
                                        break;
                                    }
                                }
#ifdef DEBUGG
                                if (recv_lag) {
                                    vtun_syslog(LOG_INFO, "Time lag for pid: %i is %u", time_lag_local.pid, time_lag_local.time_lag);
                                    vtun_syslog(LOG_INFO, "Miss packets for pid: %i is %u", time_lag_local.pid, miss_packets_max_tmp);
                                }
#endif
//                            }
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
                        } else {
							vtun_syslog(LOG_ERR, "WARNING! unknown frame mode received: %du, real flag - %u!", (unsigned int) flag_var, ntohs(*((uint16_t *)(buf+(sizeof(uint32_t)))))) ;
					}
                    /*
                    // TODO: do we need to slow down here?
                        if(hold_mode) {
                            vtun_syslog(LOG_ERR, "Resend blocked due to hold_mode = 1: seq %lu; rxm_notf %d chan %d", ntohl(*((unsigned long *)buf)), statb.rxmits_notfound, chan_num);
                            continue;
                        }
                    */


                        sem_wait(resend_buf_sem);
                        len=get_resend_frame(chan_num, ntohl(*((unsigned long *)buf)), &out2, &sender_pid);
                        sem_post(resend_buf_sem);
                        
                        // drop the SQL
                        //send_q_limit = START_SQL;

                                                if(len <= 0) {
                            statb.rxmits_notfound++;
                            vtun_syslog(LOG_ERR, "Cannot resend frame: not found %lu; rxm_notf %d chan %d", ntohl(*((unsigned long *)buf)), statb.rxmits_notfound, chan_num);
                            // this usually means that this link is slow to get resend request; the data is writen ok and wiped out
                            // so actually it is not a warning...
                            // - OR - resend buffer is too small; check configuration
                            continue;
                        }

                        if( ((lfd_host->flags & VTUN_PROT_MASK) == VTUN_TCP) && (sender_pid == info.pid)) {
                            vtun_syslog(LOG_INFO, "Will not resend my own data! It is on the way! frame len %d seq_num %lu chan %d", len, ntohl(*((unsigned long *)buf)), chan_num);
                            continue;
                        }
                        vtun_syslog(LOG_ERR, "Resending bad frame len %d eq lu %d id %lu chan %d", len, sizeof(unsigned long), ntohl(*((unsigned long *)buf)), chan_num);

                        lfd_host->stat.byte_out += len;
                        statb.rxmits++;

                        
                        // now set which channel it belongs to...
                        // TODO: this in fact rewrites CHANNEL_MODE making MODE_RETRANSMIT completely useless
                        //*( (unsigned short *) (out2 - sizeof(flag_var))) = chan_num + FLAGS_RESERVED;
                        // this does not work; done in get_resend_frame

                        gettimeofday(&send1, NULL);
                        int len_ret = proto_write(info.channel[0].descriptor, out2, len);
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "ERROR: cannot resend frame: write to chan %d", 0);
                        }
                        gettimeofday(&send2, NULL);
                        shm_conn_info->stats[info.process_num].speed_chan_data[0].up_data_len_amt += len_ret;
                        info.channel[0].up_len += len_ret;
                        info.byte_resend += len_ret;
#ifdef DEBUGG
                        if((long int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec)) > 100) vtun_syslog(LOG_INFO, "BRESEND DELAY: %lu ms", (long int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec)));
#endif
                        delay_acc += (int)((send2.tv_sec-send1.tv_sec)*1000000+(send2.tv_usec-send1.tv_usec));
                        delay_cnt++;

                        //vtun_syslog(LOG_INFO, "sending SIGUSR2 to %d", sender_pid);
                        continue;
                    }
                    if( fl==VTUN_ECHO_REQ ) {
                        /* Send ECHO reply */
                        last_net_read = cur_time.tv_sec;
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "sending PONG...");
#endif
                        int len_ret = proto_write(info.channel[chan_num].descriptor, buf, VTUN_ECHO_REP);
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
                        last_net_read = cur_time.tv_sec;
                        gettimeofday(&cur_time, NULL);

                        if(rtt_old_old == 0) {
                            rtt_old = rtt_old_old = (( (cur_time.tv_sec ) * 1000) + (cur_time.tv_usec / 1000) - ping_req_ts);
                        }
                        rtt = (   (( (cur_time.tv_sec ) * 1000) + (cur_time.tv_usec / 1000) - ping_req_ts) + rtt_old + rtt_old_old   ) / 3;
                        rtt_old_old = rtt_old;
                        rtt_old = rtt;
                        continue; 
                    }
                    if( fl==VTUN_CONN_CLOSE ) {
                        vtun_syslog(LOG_INFO,"Connection closed by other side");
                        vtun_syslog(LOG_INFO, "sem_post! conn closed other");
                        linker_term = TERM_NONFATAL;
                        break;
                    }
                } else {
                    shm_conn_info->stats[info.process_num].speed_chan_data[chan_num].down_packets++;// accumulate number of packets
                    last_net_read = cur_time.tv_sec;
                    statb.bytes_rcvd_norm+=len;
                    statb.bytes_rcvd_chan[chan_num] += len;
                    out = buf; // wtf?

                    len = seqn_break_tail(out, len, &seq_num, &flag_var);
#ifdef DEBUGG
                    if (seq_num % 50 == 0) {
                        vtun_syslog(LOG_INFO, "Receive frame ... chan %d seq %lu len %d", chan_num, seq_num, len);
                    }
#endif
                    // introduced virtual chan_num to be able to process
                    //    congestion-avoided priority resend frames
                    if(chan_num == 0) { // reserved aux channel
                         if(flag_var == 0) { // this is a workaround for some bug... TODO!!
                              vtun_syslog(LOG_ERR,"BUG! flag_var == 0 received on chan 0! sqn %lu, len %d. DROPPING",seq_num, len);
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
                    int another_chan = (info.process_num == 0) ? 1: 0;
                    sem_wait(write_buf_sem);
                    incomplete_seq_len = write_buf_add(chan_num_virt, out, len, seq_num, incomplete_seq_buf, &buf_len, info.pid, &succ_flag);
                    my_miss_packets = buf_len;
                    if(succ_flag == -2) statb.pkts_dropped++; // TODO: optimize out to wba
                    if(buf_len == 1) { // to avoid dropping first out-of order packet in sequence
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = cur_time.tv_sec;
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = cur_time.tv_usec;
                    }
                    sem_post(write_buf_sem);
#ifdef DEBUGG
                    gettimeofday(&work_loop2, NULL );
                    vtun_syslog(LOG_INFO, "write_buf_add time: %lu us", (long int) ((work_loop2.tv_sec - work_loop1.tv_sec) * 1000000 + (work_loop2.tv_usec - work_loop1.tv_usec)));
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
                    timersub(&cur_time, &last_write_time_tmp, &tv_tmp);
                    if ( (tv_tmp.tv_sec >= lfd_host->MAX_LATENCY_DROP) &&
                         (timerisset(&last_write_time_tmp))) {
                        //if(buf_len > 1)
                        vtun_syslog(LOG_ERR, "WARNING! MAX_LATENCY_DROP triggering at play! chan %d", chan_num_virt);
                        statb.max_latency_drops++;
                    }

                    sem_wait(write_buf_sem);
                    fprev = shm_conn_info->write_buf[chan_num_virt].frames.rel_head;
                    if(fprev == -1) { // don't panic ;-)
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = cur_time.tv_sec;
                         shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = cur_time.tv_usec;
                    }
                    sem_post(write_buf_sem);

                    // check for initialization
                    if (!info.just_started_recv) {
                        continue;
                    }
                    // send lws(last written sequence number) to remote side
                    sem_wait(write_buf_sem);
                    int cond_flag = shm_conn_info->write_buf[chan_num_virt].last_written_seq > (last_last_written_seq[chan_num_virt] + lfd_host->FRAME_COUNT_SEND_LWS) ? 1 : 0;
                    sem_post(write_buf_sem);
                    if(cond_flag) {
                        sem_wait(write_buf_sem);
#ifdef DEBUGG
                        vtun_syslog(LOG_INFO, "sending FRAME_LAST_WRITTEN_SEQ lws %lu chan %d", shm_conn_info->write_buf[chan_num_virt].last_written_seq, chan_num_virt);
#endif
                        *((unsigned long *)buf) = htonl(shm_conn_info->write_buf[chan_num_virt].last_written_seq);
                        last_last_written_seq[chan_num_virt] = shm_conn_info->write_buf[chan_num_virt].last_written_seq;
                        shm_conn_info->write_buf[chan_num_virt].last_lws_notified = cur_time.tv_sec;
                        sem_post(write_buf_sem);
                        *((unsigned short *)(buf+sizeof(unsigned long))) = htons(FRAME_LAST_WRITTEN_SEQ);
                        int len_ret = proto_write(info.channel[chan_num_virt].descriptor, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "Could not send last_written_seq pkt; exit");
                            linker_term = TERM_NONFATAL;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num_virt].up_data_len_amt += len_ret;
                        info.channel[chan_num_virt].up_len += len_ret;
                        // TODO: introduce periodic send via each channel. On channel use stop some of resend_buf will remain locked
                        continue;
                    }
                    if(buf_len > lfd_host->MAX_REORDER) {
                        // TODO: "resend bomb type II" problem - if buf_len > MAX_REORDER: any single(ordinary reorder) miss will cause resend
                        //       to fight the bomb: introduce max buffer scan length for missing_resend_buffer method
                        sem_wait(write_buf_sem);
                        incomplete_seq_len = missing_resend_buffer(chan_num_virt, incomplete_seq_buf, &buf_len);
                        sem_post(write_buf_sem);

                        if(incomplete_seq_len) {
                            for(imf=0; imf < incomplete_seq_len; imf++) {
                            	// TODO: use free channel to send packets that are late to fight the congestion
                                if(check_sent(incomplete_seq_buf[imf], sq_rq_buf, &sq_rq_pos, chan_num_virt)) continue;
                                tmp_l = htonl(incomplete_seq_buf[imf]);
                                memcpy(buf, &tmp_l, sizeof(unsigned long));
                                *((unsigned short *)(buf+sizeof(unsigned long))) = htons(FRAME_MODE_RXMIT);
                                vtun_syslog(LOG_INFO,"Requesting bad frame MAX_REORDER incomplete_seq_len %d blen %d seq_num %lu chan %d",incomplete_seq_len, buf_len, incomplete_seq_buf[imf], chan_num_virt);
                                //statb.rxmit_req++;
                                statb.max_reorder_hit++;
                                int len_ret = proto_write(info.channel[chan_num_virt].descriptor, buf,
                                        ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                                if (len_ret < 0) {
                                    vtun_syslog(LOG_ERR, "BAD_FRAME request resend 2");
                                    linker_term = TERM_NONFATAL;
                                    break;
                                }
                                shm_conn_info->stats[info.process_num].speed_chan_data[chan_num_virt].up_data_len_amt += len_ret;
                                info.channel[chan_num_virt].up_len += len_ret;
                            }
                        } else {
                            if(buf_len > lfd_host->MAX_REORDER) {
                                vtun_syslog(LOG_ERR, "ASSERT FAILED!! MAX_REORDER not resending! buf_len: %d", buf_len);
                            }
                        }
                        continue;
                    }

                    lfd_host->stat.byte_in += len; // the counter became completely wrong

                    if( (flag_var == FRAME_MODE_RXMIT) &&
                            ((succ_flag == 0) || ( (seq_num-shm_conn_info->write_buf[chan_num_virt].last_written_seq) < lfd_host->MAX_REORDER ))) {
                        vtun_syslog(LOG_INFO, "sending FRAME_MODE_NORM to notify THIS channel is now OK");
                        tmp_l = htonl(incomplete_seq_buf[0]);
                        memcpy(buf, &tmp_l, sizeof(unsigned long));
                        *((unsigned short *)(buf+sizeof(unsigned long))) = htons(FRAME_MODE_NORM);
                        statb.chok_not++;
                        int len_ret = proto_write(info.channel[chan_num_virt].descriptor, buf, ((sizeof(unsigned long) + sizeof(flag_var)) | VTUN_BAD_FRAME));
                        if (len_ret < 0) {
                            vtun_syslog(LOG_ERR, "BAD_FRAME request resend 2");
                            linker_term = TERM_NONFATAL;
                            break;
                        }
                        shm_conn_info->stats[info.process_num].speed_chan_data[chan_num_virt].up_data_len_amt += len_ret;
                        info.channel[chan_num_virt].up_len += len_ret;
                        succ_flag = -100; // drop flag??
                        continue;
                    }

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

        sem_wait(write_buf_sem);

        chan_num_virt = chan_num; // WTF we write to tun async with how we rcv!?!?!
        fprev = shm_conn_info->write_buf[chan_num_virt].frames.rel_head;
        if (fprev == -1) { // don't panic ;-)
            shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = cur_time.tv_sec;
            shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = cur_time.tv_usec;
        }
        shm_conn_info->write_buf[chan_num_virt].complete_seq_quantity = 0;
        fold = -1;

#ifdef DEBUGG
        if (fprev == -1) {
            vtun_syslog(LOG_INFO, "no data to write at all!");
        } else {
            vtun_syslog(LOG_INFO, "trying to write to to dev: seq_num %lu lws %lu chan %d", shm_conn_info->frames_buf[fprev].seq_num,
                    shm_conn_info->write_buf[chan_num_virt].last_written_seq, chan_num_virt);
        }
#endif
        acnt = 0;
        while ((fprev > -1) && FD_ISSET(info.tun_device, &fdset_w)) {
            int cond_flag = shm_conn_info->frames_buf[fprev].seq_num == (shm_conn_info->write_buf[chan_num_virt].last_written_seq + 1) ? 1 : 0;
            if (cond_flag || (buf_len > lfd_host->MAX_ALLOWED_BUF_LEN) || (tv_tmp.tv_sec >= lfd_host->MAX_LATENCY_DROP)) {
                struct frame_seq frame_seq_tmp = shm_conn_info->frames_buf[fprev];
#ifdef DEBUGG
                struct timeval work_loop1, work_loop2;
                gettimeofday(&work_loop1, NULL );
#endif
                if ((len = dev_write(info.tun_device, frame_seq_tmp.out, frame_seq_tmp.len)) < 0) {
                    vtun_syslog(LOG_ERR, "error writing to device %d %s chan %d", errno, strerror(errno), chan_num_virt);
                    if (errno != EAGAIN && errno != EINTR) { // TODO: WTF???????
                        vtun_syslog(LOG_ERR, "dev write not EAGAIN or EINTR");
                    } else {
                        vtun_syslog(LOG_ERR, "dev write intr - need cont");
                        //continue; // orig.. wtf??
                    }
                } else {
                    if (len < frame_seq_tmp.len) {
                        vtun_syslog(LOG_ERR, "ASSERT FAILED! could not write to device immediately; dunno what to do!! bw: %d; b rqd: %d", len,
                                shm_conn_info->frames_buf[fprev].len);
                    }
                }
#ifdef DEBUGG
                gettimeofday(&work_loop2, NULL );
                vtun_syslog(LOG_INFO, "dev_write time: %lu us", (long int) ((work_loop2.tv_sec - work_loop1.tv_sec) * 1000000 + (work_loop2.tv_usec - work_loop1.tv_usec)));
                vtun_syslog(LOG_INFO, "writing to dev: bln is %d icpln is %d, sqn: %lu, lws: %lu mode %d, ns: %d, w: %d len: %d, chan %d", buf_len, incomplete_seq_len,
                        shm_conn_info->frames_buf[fprev].seq_num, shm_conn_info->write_buf[chan_num_virt].last_written_seq, (int) channel_mode, shm_conn_info->normal_senders,
                        weight, shm_conn_info->frames_buf[fprev].len, chan_num_virt);
#endif
                shm_conn_info->write_buf[chan_num_virt].last_written_seq = shm_conn_info->frames_buf[fprev].seq_num;
                shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_sec = cur_time.tv_sec;
                shm_conn_info->write_buf[chan_num_virt].last_write_time.tv_usec = cur_time.tv_usec;

                fold = fprev;
                fprev = shm_conn_info->frames_buf[fprev].rel_next;
                frame_llist_free(&shm_conn_info->write_buf[chan_num_virt].frames, &shm_conn_info->wb_free_frames, shm_conn_info->frames_buf, fold);
            } else {
                break;
            }
#ifdef DEBUGG
            if (assert_cnt(7))
                break; // TODO: add #ifdef DEBUGG
#endif
            break;
        }
        sem_post(write_buf_sem);

        } // for chans..

        if ((pfdset_w != NULL) && FD_ISSET(info.tun_device, pfdset_w)) {
            continue; // we do not want to read data from device each time that we write a packet!
        }


        /* Read data from the local device(tun_device), encode and pass it to
             * the network (service_channel)
             *
             *
             * ****************************************************************************************
             *
             *
             * */
        sem_wait(&(shm_conn_info->AG_flags_sem));
        uint32_t AG_ready_flag_tmp = shm_conn_info->AG_ready_flag;
        sem_post(&(shm_conn_info->AG_flags_sem));
        // check for mode
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: send time, AG_ready_flags %xx0", info.mode);
#endif
        if ((AG_ready_flag_tmp == R_MODE) || (info.mode == R_MODE)) { // it is RETRANSMIT_MODE(R_MODE)
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: R_MODE");
#endif
            len = retransmit_send(out2);
            if (len == CONTINUE_ERROR) {
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: R_MODE continue err");
#endif
                len = 0;
            } else if ((len == LASTPACKETMY_NOTIFY) | (len == HAVE_FAST_RESEND_FRAME)) { // if this physical channel had sent last packet
#ifdef DEBUGG
            vtun_syslog(LOG_INFO, "debug: R_MODE main send");
#endif
                len = select_devread_send(buf, out2);
                if (len > 0) {
                    dirty_seq_num++;
                } else if (len == BREAK_ERROR) {
                    vtun_syslog(LOG_INFO, "select_devread_send() R_MODE BREAK_ERROR");
                    break;
                } else if (len == CONTINUE_ERROR) {
                    len = 0;
                } else if (len == TRYWAIT_NOTIFY) {
                    len = 0; //todo need to check resend_buf for new packet again ????
                }
            } else {
                dirty_seq_num++;
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
            //Check time interval and ping if need.
        if (((cur_time.tv_sec - last_ping) > lfd_host->PING_INTERVAL) && (len <= 0)) {
				ping_rcvd = 0;
				gettimeofday(&cur_time, NULL);

				ping_req_ts = ((cur_time.tv_sec) * 1000) + (cur_time.tv_usec / 1000);

				last_ping = cur_time.tv_sec;
#ifdef DEBUGG
				vtun_syslog(LOG_INFO, "PING2");
#endif
				// ping ALL channels! this is required due to 120-sec limitation on some NATs
            for (i = 0; i < info.channel_amount; i++) { // TODO: remove ping DUP code
                int len_ret = proto_write(info.channel[i].descriptor, buf, VTUN_ECHO_REQ);
                if (len_ret < 0) {
						vtun_syslog(LOG_ERR, "Could not send echo request 2 chan %d reason %s (%d)", i, strerror(errno), errno);
						break;
					}
					shm_conn_info->stats[info.process_num].speed_chan_data[i].up_data_len_amt += len_ret;
					info.channel[i].up_len += len_ret;
				}
			}

            gettimeofday(&cur_time, NULL);
            last_action = cur_time.tv_sec;
            lfd_host->stat.comp_out += len;
    }

    sem_wait(&(shm_conn_info->AG_flags_sem));
    shm_conn_info->channels_mask &= ~(1 << info.process_num); // del channel num from binary mask
    shm_conn_info->need_to_exit &= ~(1 << info.process_num);
    sem_post(&(shm_conn_info->AG_flags_sem));
#ifdef JSON
    vtun_syslog(LOG_INFO,
            "{\"p_chan_num\":%i,\"name\":\"%s\",\"l_chan_num\":0,\"max_reorder_byte\":0,\"send_q_limit\":0,\"send_q\":0,\"rtt\":0,\"rtt_var\":0,\"my_rtt\":0,\"magic_rtt\":0,\"cwnd\":0,\"isl\":0,\"rxmits\":0,\"buf_len\":0,\"magic_upload\":0,\"upload\":0,\"download\":0,\"hold_mode\":0,\"ACS\":0,\"R_MODE\":0, \"AG_ready_flag\":0, \"my_max_send_q_avg\":0}", info.process_num, lfd_host->host);
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
 *  Link remote and local file descriptors.
 *  We should initialize all global variable here if it possible.
 */
int linkfd(struct vtun_host *host, struct conn_info *ci, int ss, int physical_channel_num)
{
    memset(last_sent_packet_num, 0, sizeof(struct last_sent_packet) * MAX_TCP_LOGICAL_CHANNELS);
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
    rtt = 0;
    rtt_old=0;
    rtt_old_old=0;
    my_miss_packets_max = 0; // in ms; calculated here
    miss_packets_max = 0; // get from another side
    proto_err_cnt = 0;
    my_max_send_q_chan_num = 0;
    my_max_send_q = 0;
    max_reorder_byte = 0;
    last_channels_mask = 0;
    info.byte_efficient = 0;
    info.byte_resend = 0;
    info.byte_r_mode = 0;
    info.speed_efficient = 0;
    info.speed_resend = 0;
    info.speed_r_mode = 0;
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
    struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup, sa_oldusr1;
    int old_prio;
    /** Global initialization section for variable and another things*/
    memset(&info, 0, sizeof(struct phisical_status));
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
        chan_info = (struct channel_info *) calloc(info.channel_amount, sizeof(struct channel_info));
        if (chan_info == NULL ) {
            vtun_syslog(LOG_ERR, "Can't allocate array for struct chan_info for the linker");
            return 0;
        }
        info.channel[0].descriptor = host->rmt_fd; // service channel
        gettimeofday(&(info.get_tcp_info_time), NULL );
        for (int i = 0; i < info.channel_amount; i++) {
            memcpy(&(info.channel[i].get_tcp_info_time_old), &(info.get_tcp_info_time), sizeof(info.channel[i].get_tcp_info_time_old));
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
    char pid_file_str[30], pid_str[20];
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
        kill(pid, SIGUSR1);
    }

    sigaction(SIGTERM,&sa_oldterm,NULL);
    sigaction(SIGINT,&sa_oldint,NULL);
    sigaction(SIGHUP,&sa_oldhup,NULL);
    sigaction(SIGUSR1,&sa_oldusr1,NULL);

    setpriority(PRIO_PROCESS,0,old_prio);

    return linker_term;
}
