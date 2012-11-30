/*
 * socket_info.h
 *
 *  Created on: 30.11.2012
 *      Author: andrey
 */

#include <stdint.h>

#ifndef SOCKET_INFO_H_
#define SOCKET_INFO_H_
#define SSF_DCOND 0
#define SSF_SCOND 1
#define SSF_OR    2
#define SSF_AND   3
#define SSF_NOT   4
#define SSF_D_GE  5
#define SSF_D_LE  6
#define SSF_S_GE  7
#define SSF_S_LE  8
#define SSF_S_AUTO  9

enum {
    SS_UNKNOWN,
    SS_ESTABLISHED,
    SS_SYN_SENT,
    SS_SYN_RECV,
    SS_FIN_WAIT1,
    SS_FIN_WAIT2,
    SS_TIME_WAIT,
    SS_CLOSE,
    SS_CLOSE_WAIT,
    SS_LAST_ACK,
    SS_LISTEN,
    SS_CLOSING,
    SS_MAX
};

enum
{
    TCP_DB,
    DCCP_DB,
    UDP_DB,
    RAW_DB,
    UNIX_DG_DB,
    UNIX_ST_DB,
    PACKET_DG_DB,
    PACKET_R_DB,
    NETLINK_DB,
    MAX_DB
};

#define SS_ALL ((1<<SS_MAX)-1)

struct ssfilter
{
    int type;
    struct ssfilter *post;
    struct ssfilter *pred;
};

struct channel_info {
    uint8_t snd_wscale;
    uint8_t rcv_wscale;
    double rto; // TCP retransmit timeout
    double rtt; // in ms (round trip time)
    double rtt_var; // in ms (?jitter?)
    double ato; // ACK timeout
    uint32_t cwnd; // in mss
    uint32_t mss;
    uint32_t ssthresh;
    uint32_t send; // in kbyte/sec)
    double rcv_rtt;
    uint32_t rcv_space;
    uint32_t send_q;
    uint32_t recv_q;
    int lport;
    int rport;
};

int get_format_tcp_info(struct channel_info**, int channel_amount);

#endif /* SOCKET_INFO_H_ */
