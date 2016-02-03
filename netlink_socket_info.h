/*
 * socket_info.h
 *
 *  Created on: 30.11.2012
 *       Copyright (C) 2011-2016 Vrayo Systems Ltd. team 
 */

#ifndef SOCKET_INFO_H_
#define SOCKET_INFO_H_

#include <stdint.h>

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

int get_format_tcp_info(struct channel_info* channel_info_vt, int channel_amount);

#endif /* SOCKET_INFO_H_ */
