/*
 * udp_states.h
 *
 *  Created on: 15.10.2014
 *      Author: Vrayo Systems Ltd. team
 */

#ifndef UDP_STATES_H_
#define UDP_STATES_H_

#include <asm/types.h>

struct udp_stats {
    __u32 rdata[8];
    int rport;
    __u32 ldata[8];
    int lport;
    int rx_q;
    int tx_q;
    int drops, state, refcnt, wq, rq;
    unsigned uid, ino;
    unsigned long long sk;
};

int get_udp_stats(struct udp_stats* udp_struct, int conn_amount);

#endif /* UDP_STATES_H_ */
