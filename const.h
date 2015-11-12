
#ifndef _CONST_H
#define _CONST_H

// max aggregated VPN-links compiled-in (+ some extras for racing)
#define MAX_TCP_PHYSICAL_CHANNELS 7
#define AGAG_AG_THRESH 30 // how many agag to consider AG mode
#define DROP_TIME_IMMUNE 2500000 // useconds of drop immune
#define MAX_HSQS_EAT 20 // percent of channel send_q allowed to be eaten in SELECT_SLEEP_USEC
#define MAX_HSQS_PUSH 20 // the same for push MSBL to network
#define MSBL_LIMIT 1200
#define MSBL_RESERV 450
#define PBL_SMOOTH_NUMERATOR 5
#define PBL_SMOOTH_DENOMINATOR 6
#define EFF_LEN_AVG_N 7
#define EFF_LEN_AVG_D 8
#define AVG_LEN_IN_ACK_THRESH 100 /** treat incoming traffic as ACK-only if average incoming packet length is lower than this */
#define UNRECOVERABLE_LOSS 250 /** amount of packets that we won't even try to retransmit */

#endif