
#ifndef _CONST_H
#define _CONST_H

// max aggregated VPN-links compiled-in (+ some extras for racing)
#define MAX_TCP_PHYSICAL_CHANNELS 7
#define AGAG_AG_THRESH 30 // how many agag to consider AG mode
#define DROP_TIME_IMMUNE 2500000 // useconds of drop immune
#define MAX_HSQS_EAT 20 // percent of channel send_q allowed to be eaten in SELECT_SLEEP_USEC
#define MAX_HSQS_PUSH 20 // the same for push MSBL to network
#define MSBL_LIMIT 1000
#define MSBL_RESERV 10
#define PBL_SMOOTH_NUMERATOR 5
#define PBL_SMOOTH_DENOMINATOR 6
#define EFF_LEN_AVG_N 7
#define EFF_LEN_AVG_D 8
#define AVG_LEN_IN_ACK_THRESH 100 /** treat incoming traffic as ACK-only if average incoming packet length is lower than this */
#define LOSSED_BACKLOG_SIZE 250
#define UNRECOVERABLE_LOSS LOSSED_BACKLOG_SIZE-1 /** amount of packets that we won't even try to retransmit */
#define WBUF_HASH_SIZE 256
#define MAX_WBUF_HASH_DEPTH 6
#define RSR_TOP 2990000 // now infinity...
#define MIN_PPS 10 // minimal packets per second for the system
#define TOKENS_MAXWAIT 40 // amount of tokens to wait for drop max. (this limits jitter)
#define MAX_PACKET_WAIT {5,0} // 5 seconds max possible total lag before unconditional drop

// general const

#define SESSION_NAME_SIZE 50
// maximum compiled-in buffers for tcp channels per link
#define MAX_TCP_LOGICAL_CHANNELS 7//100 // int
#define SPEED_AVG_ARR 15 // for speed_algo.h structs
#define PLP_BUF_SIZE 20 // size of buffer used for old values of PBL for PLP calc
/* Max lenght of device name */
#define VTUN_DEV_LEN  20 
// should be --> MAX_ALLOWED_BUF_LEN*TCP_CONN_AMOUNT to exclude outages
#define FRAME_BUF_SIZE 2200 // int WARNING: see P_MAX_ALLOWED_BUF_LEN

// to avoid drops absolutely, this should be able to hold up to MAX_LATENCY_DROP*(TCP_CONN_AMOUT+1)*speed packets!
#ifdef LOW_MEM
    #define RESEND_BUF_SIZE 600 // int
    #define JS_MAX 1000 // data for logs, * 3 times is allocated
#else
    #define RESEND_BUF_SIZE 3000 // int
    #define JS_MAX 20000 // 100kb string len of JSON logs * 3 size is used!
#endif
#define FAST_RESEND_BUF_SIZE 21 // (MAX_TCP_PHYSICAL_CHANNELS*3)
#define FLUSHED_PACKET_ARRAY_SIZE 1000 // size of hashed seq_num array to check for flushed packets
#define CHECK_SZ 256 // size of bit check field
#define LOSS_ARRAY 80
#define W_STREAMS_AMT 1000
#endif