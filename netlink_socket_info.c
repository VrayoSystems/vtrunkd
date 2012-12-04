/*
 * netlink_socket_info.c

 *
 * According by ss from iproute2 and fss is written by Matt Tierney
 *
 *  Created on: 30.11.2012
 *      Author: Kuznetsov Andrey <andreykyz@gmail.com>
 */

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <alloca.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include "netlink_socket_info.h"
#include "lib.h"

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

enum {
    TCP_DB, DCCP_DB, UDP_DB, RAW_DB, UNIX_DG_DB, UNIX_ST_DB, PACKET_DG_DB, PACKET_R_DB, NETLINK_DB, MAX_DB
};

#define SS_ALL ((1<<SS_MAX)-1)

struct ssfilter {
    int type;
    struct ssfilter *post;
    struct ssfilter *pred;
};

struct filter {
    int dbs;
    int states;
    int families;
    struct ssfilter *f;
};

struct filter default_filter = {
    .dbs = (1 << TCP_DB),
    .states = SS_ALL & ~((1 << SS_LISTEN) | (1 << SS_CLOSE) | (1 << SS_TIME_WAIT) | (1 << SS_SYN_RECV)),
    .families = (1 << AF_INET) | (1 << AF_INET6),
};

struct filter current_filter;
int conn_counter, channel_amount_ss, show_tcpinfo = 0, show_mem = 0;
struct channel_info** channel_info_ss;

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len)
        fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
    return 0;
}

/*main parse function*/
static int tcp_show_sock(struct nlmsghdr *nlh, struct filter *f) {
    struct inet_diag_msg *r = NLMSG_DATA(nlh);
    // fill channel_info structure
    if (conn_counter < channel_amount_ss) {
        for (int i = 0; i < channel_amount_ss; i++) {
            if ((channel_info_ss[i]->lport == ntohs(r->id.idiag_sport)) | (channel_info_ss[i]->rport == ntohs(r->id.idiag_dport))) {
                format_info(nlh, r);
                channel_info_ss[i]->recv_q = r->idiag_rqueue;
                channel_info_ss[i]->send_q = r->idiag_wqueue;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "fss conn_counter - %i channel_amount_ss - %i send_q - %i recv_q - %i lport - %i rport - %i", i,
                        channel_amount_ss, channel_info_ss[i]->send_q, channel_info_ss[i]->recv_q, ntohs(r->id.idiag_sport),
                        ntohs(r->id.idiag_dport));
#endif
                conn_counter++;
                break;
            }
        }
    }

    return 0;
}

/**
 * Function for connect to kernel's netlink interface
 * and get info about tcp connections
 *
 * @param f - flags for getting tcp information
 * @param dump_fp - now unused
 * @param socktype
 * @return
 */
static int tcp_show_netlink(struct filter *f, FILE *dump_fp, int socktype) {
    int fd;
    struct sockaddr_nl nladdr;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req;
    char *bc = NULL;
    int bclen;
    struct msghdr msg;
    struct rtattr rta;
    char buf[8192];
    struct iovec iov[3];

    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0) {
        int errsv = errno;
        switch (errno) {
        case EMFILE:
            printf("Too many open files.\n");
            break;
        default:
            printf("Error: %d.\n", errsv);
            break;
        }
        return -1;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = socktype;
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = 123456;
    memset(&req.r, 0, sizeof(req.r));
    req.r.idiag_family = AF_INET;
    req.r.idiag_states = f->states;
    if (show_mem)
        req.r.idiag_ext |= (1 << (INET_DIAG_MEMINFO - 1));

    if (show_tcpinfo) {
        req.r.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
        req.r.idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));
        req.r.idiag_ext |= (1 << (INET_DIAG_CONG - 1));
    }

    iov[0] = (struct iovec ) { .iov_base = &req, .iov_len = sizeof(req) };
    if (f->f) {
//        bclen = ssfilter_bytecompile(f->f, &bc);
        rta.rta_type = INET_DIAG_REQ_BYTECODE;
        rta.rta_len = RTA_LENGTH(bclen);
        iov[1] = (struct iovec ) { &rta, sizeof(rta) };
        iov[2] = (struct iovec ) { bc, bclen };
        req.nlh.nlmsg_len += RTA_LENGTH(bclen);
    }

    msg = (struct msghdr ) { .msg_name = (void*) &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = iov, .msg_iovlen = f->f ? 3 : 1, };

    if (sendmsg(fd, &msg, 0) < 0)
        return -1;

    iov[0] = (struct iovec ) { .iov_base = buf, .iov_len = sizeof(buf) };

    while (1) {
        int status;
        struct nlmsghdr *h;

        msg = (struct msghdr ) { (void*) &nladdr, sizeof(nladdr), iov, 1, NULL, 0, 0 };

        status = recvmsg(fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR)
                continue;
            perror("OVERRUN");
            continue;
        }
        if (status == 0) {
            fprintf(stderr, "EOF on netlink\n");
            return 0;
        }

        if (dump_fp)
            fwrite(buf, 1, NLMSG_ALIGN(status), dump_fp);

        h = (struct nlmsghdr*) buf;
        while (NLMSG_OK(h, status)) {

            int err;
            struct inet_diag_msg *r = NLMSG_DATA(h);

            if (/*h->nlmsg_pid != rth->local.nl_pid ||*/
            h->nlmsg_seq != 123456)
                goto skip_it;

            if (h->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(h);
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    fprintf(stderr, "ERROR truncated\n");
                } else {
                    errno = -err->error;
                    perror("TCPDIAG answers");
                }
                return 0;
            }
            if (!dump_fp) {
                if (!(f->families & (1 << r->idiag_family))) {
                    h = NLMSG_NEXT(h, status);
                    continue;
                }
                err = tcp_show_sock(h, NULL );
                if (err < 0)
                    return err;
            }

            skip_it: h = NLMSG_NEXT(h, status);
        }
        if (msg.msg_flags & MSG_TRUNC) {
            fprintf(stderr, "Message truncated\n");
            continue;
        }
        if (status) {
            fprintf(stderr, "!!!Remnant of size %d\n", status);
//            exit(1); todo refactor
        }
    }
    if (close(fd) == -1) {
        printf("Unable to close socket: %d\n.", errno);
    }
    return 0;
}

/**
 * Function get from **channel_info_vt port's num and fill information about tcp connection
 * @param channel_info_vt
 * @param channel_amount - *channel_info_vt[] array length
 */
int get_format_tcp_info(struct channel_info** channel_info_vt, int channel_amount) {
    channel_info_ss = channel_info_vt;
    channel_amount_ss = channel_amount;
    conn_counter = 0;
    show_tcpinfo = 1;

    memset(&current_filter, 0, sizeof(current_filter));

    current_filter.states = default_filter.states;
    current_filter.dbs = default_filter.dbs;
    current_filter.families = default_filter.families;

    tcp_show_netlink(&current_filter, NULL, TCPDIAG_GETSOCK);

#ifdef DEBUGG
    for (int i = 0; i < channel_amount; i++) {
        vtun_syslog(LOG_INFO, "fss channel_info_vt send_q %u lport - %i rport - %i", channel_info_vt[i]->send_q, channel_info_vt[i]->lport,
                channel_info_vt[i]->rport);
        vtun_syslog(LOG_INFO, "fss channel_info_ss send_q %u lport - %i rport - %i", channel_info_ss[i]->send_q, channel_info_ss[i]->lport,
                channel_info_ss[i]->rport);
    }
    vtun_syslog(LOG_INFO, "fss conn_counter is %i", conn_counter);
#endif
    return 1;
}

/**
 * Parse netlink message to channel_info structure
 *
 * @param nlh
 * @param r
 * @return 0 - error and 1 as success
 */
int format_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r) {

    struct rtattr * tb[INET_DIAG_MAX + 1];
    struct tcp_info *info;

    parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr*) (r + 1), nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

    if (tb[INET_DIAG_INFO]) {
        int len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

        /* workaround for older kernels with less fields ???legacy??? */
        if (len < sizeof(*info)) {
            info = alloca(sizeof(*info));
            memset(info, 0, sizeof(*info));
            memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
        } else {
            info = RTA_DATA(tb[INET_DIAG_INFO]);
        }
    } else {
        return 0;
    }
    if (info == 0) {
        return 0;
    }

    memset(channel_info_ss[conn_counter], 0, sizeof(channel_info_ss));
    channel_info_ss[conn_counter]->snd_wscale = info->tcpi_snd_wscale;
    channel_info_ss[conn_counter]->rcv_wscale = info->tcpi_rcv_wscale;
    if (info->tcpi_rto && info->tcpi_rto != 3000000) {
        channel_info_ss[conn_counter]->rto = (double) info->tcpi_rto / 1000;
    }
    channel_info_ss[conn_counter]->rtt = (double) info->tcpi_rtt / 1000;
    channel_info_ss[conn_counter]->rtt_var = (double) info->tcpi_rttvar / 1000;
    channel_info_ss[conn_counter]->ato = (double) info->tcpi_ato / 1000;
    if (info->tcpi_snd_cwnd != 2) { // really need?
        channel_info_ss[conn_counter]->cwnd = info->tcpi_snd_cwnd;
    }
    if (info->tcpi_snd_ssthresh < 0xFFFF) {
        channel_info_ss[conn_counter]->ssthresh = info->tcpi_snd_ssthresh;
    }
    if (channel_info_ss[conn_counter]->rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
        channel_info_ss[conn_counter]->send = (uint32_t) ((double) info->tcpi_snd_cwnd * (double) info->tcpi_snd_mss * 1000.
                / channel_info_ss[conn_counter]->rtt);
    }
    channel_info_ss[conn_counter]->mss = info->tcpi_snd_mss;
    channel_info_ss[conn_counter]->rcv_rtt = (double) info->tcpi_rcv_rtt / 1000;
    channel_info_ss[conn_counter]->rcv_space = info->tcpi_rcv_space;
    return 1;
}
