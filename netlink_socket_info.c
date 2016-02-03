/*
 * netlink_socket_info.c

 *
 * According by ss from iproute2 and fss is written by Matt Tierney
 *
 *  Created on: 30.11.2012
 *       Copyright (C) 2011-2016 Vrayo Systems Ltd. team 
 */

#include <sys/socket.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
int conn_counter, channel_amount_ss;
struct channel_info* channel_info_ss;

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
static int tcp_show_sock(struct nlmsghdr *nlh, struct filter *f);
static int tcp_show_netlink(struct filter *f, FILE *dump_fp, int socktype);
int format_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r);

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len)
        vtun_syslog(LOG_ERR, "Netlink - !!!Deficit %d, rta_len=%d", len, rta->rta_len);
    return 0;
}

/*main parse function*/
static int tcp_show_sock(struct nlmsghdr *nlh, struct filter *f) {
    struct inet_diag_msg *r = NLMSG_DATA(nlh);
    // fill channel_info structure
    if (conn_counter < channel_amount_ss) {
        for (int i = 0; i < channel_amount_ss; i++) {
            if ((channel_info_ss[i].lport == ntohs(r->id.idiag_sport)) & (channel_info_ss[i].rport == ntohs(r->id.idiag_dport))) {
                format_info(nlh, r);
                channel_info_ss[i].recv_q = r->idiag_rqueue;
                channel_info_ss[i].send_q = r->idiag_wqueue;
#ifdef TRACE
                vtun_syslog(LOG_INFO, "fss conn_counter - %i channel_amount_ss - %i send_q - %i recv_q - %i lport - %i rport - %i", i,
                        channel_amount_ss, channel_info_ss[i].send_q, channel_info_ss[i].recv_q, ntohs(r->id.idiag_sport),
                        ntohs(r->id.idiag_dport));
#endif
                conn_counter++;
                break;
            }
        }
    }

    return 1;
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
    struct iovec iov;

    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0) {
        switch (errno) {
        case EMFILE:
            vtun_syslog(LOG_ERR, "Netlink - Too many open files.");
            break;
        default:
            vtun_syslog(LOG_ERR, "Netlink - Error: %s (%d)", strerror(errno), errno);
            break;
        }
        return 0;
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

// show_mem - don't use
//        req.r.idiag_ext |= (1 << (INET_DIAG_MEMINFO - 1));

    //show tcp info such as send_q, cwnd...
    req.r.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_CONG - 1));

    iov.iov_base = &req;
    iov.iov_len = sizeof(req);

    msg.msg_name = (void*) &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1; // iov can be array of structure
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    if (sendmsg(fd, &msg, 0) < 0)
    {
        vtun_syslog(LOG_ERR, "Netlink - Cannot send netlink message: %s (%d)", strerror(errno), errno);
        return 0;
    }
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    while (1) {
        int status;
        struct nlmsghdr *h;

        msg = (struct msghdr ) { (void*) &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

        status = recvmsg(fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR) {
                vtun_syslog(LOG_ERR, "Netlink - EINTR, continue...");
                continue;
            }
            vtun_syslog(LOG_ERR, "Netlink - OVERRUN: %s (%d)", strerror(errno), errno);
            continue;
        }
        if (status == 0) {
            vtun_syslog(LOG_ERR, "Netlink - EOF on netlink");
            return 0;
        }

        h = (struct nlmsghdr*) buf;
        while (NLMSG_OK(h, status)) {

            int err;
            struct inet_diag_msg *r = NLMSG_DATA(h);

            if (/*h->nlmsg_pid != rth->local.nl_pid ||*/
            h->nlmsg_seq != 123456)
                goto skip_it;

            if (h->nlmsg_type == NLMSG_DONE) {
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "Netlink - NLMSG_DONE");
#endif
                close(fd);
                return 1;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(h);
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    vtun_syslog(LOG_ERR, "Netlink - ERROR truncated");
                } else {
                    errno = -err->error;
                    vtun_syslog(LOG_ERR, "Netlink - TCPDIAG answers: %s (%d)", strerror(errno), errno);
                }
                return 0;
            }
            if (!dump_fp) {
                if (!(f->families & (1 << r->idiag_family))) {
                    h = NLMSG_NEXT(h, status);
                    continue;
                }
                if(!tcp_show_sock(h, NULL )){
                    vtun_syslog(LOG_ERR, "Netlink - tcp_show_sock return error");
                    return 0;
                }

            }

            skip_it: h = NLMSG_NEXT(h, status);
        }
        if (msg.msg_flags & MSG_TRUNC) {
            vtun_syslog(LOG_ERR, "Netlink - Message truncated");
            continue;
        }
        if (status) {
            vtun_syslog(LOG_ERR, "Netlink - !!!Remnant of size %d", status);
            return 0;
        }
    }
    if (close(fd) == -1) {
        vtun_syslog(LOG_ERR, "Netlink - Unable to close socket: %s (%d)", strerror(errno), errno);
    }
    return 1;
}

/**
 * Function get from **channel_info_vt port's num and fill information about tcp connection
 * @param channel_info_vt
 * @param channel_amount - *channel_info_vt[] array length
 * @return 1 if succes end 0 if error
 */
int get_format_tcp_info(struct channel_info* channel_info_vt, int channel_amount) {
    channel_info_ss = channel_info_vt;
    channel_amount_ss = channel_amount;
    conn_counter = 0;

    clear_channel_info(channel_info_ss, channel_amount_ss);

    memset(&current_filter, 0, sizeof(current_filter));

    current_filter.states = default_filter.states;
    current_filter.dbs = default_filter.dbs;
    current_filter.families = default_filter.families;

    if(!tcp_show_netlink(&current_filter, NULL, TCPDIAG_GETSOCK)) {
        vtun_syslog(LOG_ERR, "Netlink - return error");
        return 0; // 0 - error 1 - success
    }
#ifdef TRACE
    for (int i = 0; i < channel_amount; i++) {
        vtun_syslog(LOG_INFO, "fss channel_info_vt send_q %u lport - %i rport - %i", channel_info_vt[i].send_q, channel_info_vt[i].lport,
                channel_info_vt[i].rport);
        vtun_syslog(LOG_INFO, "fss channel_info_ss send_q %u lport - %i rport - %i", channel_info_ss[i].send_q, channel_info_ss[i].lport,
                channel_info_ss[i].rport);
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
        if (len < (int) sizeof(*info)) {
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

    channel_info_ss[conn_counter].snd_wscale = info->tcpi_snd_wscale;
    channel_info_ss[conn_counter].rcv_wscale = info->tcpi_rcv_wscale;
    if (info->tcpi_rto && info->tcpi_rto != 3000000) {
        channel_info_ss[conn_counter].rto = (double) info->tcpi_rto / 1000;
    }
    channel_info_ss[conn_counter].rtt = (double) info->tcpi_rtt / 1000;
    channel_info_ss[conn_counter].rtt_var = (double) info->tcpi_rttvar / 1000;
    channel_info_ss[conn_counter].ato = (double) info->tcpi_ato / 1000;
    if (info->tcpi_snd_cwnd != 2) { // really need?
        channel_info_ss[conn_counter].cwnd = info->tcpi_snd_cwnd;
    }
    if (info->tcpi_snd_ssthresh < 0xFFFF) {
        channel_info_ss[conn_counter].ssthresh = info->tcpi_snd_ssthresh;
    }
    if (channel_info_ss[conn_counter].rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
        channel_info_ss[conn_counter].send = (uint32_t) ((double) info->tcpi_snd_cwnd * (double) info->tcpi_snd_mss * 1000.
                / channel_info_ss[conn_counter].rtt);
    }
    channel_info_ss[conn_counter].mss = info->tcpi_snd_mss;
    channel_info_ss[conn_counter].rcv_rtt = (double) info->tcpi_rcv_rtt / 1000;
    channel_info_ss[conn_counter].rcv_space = info->tcpi_rcv_space;
    return 1;
}

void clear_channel_info(struct channel_info* channel_info, int channel_amount) {
    int lport, rport;
    for (int i = 0; i < channel_amount; i++) {
        lport = channel_info[i].lport;
        rport = channel_info[i].rport;
        memset(&(channel_info[i]), 0, sizeof(channel_info));
        channel_info[i].lport = lport;
        channel_info[i].rport = rport;
    }
}
