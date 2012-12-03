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
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include "netlink_socket_info.h"
#include "lib.h"

struct {
    int dbs;
    int states;
    int families;
    struct ssfilter *f;
} filter;

int conn_counter,channel_amount_ss;
struct channel_info** channel_info_ss;

/*main parse function*/
static int tcp_show_sock(struct nlmsghdr *nlh, struct filter *f)
{
    struct inet_diag_msg *r = NLMSG_DATA(nlh);
    struct tcpstat s;

    s.state = r->idiag_state;
    s.local.family = s.remote.family = r->idiag_family;
    s.lport = ntohs(r->id.idiag_sport);
    s.rport = ntohs(r->id.idiag_dport);

#ifdef DEBUGG
        vtun_syslog(LOG_INFO, "fss all conns send_q - %i recv_q - %i lport - %i rport - %i", r->idiag_wqueue, r->idiag_rqueue, s.lport, s.rport);
#endif
        // fill channel_info structure
    if (conn_counter < channel_amount_ss) {
        for (int i = 0; i < channel_amount_ss; i++) {
            if ((channel_info_ss[i]->lport == ntohs(r->id.idiag_sport)) | (channel_info_ss[i]->rport == ntohs(r->id.idiag_dport))) {
                format_info(tcp_show_info(nlh, r));
                channel_info_ss[i]->recv_q = r->idiag_rqueue;
                channel_info_ss[i]->send_q = r->idiag_wqueue;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "fss conn_counter - %i channel_amount_ss - %i send_q - %i recv_q - %i lport - %i rport - %i", i, channel_amount_ss,
                        channel_info_ss[i]->send_q, channel_info_ss[i]->recv_q, s.lport, s.rport);
#endif
                conn_counter++;
                break;
            }
            if (i == (channel_amount_ss - 1)) {
                tcp_show_info(nlh, r);
            }
        }
    } else {
        tcp_show_info(nlh, r);
    }

    return 0;
}
int get_format_tcp_info(struct channel_info** channel_info_vt, int channel_amount) {
    int ret = 0;
    channel_info_ss = channel_info_vt;
    conn_counter = 0, channel_amount_ss = 0;
    memset(&filter, 0, sizeof(filter));
    filter.dbs = (1 << TCP_DB);
    filter.states = SS_ALL & ~((1 << SS_LISTEN) | (1 << SS_CLOSE) | (1 << SS_TIME_WAIT) | (1 << SS_SYN_RECV));
    filter.families = (1 << AF_INET) | (1 << AF_INET6);

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

    int fd;
    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0) {
        switch (errno) {
        case EMFILE:
            vtun_syslog(LOG_ERR, "Netlink - Too many open files.");
            break;
        default:
            vtun_syslog(LOG_ERR, "Netlink - Error: %s (%d).", strerror(errno), errno);
            break;
        }
        return -1;
    }
    memset(&buf, 0, sizeof(buf));
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    /* fill netlink message header */
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = 123456;
    memset(&req.r, 0, sizeof(req.r));
    /* fill Request structure */
    req.r.idiag_family = AF_INET;
    req.r.idiag_states = filter.states;
    /* for tcp info */
    req.r.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_CONG - 1));

    msg = (struct msghdr ) { .msg_name = (void*) &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = iov, .msg_iovlen = 1, };

    if (sendmsg(fd, &msg, 0) < 0) {
        vtun_syslog(LOG_ERR, "Netlink - Error:%s (%d).", strerror(errno), errno);
        return -1;
    }

    iov[0] = (struct iovec ) { .iov_base = buf, .iov_len = sizeof(buf) };
    while (1) {
        int status;
        struct nlmsghdr *h;

        msg = (struct msghdr ) { (void*) &nladdr, sizeof(nladdr), iov, 1, NULL, 0, 0 };

        status = recvmsg(fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR)
                vtun_syslog(LOG_WARNING, "Netlink - %s (%d).", strerror(errno), errno);
            continue;
            vtun_syslog(LOG_WARNING, "Netlink OVERRUN - %s (%d).", strerror(errno), errno);
            continue;
        }
        if (status == 0) {
            vtun_syslog(LOG_ERR, "Netlink - EOF on netlink");
            return -1;
        }

        h = (struct nlmsghdr*)buf;
            while (NLMSG_OK(h, status)) {
                int err;
                struct inet_diag_msg *r = NLMSG_DATA(h);

                if (/*h->nlmsg_pid != rth->local.nl_pid ||*/
                    h->nlmsg_seq != 123456)
                    goto skip_it;

                if (h->nlmsg_type == NLMSG_DONE) {
                    vtun_syslog(LOG_ERR, "Netlink NLMSG_DONE");
                    close(fd);
                    break;
                }
                if (h->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                    if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                        vtun_syslog(LOG_ERR, "Netlink ERROR truncated");
                    } else {
                        errno = -err->error;
                        vtun_syslog(LOG_ERR, "Netlink TCPDIAG answers");
                    }
                    return -1;
                }

            if (!(filter.families & (1 << r->idiag_family))) {
                h = NLMSG_NEXT(h, status);
                continue;
            }
            err = tcp_show_sock(h, NULL );
            if (err < 0) {
                vtun_syslog(LOG_ERR, "Netlink err - %i" err);
                return err;
            }

    skip_it:
                h = NLMSG_NEXT(h, status);
            }
            if (msg.msg_flags & MSG_TRUNC) {
                vtun_syslog(LOG_INFO, "Netlink Message truncated");
                continue;
            }
            if (status) {
                vtun_syslog(LOG_ERR, "Netlink !!!Remnant of size %d", status);
                ret = -1;
                break;
            }
        }
        if (close(fd) == -1) {
            vtun_syslog(LOG_ERR, "Netlink Unable to close socket: %d.", errno);
        }

#ifdef DEBUGG
    for (int i = 0; i < channel_amount; i++) {
        vtun_syslog(LOG_INFO, "Netlink fss channel_info_vt send_q %u lport - %i rport - %i", channel_info_vt[i]->send_q, channel_info_vt[i]->lport, channel_info_vt[i]->rport);
    }
    vtun_syslog(LOG_INFO, "Netlink fss conn_counter is %i", conn_counter);
#endif
    return 1;
}
