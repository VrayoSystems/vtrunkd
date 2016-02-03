/*
 * udp_states.c
 *
 *  Created on: 15.10.2014
 *      Author: Vrayo Systems Ltd. team
 *
 *
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syslog.h>

#include "udp_states.h"
#include "lib.h"
#include "log.h"

const char udp_stat_path[] = "/proc/net/udp";

int add_line(char* line, struct udp_stats* udp_struct, int conn_amount);

int get_udp_stats(struct udp_stats* udp_struct, int conn_amount) {
    char line[256];
    int line_counter = 0;
    FILE * f = fopen(udp_stat_path, "r");
    if (f == NULL ) {
        vlog(LOG_ERR, "udp_stats %s open fail reason %s (%d)", udp_stat_path, strerror(errno), errno);
        return 0;
    }
    //skip title
    if (fgets(line, sizeof(line), f) == (char *) EOF) {
        vlog(LOG_ERR, "udp_stats fgets EOF title reason %s (%d)", strerror(errno), errno);
        if (fclose(f) == EOF) {
            vlog(LOG_ERR, "udp_stats file close err %s (%d)", strerror(errno), errno);
        }
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        int n = strlen(line);
        if (n == 0 || line[n - 1] != '\n') {
            errno = -EINVAL;
            if (fclose(f) == EOF) {
                vlog(LOG_ERR, "udp_stats file close err %s (%d)", strerror(errno), errno);
            }
            return 0;
        }
        line[n - 1] = 0;
        // line handling
        line_counter += add_line(line, udp_struct, conn_amount);
        if (line_counter == conn_amount) {
            if (fclose(f) == EOF) {
                vlog(LOG_ERR, "udp_stats file close err %s (%d)", strerror(errno), errno);
            }
            return 1;
        }
    }
    vlog(LOG_ERR, "udp connection not found reason %s (%d)", strerror(errno), errno);
    if (fclose(f) == EOF) {
        vlog(LOG_ERR, "udp_stats file close err %s (%d)", strerror(errno), errno);
    }
    return 0;
}

int add_line(char* line, struct udp_stats* udp_struct, int conn_amount) {
    int lport = 0, rport = 0;
    char *loc, *rem, *data;
    char opt[256];
    int n, ret = 0;
    char *p;

    if ((p = strchr(line, ':')) == NULL )
        return -1;
    loc = p + 2;

    if ((p = strchr(loc, ':')) == NULL )
        return -1;
    p[5] = 0;
    rem = p + 6;

    if ((p = strchr(rem, ':')) == NULL )
        return -1;
    p[5] = 0;
    data = p + 6;

    sscanf(loc, "%*x:%x", (unsigned*) &lport);
    sscanf(rem, "%*x:%x", (unsigned*) &rport);

    for (int i = 0; i < conn_amount; i++) {
        if ((lport == udp_struct[i].lport) && (rport == udp_struct[i].rport)) {
            udp_struct[i].drops = 0;
            n = sscanf(data, "%x %x:%x %*x:%*x %*x %d %*d %u %d %llx %d", &udp_struct[i].state, &udp_struct[i].tx_q, &udp_struct[i].rx_q,
                    &udp_struct[i].uid, &udp_struct[i].ino, &udp_struct[i].refcnt, &udp_struct[i].sk, &udp_struct[i].drops);
            if (n < 9)
                udp_struct[i].drops = 0;
            ret = 1;
            break;
        }
    }
    return ret;
}
