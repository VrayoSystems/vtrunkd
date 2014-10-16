/*
 * udp_states.c
 *
 *  Created on: 15.10.2014
 *      Author: Andrey Kuznetsov
 *
 *
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "udp_states.h"

const char udp_stat_path[] = "/proc/net/udp";

int add_line(char* line, struct udp_stats* udp_struct, int conn_amount);

int get_udp_stats(struct udp_stats* udp_struct, int conn_amount) {
    char line[256];
    int line_counter = 0;
    FILE * f = fopen(udp_stat_path, "r");
    //skip title
    if (fgets(line, sizeof(line), f) == NULL ) {
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        int n = strlen(line);
        if (n == 0 || line[n - 1] != '\n') {
            errno = -EINVAL;
            return 0;
        }
        line[n - 1] = 0;
        // line handling
        line_counter += add_line(line, udp_struct, conn_amount);
        if (line_counter == conn_amount) {
            return 1;
        }
    }
    return 0;
}

int add_line(char* line, struct udp_stats* udp_struct, int conn_amount) {
    int lport = 0, rport = 0;
    unsigned int ldata[8], rdata[8];
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

    sscanf(loc, "%x:%x", (unsigned int *) ldata, (unsigned*) &lport);
    sscanf(rem, "%x:%x", (unsigned int *) rdata, (unsigned*) &rport);

    for (int i = 0; i < conn_amount; i++) {
        if ((lport == udp_struct[i].lport) && (rport == udp_struct[i].rport)) {
            opt[0] = 0;
            n = sscanf(data, "%x %x:%x %*x:%*x %*x %d %*d %u %d %llx %[^\n]\n", &udp_struct[i].state, &udp_struct[i].tx_q, &udp_struct[i].rx_q,
                    &udp_struct[i].uid, &udp_struct[i].ino, &udp_struct[i].refcnt, &udp_struct[i].sk, opt);
            if (n < 9)
                opt[0] = 0;
            ret = 1;
            break;
        }
    }
    return ret;
}
