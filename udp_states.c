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

#include "udp_states.h"

const char udp_stat_path[] = "/proc/net/udp";

int get_udp_stats(struct udp_stats* udp_struct, int conn_amount) {
    char line[256];
    FILE * f = fopen(udp_stat_path, "r");
    //skip title
    if (fgets(line, sizeof(line), f) == NULL) {
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


    }

    return 1;
}

int add_line(char* line, struct udp_stats* udp_struct, int conn_amount) {

    struct tcpstat s;
    char *loc, *rem, *data;
    char opt[256];
    int n;
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

    int         sscanf(loc, "%x:%x", s.local.data, (unsigned*)&s.lport);
    sscanf(rem, "%x:%x", s.remote.data, (unsigned*)&s.rport);

    for (int i = 0; i < conn_amount; i++) {

    }

    return 1;
}
