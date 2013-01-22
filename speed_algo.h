/*
 * speed_algo.h
 *
 *  Created on: 22.01.2013
 *      Author: Kuznetsov Andrey
 */

#ifndef SPEED_ALGO_H_
#define SPEED_ALGO_H_

#include <sys/time.h>

#define SPEED_AVG_ARR 15

struct speed_algo_rtt{
    int rtt;
    int speed;
    int weight;
};

void speed_algo_ack_speed_hold(struct timeval *time_start, struct timeval *time_stop, int byte_was, int byte_now, struct speed_algo_rtt *ret);
void speed_algo_ack_rtt(int send_q, struct speed_algo_rtt *ret);
int speed_algo_avg_speed(struct speed_algo_rtt *arr, int arr_size, struct speed_algo_rtt *ret);
int speed_algo_weighed_speed_avg(struct speed_algo_rtt *arr, int arr_size);

#endif /* SPEED_ALGO_H_ */
