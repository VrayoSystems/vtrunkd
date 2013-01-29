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
#define SPEED_ALGO_SLOW_SPEED -1
#define SPEED_ALGO_OVERFLOW -2
#define SPEED_ALGO_HIGH_SPEED -3

struct speed_algo_rtt_speed {
    int rtt;
    int speed;
};

int speed_algo_ack_speed(struct timeval *time_start, struct timeval *time_stop, int byte_was, int byte_now, int byte_more);
int speed_algo_avg_speed(struct speed_algo_rtt_speed *arr, int arr_size, int new_speed, int *counter);

#endif /* SPEED_ALGO_H_ */
