/*
 * speed_algo.c
 *
 *  Created on: 22.01.2013
 *      Author: Kuznetsov Andrey
 */

#include <sys/time.h>
#include "speed_algo.h"

/**
 * Function for ACK_coming_speed = bytes_left/time.
 * Idea - was + more = now + left --> left = was + more - now
 *
 * @param time_start
 * @param time_stop
 * @param byte_was
 * @param byte_now
 * @param byte_more
 * @return speed or error -1 - byte_more overflow, -2 - bad measure or speed --> 0, -3 - high speed, need wait one more time
 */
int speed_algo_ack_speed(struct timeval *time_start, struct timeval *time_stop, int byte_was, int byte_now, int byte_more) {
    int speed = 0;
    struct timeval time_left;
    if (byte_more < 0) {
        return SPEED_ALGO_SLOW_SPEED;
    }
    int byte_left = byte_was + byte_more - byte_now;
    if (byte_left <= 0) {
        return SPEED_ALGO_OVERFLOW;
    }
    timersub(time_stop, time_start, &time_left);
    if (timercmp(&time_left, &((struct timeval) {0, 200}), <)) {
        return SPEED_ALGO_HIGH_SPEED;
    }
    int time_left_ms = time_left.tv_sec * 10000; // in ms*10
    time_left_ms += time_left.tv_usec / 100;
    speed = (byte_left * 10) / time_left_ms;
    return speed;
}

/**
 * Function for ACK_coming_speed averaging
 * @param arr
 * @param arr_size - size of *arr
 * @param new_speed - new value which will be add
 * @param counter - current pointer in *arr
 * @return speed average
 */
int speed_algo_avg_speed(struct speed_algo_rtt_speed *arr, int arr_size, int new_speed, int *counter) {
    int speed_avg = 0;
    arr[*counter++].speed = new_speed;
    for (int i = 0; i < arr_size; i++) {
        speed_avg += arr[i].speed * 10 / arr_size;
    }
    *counter = *counter == arr_size ? 0 : *counter;
    return speed_avg / 10;
}

