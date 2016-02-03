/*
 * speed_algo.c
 *
 *  Created on: 22.01.2013
 *      Author: Vrayo Systems Ltd. team
 */

#include <sys/time.h>
#include <syslog.h>
#include <stdint.h>
#include "speed_algo.h"
#include "lib.h"

/**
 * Function for ACK_coming_speed = bytes_acked/time.
 * Idea - was + more = now + acked --> acked = was + more - now
 *
 * @param time_start
 * @param time_stop
 * @param byte_was
 * @param byte_now
 * @param byte_more
 * @return speed or error -1 - byte_more overflow, -2 - bad measure or speed --> 0, -3 - high speed, need wait one more time
 */
int speed_algo_ack_speed(struct timeval *time_start, struct timeval *time_stop, int byte_was, int byte_now, int byte_more, int min_time_usec) {
    int speed = 0;
    struct timeval time_passed;
    timersub(time_stop, time_start, &time_passed);
#ifdef DEBUGG
    vtun_syslog(LOG_INFO,"was %i + more %i == acked %i + now %i  / time_passed - %ul s %ul us, min_time_usec = %i", byte_was, byte_more,byte_was + byte_more - byte_now, byte_now, time_passed.tv_sec, time_passed.tv_usec, min_time_usec);
#endif
    if (byte_more < 0) {
        return SPEED_ALGO_OVERFLOW;
    }
    int byte_acked = byte_was + byte_more - byte_now;
    if (byte_acked <= 1000) {
        if (timercmp(&time_passed, &((struct timeval) {SPEED_ALGO_EPIC_TIME_S, SPEED_ALGO_EPIC_TIME_US}), <)) {
            return SPEED_ALGO_SLOW_SPEED;
        } else {
            return SPEED_ALGO_EPIC_SLOW;
        }
    }
    if (timercmp(&time_passed, &((struct timeval) {0, min_time_usec}), <)) {
        return SPEED_ALGO_HIGH_SPEED;
    }
    int time_passed_ms = time_passed.tv_sec * (1000000/100); // in ms*10
    time_passed_ms += time_passed.tv_usec / 100;
    speed = (byte_acked * 10) / time_passed_ms;
#ifdef TRACE
    vtun_syslog(LOG_INFO,"speed_moment - %i", speed);
#endif
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
int speed_algo_avg_speed(int32_t *arr, int arr_size, int new_speed, int *counter) {
    int speed_avg = 0;
#ifdef TRACE
    vtun_syslog(LOG_INFO,"new_speed - %i counter - %i",new_speed, *counter);
#endif
    (*counter)++;
    *counter = *counter == arr_size ? 0 : *counter;
    arr[*counter] = new_speed;
    for (int i = 0; i < arr_size; i++) {
#ifdef TRACE
        vtun_syslog(LOG_INFO,"speed[%i] - %i",i, arr[i] );
#endif
        speed_avg += arr[i] * 100 / arr_size;
    }
    return speed_avg / 100;
}

