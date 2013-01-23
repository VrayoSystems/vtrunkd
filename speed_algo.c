/*
 * speed_algo.c
 *
 *  Created on: 22.01.2013
 *      Author: Kuznetsov Andrey
 */

#include <sys/time.h>
#include "speed_algo.h"

void speed_algo_ack_speed_hold(struct timeval *time_start, struct timeval *time_stop, int byte_was, int byte_now, struct speed_algo_rtt *ret) {
    struct timeval time_left;
    timersub(time_stop, time_start, &time_left);
    int byte_left = byte_was - byte_now;
    byte_left = byte_left < 0 ? 0 : byte_left;
    byte_left = time_left.tv_sec > 0 ? (byte_left / time_left.tv_sec) * 1000 : byte_left * 1000;
    ret->speed = (byte_left) / (time_left.tv_usec);
    ret->weight = byte_left > 2000 ? -1 : time_left.tv_sec * 10000 + time_left.tv_usec / 100;
}

void speed_algo_ack_rtt(int send_q, struct speed_algo_rtt *ret) {
    ret->rtt = ret->speed == 0 ? 0 : send_q / ret->speed;
}

int speed_algo_weighed_speed_avg(struct speed_algo_rtt *arr, int arr_size) {
    long int weight_amount = 0;
    int speed = 0, simple_avg_flag = 0;
    for (int i = 0; i < arr_size; i++) {
        if (arr[i].weight == -1){
            simple_avg_flag = 1;
            break;
        }
        weight_amount += arr[i].weight;
    }
    if (1) {
        for (int i = 0; i < arr_size; i++) {
            speed += (arr[i].speed * 10) / arr_size;
        }
    } else {
        for (int i = 0; i < arr_size; i++) {
            speed += (arr[i].speed * ((arr[i].weight * 1000) / weight_amount)) / 100;
        }
        speed = speed / 10 > 15 ? 150 : speed;
    }
    return speed / 10;
}

int speed_algo_avg(struct speed_algo_rtt *arr, int arr_size) {
    int speed = 0;
    for (int i = 0; i < arr_size; i++) {
        speed += arr[i].speed / arr_size;
    }
    return speed;
}
