/*
 * timer.c
 *
 *  Created on: 11.12.2013
 *      Author: Vrayo Systems Ltd. team
 */

#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include "timer.h"

struct timer_obj* create_timer() {
    return malloc(sizeof(struct timer_obj));
}

void free_timer(struct timer_obj *timer) {
    free(timer);
}

void set_timer(struct timer_obj *timer, struct timeval *timer_time) {
    memset(timer, 0, sizeof(struct timer_obj));
    gettimeofday(&(timer->start_time), NULL );
    memcpy(&(timer->timer_time), timer_time, sizeof(struct timeval));
}

void update_timer(struct timer_obj *timer){
    gettimeofday(&(timer->start_time), NULL );
}

void fast_update_timer(struct timer_obj *timer, struct timeval *cur_time){
    timer->start_time.tv_sec = cur_time->tv_sec;
    timer->start_time.tv_usec = cur_time->tv_usec;
}

int check_timer(struct timer_obj *timer) {
    gettimeofday(&timer->cur_time, NULL );
    timersub(&(timer->cur_time), &(timer->start_time), &(timer->tmp));
    return timercmp(&(timer->timer_time), &(timer->tmp), <=);
}

int fast_check_timer(struct timer_obj *timer, struct timeval *cur_time){
    timersub(cur_time, &(timer->start_time), &(timer->tmp));
    return timercmp(&(timer->timer_time), &(timer->tmp), <=);
}

struct timeval* get_difference_timer(struct timer_obj *timer, struct timeval *cur_time) {
    timersub(cur_time, &(timer->start_time), &(timer->tmp));
    return &(timer->tmp);
}

