/*
 * timer.h
 *
 *  Created on: 11.12.2013
 *      Author: Vrayo Systems Ltd. team
 */

#ifndef TIMER_H_
#define TIMER_H_

#include <sys/time.h>

struct timer_obj {
    struct timeval start_time;
    struct timeval timer_time;
    struct timeval cur_time;
    struct timeval tmp;
};

struct timer_obj* create_timer();
void free_timer(struct timer_obj *timer);

void set_timer(struct timer_obj *timer, struct timeval *timer_time);
void update_timer(struct timer_obj *timer);
void fast_update_timer(struct timer_obj *timer, struct timeval *cur_time);
int check_timer(struct timer_obj *timer);
int fast_check_timer(struct timer_obj *timer, struct timeval *cur_time);
struct timeval* get_difference_timer(struct timer_obj *timer, struct timeval *cur_time);

#endif /* TIMER_H_ */
