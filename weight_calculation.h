/*
 * weight_calculation.h
 *
 *  Created on: 07.06.2012
 *      Author: Kuznetsov Andrey
 */

#ifndef WEIGHT_CALCULATION_H_
#define WEIGHT_CALCULATION_H_
#include "vtun.h"
long int weight_landing_sub_div(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, struct timeval cur_time, int my_conn_num);
long int weight_landing_sub(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, struct timeval cur_time, int my_conn_num);
long int weight_trend_to_start(long int weight, struct vtun_host *lfd_host);
long int weight_trend_to_zero(long int weight, struct vtun_host *lfd_host);
long int weight_add_delay(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, int mean_delay, int my_conn_num);

#endif /* WEIGHT_CALCULATION_H_ */
