/*
 * weight_calculation.c
 *
 *  Created on: 07.06.2012
 *      Author: Kuznetsov Andrey
 */
#include "weight_calculation.h"
#include "vtun.h" // for MAX_AG_CONN, MIN_WEIGHT

/**
 * Weight landing - lfd_host->WEIGHT_SAW_STEP_DN_DIV division subtract method
 *
 * @param shm_conn_info
 * @param lfd_host - the parameters which are extracted from the configuration file.
 * @param cur_time - current time
 * @param my_conn_num - the calling process (CONNection)
 * @return - the calling process weight
 */
long int inline weight_landing_sub_div(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, struct timeval cur_time, int my_conn_num) {
	long int min_weight = MIN_WEIGHT;
	for (int j = 0; j < MAX_AG_CONN; j++) {
		if ((shm_conn_info->stats[j].pid != 0) && (shm_conn_info->stats[j].weight < min_weight)
				&& ((cur_time.tv_sec - shm_conn_info->stats[j].last_tick) < lfd_host->RXMIT_CNT_DROP_PERIOD + 2)) {
			min_weight = shm_conn_info->stats[j].weight;
		}
	}

	if (min_weight == MIN_WEIGHT)
		min_weight = shm_conn_info->stats[my_conn_num].weight;

	for (int j = 0; j < MAX_AG_CONN; j++) {
		if ((shm_conn_info->stats[j].pid != 0) && ((cur_time.tv_sec - shm_conn_info->stats[j].last_tick) < lfd_host->RXMIT_CNT_DROP_PERIOD + 2)) {
			if (shm_conn_info->stats[j].weight == min_weight)
				shm_conn_info->stats[j].weight = 0;
			else {
				/*
				 * Here lies the "direct close-up problem": for DN DIV the DIV value is usually
				 * smaller than for UP; so the impact on DN of close-up is much lower since
				 * it will still smoothen step-downs while wtep-ups will come unsmoothed
				 * at this threshold
				 */
				shm_conn_info->stats[j].weight -= min_weight / lfd_host->WEIGHT_SAW_STEP_DN_DIV;
			}
		}
	}

	return shm_conn_info->stats[my_conn_num].weight;

}

/**
 * Weight landing - subtruct min_weight method
 *
 * @param shm_conn_info
 * @param lfd_host - the parameters which are extracted from the configuration file.
 * @param cur_time - current time
 * @param my_conn_num - the calling process (CONNection)
 * @return - the calling process weight
 */
long int inline weight_landing_sub(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, struct timeval cur_time, int my_conn_num) {
	long int min_weight = MIN_WEIGHT;
	for (int j = 0; j < MAX_AG_CONN; j++) {
		// WARNING! may be problems here if MIN belongs to a dead process! TODO some watchdog
		if ((shm_conn_info->stats[j].pid != 0) && (shm_conn_info->stats[j].weight < min_weight)
				&& ((cur_time.tv_sec - shm_conn_info->stats[j].last_tick) < lfd_host->RXMIT_CNT_DROP_PERIOD + 2))
			min_weight = shm_conn_info->stats[j].weight;
	}
	if (min_weight == MIN_WEIGHT)
		min_weight = shm_conn_info->stats[my_conn_num].weight;
	for (int j = 0; j < MAX_AG_CONN; j++) {
		if ((shm_conn_info->stats[j].pid != 0) && ((cur_time.tv_sec - shm_conn_info->stats[j].last_tick) < lfd_host->RXMIT_CNT_DROP_PERIOD + 2))
			shm_conn_info->stats[j].weight -= min_weight;
	}

	return shm_conn_info->stats[my_conn_num].weight;
}
/**
 * The function trend weight to the START_WEIGHT
 *
 * @param weight - for recalculation
 * @return - recalculation weight
 */
long int inline weight_trend_to_start(long int weight, struct vtun_host *lfd_host) {
	if (lfd_host->WEIGHT_START_STICKINESS > 0) {
		weight = ((weight - lfd_host->START_WEIGHT) / lfd_host->WEIGHT_START_STICKINESS) + lfd_host->START_WEIGHT;
		if (weight < 0) {
			weight = 0;
		}
	}
	return weight;
}
/**
 * The function trend weight to the zero ( 0 )
 *
 * @param weight - for recalculation
 * @return - recalculation weight
 */
long int inline weight_trend_to_zero(long int weight, struct vtun_host *lfd_host) {
	if (lfd_host->WEIGHT_SMOOTH_DIV > 0) {
		weight = weight / lfd_host->WEIGHT_SMOOTH_DIV;
		if (weight < 0) {
			weight = 0;
		}
	}
	return weight;
}
/**
 * The function add delay to weight. More delay - more weight.
 * More weight - more time for wait(weight == penalty).
 * The function share weight to shm and return it.
 *
 * @param shm_conn_info
 * @param lfd_host - the parameters which are extracted from the configuration file.
 * @param mean_delay - new arithmetic(al) mean delay
 * @param my_conn_num - the calling process (CONNection)
 * @return - new weight of the calling process
 */
long int inline weight_add_delay(struct conn_info *shm_conn_info, struct vtun_host *lfd_host, int mean_delay, int my_conn_num) {
	if ((mean_delay > lfd_host->WEIGHT_SAW_STEP_UP_DIV) && (mean_delay > lfd_host->WEIGHT_SAW_STEP_UP_MIN_STEP)) { // increase reverse weight..
		if ((mean_delay / lfd_host->WEIGHT_SAW_STEP_UP_DIV) < lfd_host->MAX_WEIGHT_NORM) { // ignore noize peaks...
			shm_conn_info->stats[my_conn_num].weight += (mean_delay / lfd_host->WEIGHT_SAW_STEP_UP_DIV);
		} else {
			shm_conn_info->stats[my_conn_num].weight += mean_delay; // to have a direct close-up
		}
	} else {
		shm_conn_info->stats[my_conn_num].weight += lfd_host->WEIGHT_SAW_STEP_UP_MIN_STEP;
	}

	return shm_conn_info->stats[my_conn_num].weight;
}
