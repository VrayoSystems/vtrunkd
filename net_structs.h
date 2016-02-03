/*
 * net_structs.h
 *
 *  Created on: 04.07.2012
 *      Author: Vrayo Systems Ltd. team 
 */

#ifndef NET_STRUCTS_H_
#define NET_STRUCTS_H_
#include <stdint.h>

/**
 * simple info packet
 */
struct info_packet {
	uint32_t data;
	uint16_t flag;
};
/**
 * Struct for pack/unpack time lag
 * based on info_packet
 * contain info_packet + uint16_t
 */
struct time_lag_packet {
	uint32_t time_lag;
	uint16_t flag;
	uint16_t pid;
};

#endif /* NET_STRUCTS_H_ */
