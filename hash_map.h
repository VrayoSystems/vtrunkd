/*
 * hash_map
 *
 *  Created on: 21.08.2012
 *      Author: Andrey Kuznetsov
 *      email: andreykyz@gmail.com
 */

#ifndef HASH_MAP_
#define HASH_MAP_

#include "vtun.h"

unsigned long add_packet(struct packet_hash_map *map, int logical_channel, char *packet, int packet_length, int sender_pid);

#endif /* HASH_MAP_ */
