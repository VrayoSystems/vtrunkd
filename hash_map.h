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

unsigned long add_packet(struct packet_hash_map *map, int logical_channel, char *packet, size_t packet_length, int sender_pid);
unsigned long get_last_seq_num(struct packet_hash_map *map);
struct hashed_packet* get_packet_by_seq(struct packet_hash_map *map, unsigned long seq_num);

#endif /* HASH_MAP_ */
