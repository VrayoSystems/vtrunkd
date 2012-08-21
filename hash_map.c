/*
 * hash_map.c
 *
 *  Created on: 21.08.2012
 *      Author: Andrey Kuznetsov
 *      email:  andreykyz@gmail.com
 */

#include <semaphore.h>
#include <string.h>
#include "hash_map.h"
#include "vtun.h"

int get_loop_back_shift(int shift, int index, int length);
int get_loop_forward_shift(int shift, int index, int length);

/**
 * Add packet to tail
 *
 * This function is synchronized by map->resend_buf_sem
 */
unsigned long add_packet(struct packet_hash_map *map, int logical_channel, char *packet, size_t packet_length, int sender_pid) {
    sem_wait(&(map->resend_buf_sem));
    map->index = get_loop_forward_shift(1, map->index, RESEND_BUF_SIZE);
    memcpy(&(map->data[map->index].packet), packet, packet_length);
    map->data[map->index].sender_pid = sender_pid;
    unsigned long seq_num = ++map->last_seq_num;
    sem_post(&(map->resend_buf_sem));
    return seq_num;
}

/**
 *
 * This function is synchronized by map->resend_buf_sem
 */
struct hashed_packet* get_packet_by_seq(struct packet_hash_map *map, unsigned long seq_num) {
    int new_index, shift;
    struct hashed_packet* packet;
    sem_wait(&(map->resend_buf_sem));
    shift = map->last_seq_num - seq_num;
    if (shift >= RESEND_BUF_SIZE) {
        sem_post(&(map->resend_buf_sem));
        return NULL; // seq_num not found
    } else {
        new_index = get_loop_back_shift(shift, map->index, RESEND_BUF_SIZE);
        packet = &(map->data[new_index]);
        sem_post(&(map->resend_buf_sem));
        return packet;
    }
}

struct hashed_packet* get_last_packet(struct packet_hash_map *map) {
    struct hashed_packet* packet;
    sem_wait(&(map->resend_buf_sem));
    packet = &(map->data[map->index]);
    sem_post(&(map->resend_buf_sem));
    return packet;
}

/**
 * This function is synchronized by map->resend_buf_sem
 */
unsigned long get_last_seq_num(struct packet_hash_map *map) {
    unsigned long seq_num;
    sem_wait(&(map->resend_buf_sem));
    seq_num = map->last_seq_num;
    sem_post(&(map->resend_buf_sem));
    return seq_num;
}

/**
 * Function return new array's index
 */
int get_loop_back_shift(int shift, int index, int length) {
    if (shift > index) {
        return length - (shift - index);
    } else {
        return index - shift;
    }
}

/**
 * Function return new array's index
 */
int get_loop_forward_shift(int shift, int index, int length) {
    if ((length - index) <= shift) {
        return shift - (length - index);
    } else {
        return shift + index;
    }
}
