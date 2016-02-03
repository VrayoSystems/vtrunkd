/*
 * packet_code.c
 *
 *  Created on: 03.04.2014
 *       Copyright (C) 2011-2016 Vrayo Systems Ltd. team 
 */

#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "frame_llist.h"
#include "packet_code.h"
#include "lib.h"
#include "defines.h"

void sum_init(struct packet_sum* sum, uint32_t start_seq, uint32_t stop_seq, int my_selection_num, size_t packet_len) {
    memset(sum->sum, 0, packet_len);
    sum->len_sum = 0;
    sum->start_seq = start_seq;
    sum->stop_seq = stop_seq;
    sum->current_seq = 0;
    sum->my_selection_num = my_selection_num;
#ifdef CODE_LOG
    vtun_syslog(6, "func sum_init selection %d seq start %"PRIu32" stop %"PRIu32" len %i", my_selection_num, start_seq, stop_seq, packet_len);
#endif
}

__attribute__ ((section ("code_packing"))) void add_packet_code(char* restrict packet, struct packet_sum* restrict sum, uint16_t packet_len) {
    uint16_t i = 0;
    for (; i + sizeof(uint64_t) < packet_len; i += sizeof(uint64_t)) {
        *(uint64_t*) (sum->sum + i) ^= *(uint64_t*) (packet + i);
    }
    for (; i < packet_len; i++) {
        *(uint8_t*) (sum->sum + i) ^= *(uint8_t*) (packet + i);
    }
    if (sum->len_sum < packet_len)
        sum->len_sum = packet_len;
}

void del_packet_code(struct packet_sum* sum, int index) {
    sum[index].len_sum = 0;
    sum[index].start_seq = 0;
    sum[index].stop_seq = 0;
    sum[index].my_selection_num = 0;
}

int add_redundancy_packet_code(struct packet_sum *sum, int *bulk_counter, char* packet, size_t packet_len) {
    uint32_t start_seq, stop_seq;
    uint16_t my_selection_num_n;
    // load redundancy code and range
    memcpy(&start_seq, packet, sizeof(uint32_t));
    memcpy(&stop_seq, packet + packet_len - (sizeof(uint32_t) + sizeof(uint16_t)), sizeof(uint32_t));
    start_seq = ntohl(start_seq);
    stop_seq = ntohl(stop_seq);
    for (int i = 0; i < BULK_BUFFER_PACKET_CODE; i++) {
        if ((sum[i].start_seq == start_seq) && (sum[i].stop_seq == stop_seq)) {
            return i;
        }
    }
    memcpy(&my_selection_num_n, packet + packet_len - sizeof(uint16_t), sizeof(uint16_t));
    sum[*bulk_counter].start_seq = start_seq;
    sum[*bulk_counter].stop_seq = stop_seq;
    sum[*bulk_counter].my_selection_num = ntohs(my_selection_num_n);
    sum[*bulk_counter].len_sum = packet_len - (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t));
    memcpy(sum[*bulk_counter].sum, packet + sizeof(uint32_t) + sizeof(uint16_t), sum[*bulk_counter].len_sum);
#ifdef CODE_LOG
    vtun_syslog(6, "func add_redundancy_packet_code selection %i start_seq %"PRIu32" %"PRIu32" stop_seq %"PRIu32" len %i", sum[*bulk_counter].my_selection_num, sum[*bulk_counter].start_seq,ntohl(start_seq_n), sum[*bulk_counter].stop_seq, sum[*bulk_counter].len_sum);
#endif
    int lastCounter = *bulk_counter;
    //iterate the sum recv buffer
    if (++*bulk_counter == BULK_BUFFER_PACKET_CODE) {
        *bulk_counter = 0;
    }
    return lastCounter;
}

int pack_redundancy_packet_code(char *buf, struct packet_sum* sum, uint32_t seq_counter, int selection, int flag) {
    memcpy(buf + sizeof(uint16_t) + sizeof(uint32_t), sum->sum, sum->len_sum);
    int len_sum = sum->len_sum + sizeof(uint32_t) + sizeof(uint16_t);
    uint16_t FRAME_REDUNDANCY_CODE_n = htons(flag);
    uint32_t start_seq_n = htonl(sum->start_seq);
    uint32_t stop_seq_n = htonl(sum->stop_seq);
    sum_init(sum, seq_counter + SELECTION_NUM, seq_counter + REDUNDANCY_CODE_LAG, selection, 1500);
    memcpy(buf, &start_seq_n, sizeof(uint32_t));
    memcpy(buf + sizeof(uint32_t), &FRAME_REDUNDANCY_CODE_n, sizeof(uint16_t));
    memcpy(buf + len_sum, &stop_seq_n, sizeof(uint32_t));
    len_sum += sizeof(uint32_t);
    uint16_t current_selection_n = htons(selection);
    memcpy(buf + len_sum, &current_selection_n, sizeof(uint16_t));
    len_sum += sizeof(uint16_t);
    return len_sum;
}
/**
 * Look for redundancy code
 * @param sum
 * @param seq_num
 * @return index or -1 if does not exist
 */
int check_bulk_packet_code(struct packet_sum* sum, uint32_t seq_num, int selection) {
    for (int i = 0; i < BULK_BUFFER_PACKET_CODE; i++) {
        if ((sum[i].start_seq <= seq_num) && (sum[i].stop_seq >= seq_num) && (sum[i].my_selection_num == selection)) {
            if (sum[i].len_sum == 0) {
                return -1;
            } else {
                return i;
            }
        }
    }
    return -1;
}

/**
 *
 * @param sum
 * @param wb_written
 * @param wb
 * @param buf
 * @param seq_num - repaired seqNum
 * @return -1 if error or seqNum if success
 */
int check_n_repair_packet_code(struct packet_sum* sum, struct frame_llist* wb_written, struct frame_llist* wb, struct frame_seq buf[], uint32_t seq_num) {
    int selection = (seq_num - (SEQ_START_VAL + 1)) % SELECTION_NUM;
    //int gg = (BULK_BUFFER_PACKET_CODE-1);
    int sum_index = check_bulk_packet_code(sum, seq_num, selection);//get_packet_code(sum, &gg, seq_num);
    if (sum_index == -1) {
        return -1;
    }
    uint32_t seq_amount = (sum[sum_index].stop_seq - sum[sum_index].start_seq) / SELECTION_NUM + 1;
#ifdef CODE_LOG
    vtun_syslog(6, " packet code found for packet seq_num %"PRIu32" selection %i sum - start_seq %"PRIu32" stop_seq %"PRIu32"  found packet len %i", seq_num, selection, sum[sum_index].start_seq, sum[sum_index].stop_seq, sum[sum_index].len_sum);
#endif
    // if sum with one packet return sum immediately without xoring
    if (seq_amount == 1) {
        return sum_index;
    }

    uint32_t seq_counter = 0;
    int j = wb_written->rel_head;
    //check first
    for (;;) {
        if (buf[j].seq_num > sum[sum_index].stop_seq) {
            break;
        }
        if ((buf[j].seq_num >= sum[sum_index].start_seq) && (buf[j].seq_num <= sum[sum_index].stop_seq) && (((buf[j].seq_num - (SEQ_START_VAL + 1)) % SELECTION_NUM) == selection)) {
#ifdef CODE_LOG
            vtun_syslog(6, " seq %"PRIu32" found packet len %i", buf[j].seq_num, buf[j].len);
#endif
            seq_counter++;
        }
        if (j == wb->rel_tail) {
            break;
        }
        if (j == wb_written->rel_tail) {
            j = wb->rel_head;
        } else {
            j = buf[j].rel_next;
        }
    }
    //if we lost 1 packet in selection we can repair it
    if (seq_counter != (seq_amount -1)) {
        return -1;
    }
    j = wb_written->rel_head;
    //repair packet and ret as index of struct packet_sum* sum
    for (;;) {
        if (buf[j].seq_num > sum[sum_index].stop_seq) {
            break;
        }
        if ((buf[j].seq_num >= sum[sum_index].start_seq) && (buf[j].seq_num <= sum[sum_index].stop_seq) && (((buf[j].seq_num - (SEQ_START_VAL + 1)) % SELECTION_NUM) == selection)) {
#ifdef CODE_LOG
            vtun_syslog(6, "xoring seq %"PRIu32" packet len %i", buf[j].seq_num, buf[j].len);
#endif
            add_packet_code(buf[j].out, &sum[sum_index], buf[j].len);
            if (--seq_counter == 0)
                break;
        }
        if (j == wb_written->rel_tail) {
            j = wb->rel_head;
        } else {
            j = buf[j].rel_next;
        }
    }
    return sum_index;
}
/**
 *
 * @param sum
 * @param bulk_counter
 * @param seq_num
 * @return index or -1 if not found
 */
int get_packet_code(struct packet_sum* sum, int *bulk_counter, uint32_t seq_num) {
    int index = *bulk_counter;
    for (int counter = BULK_BUFFER_PACKET_CODE; counter >= 0; counter--) {
        if ((seq_num >= sum[index].start_seq) && (seq_num <= sum[index].stop_seq)) {
            return index;
        }
        if (--index < 0) {
            index = BULK_BUFFER_PACKET_CODE - 1;
        }
    }
    return -1;
}
