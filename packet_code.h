/*
 * packet_code.h
 *
 *  Created on: 02.04.2014
 *      Author: Vrayo Systems Ltd. team
 */

#ifndef PACKET_CODE_H_
#define PACKET_CODE_H_

#include "timer.h"

#define REDUNDANCY_CODE_SIZE (3*512)
#define BULK_BUFFER_PACKET_CODE 15
#define SELECTION_NUM 1
#define SELECTION_LENGTH 100
#define REDUNDANCY_CODE_LAG (SELECTION_LENGTH * SELECTION_NUM)
#define PACKET_CODE_BUFFER_SIZE 150
#define REDUNDANT_CODE_TIMER_TIME { 0, 65000 }


/*
 * REDUNDANCY_CODE_PACKET_CODE format
 *  32 bit        16 bit                 32 bit          16bit
 * start_seq  ||   flag   ||  data  ||  stop_seq  ||  selection_num
 *
 */

struct packet_sum {
    int my_selection_num;
    uint16_t len_sum;
    uint32_t start_seq;
    uint32_t stop_seq;
    uint32_t current_seq;
    char sum[1500];
    struct timer_obj timer;
    int lostAmount;
};

void sum_init(struct packet_sum* sum, uint32_t start_seq, uint32_t stop_seq, int my_selection_num, size_t packet_len);
void add_packet_code(char* packet, struct packet_sum* sum, uint16_t packet_len);
void del_packet_code(struct packet_sum* sum, int index);
int add_redundancy_packet_code(struct packet_sum* sum, int* bulk_counter, char* packet, size_t packet_len);
int pack_redundancy_packet_code(char *buf, struct packet_sum* sum, uint32_t seq_counter, int selection, int flag);
int check_bulk_packet_code(struct packet_sum* sum, uint32_t seq_num, int selection);
int repair_packet_code(struct packet_sum* sum, char* packet, uint32_t seq_num, size_t packet_len);
int check_n_repair_packet_code(struct packet_sum* sum, struct frame_llist* wb_written, struct frame_llist* wb, struct frame_seq buf[], uint32_t seq_num);
int get_packet_code(struct packet_sum* sum, int *bulk_counter, uint32_t seq_num);

#endif /* PACKET_CODE_H_ */
