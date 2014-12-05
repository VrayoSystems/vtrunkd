/*
 Detected loss +-1 by REORDER lsn: 6495; last lsn: 6489, sqn: 1
2884, lsq before loss 6489
 lossed buffer: complete: 15 lsn 6495, last: 15 lsn 6495
 > 0 lsn 6480, sn 12869
 > 1 lsn 6481, sn 12870
 > 2 lsn 6482, sn 12871
 > 3 lsn 6483, sn 12872
 > 4 lsn 6484, sn 12873
 > 5 lsn 6485, sn 12874
 > 6 lsn 6486, sn 12875
 > 7 lsn 6487, sn 12876
 > 8 lsn 6488, sn 12877
 > 9 lsn 6489, sn 12878
 > 10 lsn 6470, sn 12859
 > 11 lsn 6471, sn 12860
 > 12 lsn 6472, sn 12861
 > 13 lsn 6473, sn 12862
 > 14 lsn 6474, sn 12863
 > 15 lsn 6495, sn 12884                                       
 > 16 lsn 6476, sn 12865                                       
 > 17 lsn 6477, sn 12866                                       
 > 18 lsn 6478, sn 12867                                       
 > 19 lsn 6479, sn 12868                                       
 sedning loss -1 lrs 12884, llrs 6495         

*/

#include <stdio.h>

struct {
    int lossed_complete_received;
    int lossed_last_received;
    struct {
        int local_seq_num;
        int seq_num;
    } lossed_loop_data[10];
} info;

int lossed_count() {
    int cnt = 0;
    int idx_prev = info.lossed_complete_received;
    int idx = idx_prev;
    unsigned int old_lsn = info.lossed_loop_data[idx].local_seq_num;
    int pkt_shift = 1;
    while(idx != info.lossed_last_received) {
        idx++;
        if(idx >= LOSSED_BACKLOG_SIZE) idx = 0;
        if((info.lossed_loop_data[info.lossed_complete_received].local_seq_num + pkt_shift) == info.lossed_loop_data[idx].local_seq_num) {
            // ok
        } else {
            cnt++;
        }
        idx_prev = idx;
        pkt_shift++;
    }
    return cnt - 1; // last one is for vendetta!
}


int is_loss() {
    if(info.lossed_last_received != info.lossed_complete_received) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    info.lossed_complete_received = 4;
    info.lossed_last_received = 8;
    info.lossed_loop_data = { 
        { 6480, 12869 },
        { 6481, 12870 },
        { 6482, 12871 },
        { 6483, 12872 },
        { 6484, 12873 },
        { 6470, 12859 },
        { 6471, 12860 },
        { 6472, 12861 },
        { 6485, 12869 },
        { 6465, 12869 }
    };
    printf("count %d", lossed_count());
    return 0;
}
