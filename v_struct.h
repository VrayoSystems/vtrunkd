/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016 Vrayo Systems Ltd. team 
   This file is dual-licensed to be compatible with 
   Vrayo Systems vtrunkd_helper, part of Vrayo Internet Combiner package

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */
 
#define SHM_SYSLOG 100000

struct frame_hash {
    unsigned int seq;
    int n;
};

struct timed_loss {
    struct timeval timestamp;
    uint16_t name;
    int pbl;
    int psl;
    uint32_t sqn;
    int16_t who_lost;
};


struct _write_buf {
    struct frame_llist frames;
    //struct frame_llist free_frames; /* init all elements here */
    struct frame_llist now; // maybe unused
    unsigned long last_written_seq; // last pack number has written into device
    unsigned long wr_lws; // last pack number has written into device
    unsigned long last_received_seq[MAX_TCP_PHYSICAL_CHANNELS]; // max of 30 physical channels
    unsigned long last_received_seq_shadow[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder
    unsigned long possible_seq_lost[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder
    unsigned long packet_lost_state[MAX_TCP_PHYSICAL_CHANNELS]; // used for max_reorder

    struct timeval last_write_time; // into device
    int buf_len;
    unsigned long remote_lws; // last written packet into device on remote side
    unsigned long last_lws_notified;
    uint16_t complete_seq_quantity;
    int top_packet_physical_channel_num;
};

/**
 * local structure
 * per channel
 */
struct time_lag_info {
	uint64_t time_lag_sum;
	uint16_t time_lag_cnt;
	uint32_t packet_lag_sum; // lag in packets
	uint16_t packet_lag_cnt;
	uint8_t once_flag:1;
};

/**
 * local structure
 * for local pid
 */
struct time_lag {
	uint32_t time_lag_remote; // calculater here
	uint32_t time_lag; // get from another side
	int pid_remote; // pid from another side
	int pid; // our pid
};

struct _events {
    int update;
    int tick;
    int loss;
};

struct speed_chan_data_struct {
    uint32_t up_current_speed; // current physical channel's speed(kbyte/s) = up_data_len_amt / time
    uint32_t up_recv_speed;
    uint32_t up_data_len_amt; // in byte
    uint32_t down_current_speed; // current physical channel's speed(kbyte/s) = down_data_len_amt / time
    uint32_t down_data_len_amt; // in byte

    uint32_t down_packets; // per last_tick. need for speed calculation
    uint32_t down_packet_speed;
    uint32_t send_q_loss;

};

/**
 * global structure
 */
struct conn_stats {
    char name[SESSION_NAME_SIZE];
    int lssqn; // TODO: remove this after tests
    int hsnum; /* session name hash - identical between prodesses */
    int pid; /* current pid */
    int pid_remote; // pid from another side
    long int weight; /* bandwith-delay product */
    long int last_tick; // watch dog timer
    // time_lag = old last written time - new written time (in millisecond)
    // and get from another side
    uint32_t time_lag_remote;// calculated here
    uint32_t time_lag; // get from another side
    struct speed_chan_data_struct speed_chan_data[MAX_TCP_LOGICAL_CHANNELS];
    uint32_t max_upload_speed;
    uint32_t max_send_q;
    uint32_t max_send_q_avg;
    int32_t send_q_limit; // remove this; replaced by rsr
    uint16_t miss_packets_max; // get from another side
    int32_t ACK_speed;
    int32_t max_ACS2;
    int32_t max_PCS2;
    int32_t max_sqspd;
    int32_t W_cubic;
    int max_send_q_available;
    int32_t W_cubic_u;
    int32_t rsr; // sync on stats_sem
    int rtt_phys_avg; // accurate on idling
    int rtt2; // RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int srtt2_10; // COPIED from info RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int srtt2_100; // COPIED from info RTT based on per-packet ACK delivery watch; very accurate on high speeds; does not work while idling
    int sqe_mean;
    int sqe_var;
    int sqe_mean_lossq;
    int my_max_send_q_chan_num;
    int ag_flag_local;
    int hold;
    int channel_dead;
    int exact_rtt;
    int rttvar; // pure ms
    int head_in;
    int head_use;
    struct timeval bdp1;
    struct timeval real_loss_time;
    int packet_speed_ag;
    int packet_speed_rmit;
    int local_seq_num_beforeloss;
    int packet_recv_counter_afterloss;
    int l_pbl;
    int l_pbl_recv;
    int brl_ag_enabled;
    int l_pbl_tmp; 
    int l_pbl_unrec_avg;
    int l_pbl_tmp_unrec; 
    int pbl_lossed;
    int pbl_lossed_cnt;
    int packet_upload_cnt;
    int packet_upload_spd;
    struct timeval packet_upload_tv;
    struct timeval agon_time;
    struct timeval agoff_immunity_tv;
    int recv_mode;
    struct timeval plp_immune;
    int l_pbl_recv_saved;
    int l_pbl_tmp_saved;
    int pbl_lossed_saved;
    int pbl_lossed_cnt_saved;
    int remote_head_channel;
    uint32_t la_sqn; // last received global seq_num ACK
    int loss_send_q;
    int32_t ACK_speed_avg;  /**< Moving average of @see ACK_speed */
    int remote_sqe_mean_pkt; /** remote sqe_mean sent by FCI, in packets */
    struct _events events;
};
/**
 * Structure for garbage statistic and information
 * about logical channels. Include service channel[0]
 */
struct logical_status {
    /** Information about tcp connection */
    uint16_t rport;  /**< remote(dst) tcp port */
    uint16_t lport;  /**< local(src) tcp port */
    int descriptor; /** file descriptor associated with this connection*/

    /** AVG measuring speed */
    uint32_t upload;    /**< upload speed */
    uint32_t up_len;    /**< how much bytes are uploaded */
    uint32_t up_packets; /**< how much packets are uploaded */
    uint32_t download;  /**< download speed */
    uint32_t down_len;    /**< how much bytes are downloaded */
    uint32_t packet_download;
    uint32_t down_packets;
    uint32_t rtt;       /**< rtt is measured by vtrunkd */
    uint32_t tcp_rtt;   /**< rtt is said by @see get_format_tcp_info() */
    uint32_t magic_rtt;   /**< rtt based on @see ACK_speed_avg */

    /** Net buffer control information */
    uint32_t send_q;    /**< current send_q value */
    struct timeval send_q_time;
    uint32_t send_q_old;    /**< previous send_q value */
    int32_t send_q_limit;  /**< current send_q_limit value */
    int32_t ACK_speed[SPEED_AVG_ARR];      /**< Speed based on how fast ACK packets come back. Last 10 measurements @see avg_count */
    int avg_count;         /**< Counter for @see ACK_speed_avg calculate*/
    uint32_t local_seq_num;
    uint32_t local_seq_num_recv;
    uint32_t local_seq_num_beforeloss; /** used for max_reorder support */
    struct timeval loss_time; /** time from last detected packet loss on this chan_num (incoming stream) */
    struct timeval last_recv_time;
    struct timeval last_info_send_time;
    int16_t packet_loss_counter;
    uint16_t packet_recv_counter;
    uint16_t packet_recv_counter_afterloss;
    struct timeval packet_recv_time;
    int16_t packet_loss;
    uint16_t packet_recv;
    uint32_t packet_seq_num_acked;
    uint32_t packet_recv_period;
    uint32_t packet_recv_upload;
    uint32_t packet_recv_upload_avg;
    struct timeval get_tcp_info_time_old; /**< Previous value of @see get_tcp_info_time.*/
    int32_t ACS2;
    uint32_t old_packet_seq_num_acked;
    uint32_t bytes_put;
};

/**
 * Structure for storing all information about
 * physical channel
 */
struct phisical_status { // A.K.A. "info"
    /** Common information */
    int process_num;    /**< Current physical channel's number */
    int pid; /**< Our pid is got on this side by getpid()  */
    int remote_pid; /**< Pid is got from another side by net */
    int tun_device; /**< /dev/tun descriptor */
    int srv; /**< 1 - if I'm server and 0 - if I'm client */
    int head_channel;
    int min_rtt_chan;
    struct {
        unsigned int seq_num;
        unsigned int local_seq_num;
    } lossed_loop_data[LOSSED_BACKLOG_SIZE]; // array of seq_nums for lossed detect
    uint32_t lossed_local_seq_num_lost_start; /** start seq_num of lost packet */
    int lossed_complete_received;
    int lossed_last_received;
    /** Collect statistic*/
    int mode;   /**< local aggregation flag, can be AG_MODE and R_MODE */
    struct timeval current_time;    /**< Is last got time.*/
    struct timeval current_time_old; /**< Previous value of @see current_time. Need for for the Tick module */
    uint32_t max_send_q_avg;
    uint32_t max_send_q_avg_arr[SPEED_AVG_ARR];
    uint32_t max_send_q_min;
    uint32_t max_send_q_max;
    uint32_t max_send_q_calc; // = cwnd * mss
    int max_send_q_counter;
    unsigned int speed_efficient;
    unsigned int speed_resend;
    unsigned int speed_r_mode;
    unsigned int byte_efficient;
    unsigned int byte_resend;
    unsigned int byte_r_mode;
    int rtt;
    uint32_t packet_recv_upload_avg;
    struct timeval bdp1;

    /** Calculated values*/
    int32_t send_q_limit_cubic;
    int32_t send_q_limit;
    int32_t send_q_limit_cubic_max;
    int32_t rsr;
    struct timeval cycle_last;
    double C;
    double Cu;
    double B;
    double Bu;
    int W_u_max;
    int cubic_t_max_u;
    struct timeval u_loss_tv;
    int max_send_q;
    int max_send_q_u;
    struct timeval tv_sqe_mean_added;
    /** Logical channels information and statistic*/
    int channel_amount;   /**< Number elements in @see channel array AKA Number of logical channels already established(created)*/
    struct logical_status *channel; /**< Array for all logical channels */
    uint32_t session_hash_this; /**< Session hash for this machine */
    uint32_t session_hash_remote; /**< Session hash for remote machine */
    /** Events */
    int just_started_recv; /**< 0 - when @see FRAME_JUST_STARTED hasn't received yet and 1 - already */
    int check_shm; /**< 1 - need to check some shm values */
    uint32_t least_rx_seq[MAX_TCP_LOGICAL_CHANNELS]; // local store of least received seq_num across all phy

    uint32_t rtt2_lsn[MAX_TCP_LOGICAL_CHANNELS];
    int32_t max_sqspd;
    int32_t rtt2_send_q[MAX_TCP_LOGICAL_CHANNELS];
    struct timeval rtt2_tv[MAX_TCP_LOGICAL_CHANNELS]; 
    int rtt2; // max..?
    int srtt2_10; // max..?
    int srtt2_100; // max..?
    int srtt2var; 
    int dropping;
    struct timeval max_reorder_latency;
    struct timeval max_latency_drop;
    int eff_len;
    int send_q_limit_threshold;
    int exact_rtt;
    int flush_sequential; // PSL
    int ploss_event_flag; /** flag to detect PLOSS at tflush */
    int mean_latency_us;
    int max_latency_us;
    int frtt_us_applied;
    int PCS2_recv; // through FRAME_CHANNEL_INFO
    
    int i_plp; /** inverse packet loss probability (sent) */
    int p_lost;
    int last_loss_lsn;
    int i_rplp; /** inverse packet loss probability (received) */
    int r_lost;
    int last_rlost_lsn;

    int l_pbl;
    int pbl_cnt;
    struct {
        int pbl;
        struct timeval ts;
    } plp_buf[PLP_BUF_SIZE];
    
    int fast_pcs_old;
    int pcs_sent_old;
    struct timeval fast_pcs_ts;
    struct timeval last_sent_FLI;
    int last_sent_FLI_idx;
    int last_sent_FLLI_idx;
    int32_t encap_streams_bitcnt;
    int encap_streams;
    int W_cubic_copy;
    int Wu_cubic_copy;
    struct timeval hold_time;
    struct timeval head_change_tv;
    int head_change_safe; // enough time passed since head change
    int frtt_remote_predicted;
    int select_immediate; /** immediate select times counter */
    int Wmax_saved;
    struct timeval Wmax_tv;
    int gsend_q_grow;
    int whm_cubic;
    int whm_rsr;
    int whm_send_q;
    int previous_idle;
    int head_send_q_shift;
    int head_send_q_shift_old;
    int FCI_send_counter;
    struct timeval recv_loss_immune;
    struct timeval idle_enter;
    int loss_event_count; // EXT
    int psl_count; // EXT
    int psl_per_second; // EXT
    int loss_events_per_second; // EXT
    int xlm;
};

/** @struct conn_info
 *  @brief Common shm struct.
 *
 *  Description
 */
struct conn_info {
#ifdef SHM_DEBUG
    volatile char void11[4096];
    char void1[4096];
#endif
    int usecount;
    int rdy; /* ready flag */
    // char sockname[100], /* remember to init to "/tmp/" and strcpy from byte *(sockname+5) or &sockname[5]*/ // not needed due to devname
    char devname[VTUN_DEV_LEN];
    sem_t hard_sem;
    //sem_t frtt; // for frtt calculations and tokens
    sem_t tun_device_sem;
    int packet_debug_enabled;
    int is_single_channel;
    struct frame_seq frames_buf[FRAME_BUF_SIZE];			// memory for write_buf
    struct frame_seq resend_frames_buf[RESEND_BUF_SIZE];	// memory for resend_buf
    int resend_buf_idx;
    struct frame_seq fast_resend_buf[FAST_RESEND_BUF_SIZE];
    int fast_resend_buf_idx; // how many packets in fast_resend_buf
    struct _write_buf write_buf[MAX_TCP_LOGICAL_CHANNELS]; // input todo need to synchronize
    struct frame_hash write_buf_hashtable[WBUF_HASH_SIZE];
    int write_sequential; // PBL sync by write_buf_sem
    int prev_flushed; // PBL/PSL flagsync by write_buf_sem
    struct frame_llist wb_just_write_frames[MAX_TCP_LOGICAL_CHANNELS];
    struct frame_llist wb_free_frames; /* init all elements here */ // input (to device)
    sem_t write_buf_sem; //for write buf, seq_counter
    struct _write_buf resend_buf[MAX_TCP_LOGICAL_CHANNELS]; // output
    struct frame_llist rb_free_frames; /* init all elements here */ // output (to net)
    sem_t resend_buf_sem; //for resend buf,  (ever between write_buf_sem if need double blocking)
    sem_t common_sem; // for seq_counter
    unsigned long seq_counter[MAX_TCP_LOGICAL_CHANNELS];	// packet sequense counter
    uint32_t flushed_packet[FLUSHED_PACKET_ARRAY_SIZE]; //sync by write_buf_sem
    uint32_t seq_num_unrecoverable_loss; /** seq_num of unrecoverable loss - just flush up to this one since we're going to retransmit anyways */
    short lock_pid;	// who has locked shm
    char normal_senders;
    int rxmt_mode_pid; // unused?
    sem_t stats_sem;
    sem_t event_sem;
    long int event_mask;
    uint16_t miss_packets_max; // get from another side sync on stats_sem
    int buf_len_recv,buf_len;
    struct conn_stats stats[MAX_TCP_PHYSICAL_CHANNELS]; // need to synchronize because can acces few proccees
    uint32_t miss_packets_max_recv_counter; // sync on stats_sem
    uint32_t miss_packets_max_send_counter; // sync on stats_sem
#ifdef SHM_DEBUG
    char void12[4096];
    char void2[4096];
#endif
    long int lock_time;
    long int alive;
    sem_t AG_flags_sem; // semaphore for AG_ready_flags and channels_mask
    uint32_t AG_ready_flag; // contain global flags for aggregation possible 0 - enable 1 - disable sync by AG_flags_sem
    uint32_t channels_mask; // 1 - channel is working 0 - channel is dead sync by AG_flags_sem
    uint32_t hold_mask; // 0 - channel is on hold, 1 = send allowed
    uint32_t need_to_exit; // sync by AG_flags_sem
    uint32_t session_hash_this; /**< Session hash for this machine sync by @see AG_flags_sem*/
    uint32_t session_hash_remote; /**< Session hash for remote machine sync by @see AG_flags_sem*/
    unsigned char check[CHECK_SZ]; // check-buf. TODO: fill with pattern "170" aka 10101010
    int head_process;
    int tflush_counter, tflush_counter_recv;
    struct timeval chanel_info_time;
    int flood_flag[MAX_TCP_PHYSICAL_CHANNELS];
    struct timeval last_flood_sent;
    struct timeval last_switch_time;
    int head_all;
    int max_chan;
    int dropping;
    int head_lossing;
    struct timeval forced_rtt_start_grow;
    int forced_rtt;
    int forced_rtt_recv; //in ms
    int idle;
    struct timeval drop_time; // time that we DROPPED by fact!
    struct timed_loss loss[LOSS_ARRAY]; // sync by write_buf_sem
    struct timed_loss loss_recv[LOSS_ARRAY]; // sync by recv_loss_sem
    struct timed_loss l_loss[LOSS_ARRAY]; // sync by write_buf_sem
    struct timed_loss l_loss_recv[LOSS_ARRAY]; // sync by recv_loss_sem
    sem_t recv_loss_sem;
    int loss_idx; // sync by write_buf_sem
    int l_loss_idx; // sync by write_buf_sem
    struct {
#define EFF_LEN_BUFF 15
        int warming_up;
        int counter;
        int len_num[EFF_LEN_BUFF];
        int sum;
    } eff_len; /**< Session hash for remote machine sync by @see common_sem*/
    int t_model_rtt100; // RTT multiplied by 100, in ms, for tcp model, calculated as toata avg rtt
    unsigned char streams[32];
    int single_stream;
    struct packet_sum packet_code[SELECTION_NUM][MAX_TCP_LOGICAL_CHANNELS];// sync by common_sem
    struct packet_sum packet_code_recived[MAX_TCP_LOGICAL_CHANNELS][BULK_BUFFER_PACKET_CODE];// sync by common_sem
    int packet_code_bulk_counter;
    struct packet_sum test_packet_code[MAX_TCP_LOGICAL_CHANNELS];
    struct timeval last_written_recv_ts;
    struct timeval last_head;
    int frtt_ms;
    int drtt;
    int frtt_local_applied;
    struct timeval frtt_smooth_tick;
    uint32_t ag_mask; // unsynced
    uint32_t ag_mask_recv; // unsynced
    int max_rtt_lag;
    int APCS_cnt; // counter for coming packets with AG mode
    int APCS; // speed for packets per seconf in AG mode coming to WB
    struct timeval APCS_tick_tv;
    struct timeval tpps_tick_tv;
    int tokens;
    struct timeval tokens_lastadd_tv;
    int max_chan_new;
    struct timeval head_detected_ts;
    int max_allowed_rtt; // MAR calculated against current speed and send_q
    int tpps; // transfer packets per second
    int forced_rtt_remote;
    int rttvar_worst;
    uint32_t latest_la_sqn; /** latest SQN used to identify HSQS event update age */
    int remote_head_pnum; // remote head local pnum (for TPC)
    int write_speed_avg;
    int write_speed;
    int write_speed_b;
    int min_rtt_pnum_checkonly;
    int max_rtt_pnum_checkonly;
    int max_stuck_buf_len;
    int max_stuck_rtt;
    int msbl_recv;
    int total_max_rtt;
    int total_max_rtt_var;
    int total_min_rtt;
    int total_min_rtt_var;
    int full_cwnd;
    struct timeval msbl_tick;
    struct timeval msrt_tick;
    int tokens_in_out;
    int ssd_gsq_old;
    int tpps_old; /** holding old global seq_coutner[1] value */
    int ssd_pkts_sent;
    int slow_start;
    int slow_start_recv;
    int slow_start_prev;
    int slow_start_allowed;
    int slow_start_force;
    int avg_len_in;
    int avg_len_out;
    struct timeval slow_start_tv;
    // struct streams_seq w_streams[W_STREAMS_AMT];
    int w_stream_pkts[W_STREAMS_AMT]; /** packets for this stream currently in wb */
    struct timeval cwr_tv; // for CWND Reserve 1s
    struct timeval max_network_stall; /** drop packets if this value is exceeded */
    int head_send_q_shift_recv; 
    struct timeval head_change_htime_tv;
    int head_change_htime;
    int tokenbuf;
    int last_net_read_ds; /** last network read in deciseconds */
#ifdef SHM_DEBUG
    char void13[4096];
    char void3[4096];
#endif
    struct {
        sem_t logSem;
        char log[SHM_SYSLOG];
        int counter;
    } syslog;
};
