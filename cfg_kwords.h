/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011-2016  Vrayo Systems Ltd. team

   Vtrunkd has been derived from VTUN package by Maxim Krasnyansky. 
   vtun Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */

/*
 * cfg_kwords.h,v 1.1.1.1.2.3.2.8 2006/11/16 04:02:45 mtbishop Exp
 */ 

extern int lineno;

struct kword {
   char *str;
   int  type;
}; 

struct kword cfg_keyword[] = {
   { "options",  K_OPTIONS }, 
   { "default",  K_DEFAULT },
   { "up",	 K_UP },
   { "down",	 K_DOWN },
   { "port",     K_PORT }, 
   { "srcaddr",  K_SRCADDR }, 
   { "addr",  	 K_ADDR }, 
   { "iface",  	 K_IFACE }, 
   { "bindaddr", K_BINDADDR },
   { "persist",	 K_PERSIST }, 
   { "multi",	 K_MULTI }, 
   { "iface",    K_IFACE }, 
   { "timeout",	 K_TIMEOUT }, 
   { "passwd",   K_PASSWD }, 
   { "password", K_PASSWD }, 
   { "program",  K_PROG }, 
   { "speed",    K_SPEED }, 
   { "compress", K_COMPRESS }, 
   { "encrypt",  K_ENCRYPT }, 
   { "type",	 K_TYPE }, 
   { "proto",	 K_PROT }, 
   { "device",	 K_DEVICE }, 
   { "ppp",	 K_PPP },
   { "ifconfig", K_IFCFG },
   { "ifcfg", 	 K_IFCFG },
   { "firewall", K_FWALL }, 
   { "route", 	 K_ROUTE }, 
   { "ip", 	 K_IPROUTE }, 
   { "keepalive",K_KALIVE }, 
   { "stat",	 K_STAT }, 
   { "syslog",   K_SYSLOG },


   { "tick_secs",   K_TICK_SECS },
   { "rxmit_cnt_drop_period",   K_RXMIT_CNT_DROP_PERIOD },
   { "max_weight_norm",   K_MAX_WEIGHT_NORM },
   { "weight_scale",   K_WEIGHT_SCALE },
   { "weight_smooth_div",   K_WEIGHT_SMOOTH_DIV },
   { "weight_start_stickiness",   K_WEIGHT_START_STICKINESS },
   { "weight_saw_step_up_div",   K_WEIGHT_SAW_STEP_UP_DIV },
   { "weight_saw_step_up_min_step",   K_WEIGHT_SAW_STEP_UP_MIN_STEP },
   { "weight_saw_step_dn_div",   K_WEIGHT_SAW_STEP_DN_DIV },
   { "weight_msec_delay",   K_WEIGHT_MSEC_DELAY },
   { "weight_usec_delay",   K_WEIGHT_MSEC_DELAY },
   { "max_window",   K_MAX_WINDOW },
   { "pen_usec_immune",   K_PEN_USEC_IMMUNE},
   { "max_latency",   K_MAX_LATENCY },
   { "max_latency_drop",   K_MAX_LATENCY_DROP },
   { "max_allowed_buf_len",   K_MAX_ALLOWED_BUF_LEN },
   { "max_reorder",   K_MAX_REORDER },
   { "max_idle_timeout",   K_MAX_IDLE_TIMEOUT },
   { "frame_count_send_lws",   K_FRAME_COUNT_SEND_LWS },
   { "ping_interval",   K_PING_INTERVAL },
   { "tun_txqueue_len",   K_TUN_TXQUEUE_LEN },
   { "max_tunnels_num",   K_MAX_TUNNELS_NUM },
   { "tcp_conn_amount",   K_TCP_CONN_AMOUNT },
   { "start_weight", K_START_WEIGHT },
   { "rt_mark", K_RT_MARK },


   { NULL , 0 }
};

struct kword cfg_param[] = {
   { "yes",      1 }, 
   { "no",       0 },
   { "allow",	 1 },
   { "deny",	 0 },
   { "enable",	 1 },
   { "disable",	 0 },
   { "tty",      VTUN_TTY }, 
   { "pipe",	 VTUN_PIPE }, 
   { "ether",	 VTUN_ETHER }, 
   { "tun",	 VTUN_TUN }, 
   { "tcp",      VTUN_TCP }, 
   { "udp",      VTUN_UDP }, 
   { "lzo",      VTUN_LZO }, 
   { "zlib",     VTUN_ZLIB }, 
   { "wait",	 1 },
   { "killold",	 VTUN_MULTI_KILL },
   { "inetd",	 VTUN_INETD },
   { "stand",	 VTUN_STAND_ALONE },
   { "keep",     VTUN_PERSIST_KEEPIF },
   { "blowfish128ecb", VTUN_ENC_BF128ECB },
   { "blowfish128cbc", VTUN_ENC_BF128CBC },
   { "blowfish128cfb", VTUN_ENC_BF128CFB },
   { "blowfish128ofb", VTUN_ENC_BF128OFB },
   { "blowfish256ecb", VTUN_ENC_BF256ECB },
   { "blowfish256cbc", VTUN_ENC_BF256CBC },
   { "blowfish256cfb", VTUN_ENC_BF256CFB },
   { "blowfish256ofb", VTUN_ENC_BF256OFB },
   { "aes128ecb",      VTUN_ENC_AES128ECB },
   { "aes128cbc",      VTUN_ENC_AES128CBC },
   { "aes128cfb",      VTUN_ENC_AES128CFB },
   { "aes128ofb",      VTUN_ENC_AES128OFB },
   { "aes256ecb",      VTUN_ENC_AES256ECB },
   { "aes256cbc",      VTUN_ENC_AES256CBC },
   { "aes256cfb",      VTUN_ENC_AES256CFB },
   { "aes256ofb",      VTUN_ENC_AES256OFB },
   { NULL , 0 }
};
