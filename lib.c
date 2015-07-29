/*  
   vtrunkd - Virtual Tunnel Trunking over TCP/IP network. 

   Copyright (C) 2011  Andrew Gryaznov <realgrandrew@gmail.com>

   Vtrunkd has been derived from VTUN package by Maxim Krasnyansky. 
   vtun Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 */

/*
 * lib.c,v 1.1.1.2.2.9.2.1 2006/11/16 04:03:17 mtbishop Exp
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>
#include <math.h>
#include <netinet/tcp.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

volatile sig_atomic_t __io_canceled = 0;

#ifndef HAVE_SETPROC_TITLE
/* Functions to manipulate with program title */

extern char **environ;
char	*title_start;	/* start of the proc title space */
char	*title_end;     /* end of the proc title space */
int	title_size;

void init_title(int argc,char *argv[], char *envp[], char *name)
{
	int i;

	/*
	 *  Move the environment so settitle can use the space at
	 *  the top of memory.
	 */

	for (i = 0; envp[i]; i++);

	environ = (char **) malloc(sizeof (char *) * (i + 1));

	for(i = 0; envp[i]; i++)
	   environ[i] = strdup(envp[i]);
	environ[i] = NULL;

	/*
	 *  Save start and extent of argv for set_title.
	 */

	title_start = argv[0];

	/*
	 *  Determine how much space we can use for set_title.  
	 *  Use all contiguous argv and envp pointers starting at argv[0]
 	 */
	for(i=0; i<argc; i++)
	    if( !i || title_end == argv[i])
	       title_end = argv[i] + strlen(argv[i]) + 1;

	for(i=0; envp[i]; i++)
  	    if( title_end == envp[i] )
	       title_end = envp[i] + strlen(envp[i]) + 1;
	
	strcpy(title_start, name);
	title_start += strlen(name);
	title_size = title_end - title_start;
}

void set_title(const char *fmt, ...)
{
	char buf[255];
	va_list ap;

	memset(title_start,0,title_size);

	/* print the argument string */
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	if( strlen(buf) > title_size - 1)
	   buf[title_size - 1] = '\0';

	strcat(title_start, buf);
}
#endif  /* HAVE_SETPROC_TITLE */

struct my_ip {
    u_int8_t    ip_vhl;     /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;     /* type of service */
    u_int16_t   ip_len;     /* total length */
    u_int16_t   ip_id;      /* identification */
    u_int16_t   ip_off;     /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t    ip_ttl;     /* time to live */
    u_int8_t    ip_p;       /* protocol */
    u_int16_t   ip_sum;     /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


#define SYSLOG_DUPS 3
char *syslog_buf[SYSLOG_DUPS];
int syslog_buf_counter = 0;
int syslog_dup_counter = 0;
int syslog_sequential_counter = 0;
int syslog_dup_type = 0; //0 - dups no found 1 - single dup 2 - double dup
int init = 0;

int shm_log_state = 0; // 0 - regular log 1 - over shm
struct {
    sem_t *logSem;
    char *log;
    int *pointer;
    int size;
} shm_syslog = { NULL, NULL, NULL, 0 };

void set_vtun_syslog_shm(int state, sem_t *logSem, char *log, int *counter, int size) {
    shm_log_state = state;
    if (state) {
        shm_syslog.logSem = logSem;
        shm_syslog.log = log;
        shm_syslog.pointer = counter;
        shm_syslog.size = size;
    } else {
        shm_syslog.logSem = NULL;
        shm_syslog.log = NULL;
        shm_syslog.pointer = NULL;
        shm_syslog.size = 0;
    }
}

void print_vtun_shm_syslog(int priority, char *format, ...) {
    va_list ap;
    va_start(ap, format);
    if (shm_log_state) {
        char buf[JS_MAX];
        int str_len = vsnprintf(buf, sizeof(buf) - 1, format, ap);
        sem_wait(shm_syslog.logSem);
        if (shm_syslog.size - *(shm_syslog.pointer) < str_len + 1) { // str_len + zero terminate
            memcpy(shm_syslog.log + *(shm_syslog.pointer), buf, shm_syslog.size - *(shm_syslog.pointer));
            memcpy(shm_syslog.log, buf + (shm_syslog.size - *(shm_syslog.pointer)), (str_len + 1) - (shm_syslog.size - *(shm_syslog.pointer)));
            *(shm_syslog.pointer) = (str_len + 1) - (shm_syslog.size - *(shm_syslog.pointer));
        } else {
            memcpy(shm_syslog.log + *(shm_syslog.pointer), buf, str_len + 1);
            *shm_syslog.pointer += str_len + 1;
        }
        sem_post(shm_syslog.logSem);
    } else {
        vsyslog(priority, format, ap);
    }
    va_end(ap);
}

/* 
 * Print padded messages.
 * Used by 'auth' function to force all messages 
 * to be the same len.
 */
int print_p(int fd,const char *fmt, ...)
{
	char buf[VTUN_MESG_SIZE];
	va_list ap;

	memset(buf,0,sizeof(buf));

	/* print the argument string */
	va_start(ap, fmt);
	vsnprintf(buf,sizeof(buf)-1, fmt, ap);
	va_end(ap);
  
	return write_n(fd, buf, sizeof(buf));
}

/* Read N bytes with timeout */
int readn_t(int fd, void *buf, size_t count, time_t timeout) 
{
	fd_set fdset;
	struct timeval tv;

	tv.tv_usec=0; tv.tv_sec=timeout;

	FD_ZERO(&fdset);
	FD_SET(fd,&fdset);
	if( select(fd+1,&fdset,NULL,NULL,&tv) <= 0)
	   return -1;

	return read_n(fd, buf, count);
}

/* 
 * Substitutes opt in place off '%X'. 
 * Returns new string.
 */
char * subst_opt(char *str, struct vtun_sopt *opt)
{
    register int slen, olen, sp, np;
    register char *optr, *nstr, *tmp;
    char buf[10];

    if( !str ) return NULL;

    slen = strlen(str) + 1;
    if( !(nstr = malloc(slen)) )
       return str;

    sp = np = 0;
    while( str[sp] ){
       switch( str[sp] ){
          case '%':
             optr = NULL;
             /* Check supported opt */
             switch( str[sp+1] ){
                case '%':
                case 'd':
                   optr=opt->dev;
                   break;
                case 'A':
                   optr=opt->laddr;
                   break;
                case 'P':
		   sprintf(buf,"%d",opt->lport);
                   optr=buf;
                   break;
                case 'a':
                   optr=opt->raddr;
                   break;
                case 'p':
		   sprintf(buf,"%d",opt->rport);
                   optr=buf;
                   break;
                default:
                   sp++;
                   continue;
             }
             if( optr ){
                /* Opt found substitute */
                olen = strlen(optr);
                slen = slen - 2 + olen;
                if( !(tmp = realloc(nstr, slen)) ){
                   free(nstr);
                   return str;
                }
                nstr = tmp;
                memcpy(nstr + np, optr, olen);
                np += olen;
             }
             sp += 2;
             continue;

          case '\\':
             nstr[np++] = str[sp++];
             if( !nstr[sp] )
                continue;
             /* fall through */
          default:
             nstr[np++] = str[sp++];
             break;
       }
    }
    nstr[np] = '\0';
    return nstr;
}

/* 
 * Split arguments string.
 * ' ' - group arguments
 * Modifies original string. 
 */
void split_args(char *str, char **argv)
{       
     register int i = 0;
     int mode = 0;

     while( str && *str ){
        switch( *str ){
           case ' ':
              if( mode == 1 ){
                 *str = '\0';
                 mode = 0;
                 i++;
              }
              break;

           case '\'':
              if( !mode ){
                 argv[i] = str+1;
                 mode = 2;
              } else {
                 memmove(argv[i]+1, argv[i], str - argv[i]);
                 argv[i]++;

                 if( mode == 1 )
                    mode = 2;
                 else
                    mode = 1;
              }
              break;

           case '\\':
              if( mode ){
                 memmove(argv[i]+1, argv[i], str - argv[i]);
                 argv[i]++;
              }
	      if( !*(++str) ) continue;
	      /*Fall through */

           default:
              if( !mode ){
                 argv[i] = str;
                 mode = 1;
              }
              break;
        }
        str++;
     }
     if( mode == 1 || mode == 2)
	i++;

     argv[i]=NULL;
}
 
int run_cmd(void *d, void *opt)
{
     struct vtun_cmd *cmd = d;	
     char *argv[50], *args;
     int pid, st;

     switch( (pid=fork()) ){
	case 0:
	   break;
	case -1:
	   vtun_syslog(LOG_ERR,"Couldn't fork()");
	   return 0;
	default:
    	   if( cmd->flags & VTUN_CMD_WAIT ){
	      /* Wait for termination */
	      if( waitpid(pid,&st,0) > 0 && (WIFEXITED(st) && WEXITSTATUS(st)) )
		 vtun_syslog(LOG_INFO,"Command [%s %.20s] error %d", 
				cmd->prog ? cmd->prog : "sh",
				cmd->args ? cmd->args : "", 
				WEXITSTATUS(st) );
	   }
    	   if( cmd->flags & VTUN_CMD_DELAY ){
	      struct timespec tm = { VTUN_DELAY_SEC, 0 };
	      /* Small delay hack to sleep after pppd start.
	       * Until I have no good solution for solving 
	       * PPP + route problem  */
	      nanosleep(&tm, NULL);
	   }
	   return 0;	 
     }

     args = subst_opt(cmd->args, opt);
     if( !cmd->prog ){
	/* Run using shell */
	cmd->prog = "/bin/sh";
        argv[0] = "sh";	
	argv[1] = "-c";
	argv[2] = args;
	argv[3] = NULL;
     } else {
        argv[0] = cmd->prog;	
        split_args(args, argv + 1);
     }
     execv(cmd->prog, argv);

     vtun_syslog(LOG_ERR,"Couldn't exec program %s", cmd->prog);
     exit(1);
}

void free_sopt( struct vtun_sopt *opt )
{
     if( opt->dev ){
	free(opt->dev);
        opt->dev = NULL;
     }

     if( opt->laddr ){
	free(opt->laddr);
        opt->laddr = NULL;
     }

     if( opt->raddr ){
	free(opt->raddr);
        opt->raddr = NULL;
     }
}

static int llsqrt(long a)
{
        long long prev = ~((long long)1 << 63);
        long long x = a;

        if (x > 0) {
                while (x < prev) {
                        prev = x;
                        x = (x+(a/x))/2;
                }
        }

        return (int)x;
}

/*
 * finds the standard deviation
 * =sqrt(sum)x-mean(x)^2)/n)
 */
int std_dev(int nums[], int len)
{
	long sum = 0;
	long mean = 0;
	if(len==0) return 0;
	long llen = len;
	
	int i;
	
	for(i=0;i<len;i++) {
		sum+=nums[i];
	}
	mean = sum/llen;
	sum = 0;
	for(i = 0; i < len; i++)
		sum += abs(nums[i]-mean); // for stddev need to mult
	
	//return llsqrt(sum/len);
	return (sum/len);
}

void vtun_syslog_init() {
    for (int i = 0; i < SYSLOG_DUPS; i++) {
        syslog_buf[i] = malloc(JS_MAX);
        memset(syslog_buf[i], 0, JS_MAX);
    }
    init = 1;
}

void vtun_syslog_free() {
    for (int i = 0; i < SYSLOG_DUPS; i++) {
        free(syslog_buf[i]);
    }
    init = 0;
}

void vtun_direct_syslog(char *format, ...) {

}

void vtun_syslog(int priority, char *format, ...) {
#ifdef SYSLOG
    static volatile sig_atomic_t in_syslog = 0;
    char buf[JS_MAX];
    va_list ap;
    int print = 0;

    if (!in_syslog) {
        in_syslog = 1;

        va_start(ap, format);
        vsnprintf(buf, sizeof(buf) - 1, format, ap);
        va_end(ap);
        if (init) {
            if (syslog_dup_type == 0) {
//                syslog(priority, "type 1 test counter %d %s new - %s",syslog_buf_counter,syslog_buf[syslog_buf_counter], buf);

                if (!strcmp(syslog_buf[syslog_buf_counter], buf)) {
                    syslog_dup_counter++;
                    syslog_dup_type = 1;
                    syslog_sequential_counter = 0;
//                    syslog(priority, "type %d raise",syslog_dup_type);
                } else {
                    int counter = syslog_buf_counter - 1;
                    if (counter < 0) {
                        counter = SYSLOG_DUPS - 1;
                    }
//                    syslog(priority, "type 2 test buf %d counter %d %s new - %s",syslog_buf_counter,counter,syslog_buf[counter], buf);
                    if (!strcmp(syslog_buf[counter], buf)) {
                        syslog_dup_counter++;
                        syslog_dup_type = 2;
//                        syslog(priority, "type %d raise",syslog_dup_type);
                        syslog_sequential_counter = 0;
                    } else {
                        if (--counter < 0) {
                            counter = SYSLOG_DUPS - 1;
                        }
//                        syslog(priority, "type 3 test buf %d counter %d %s new - %s",syslog_buf_counter,counter,syslog_buf[counter], buf);

                        if (!strcmp(syslog_buf[counter], buf)) {
                            syslog_dup_counter++;
                            syslog_dup_type = 3;
                            syslog_sequential_counter = 1;
//                            syslog(priority, "type %d raise",syslog_dup_type);
                        } else {
                            if (++syslog_buf_counter == SYSLOG_DUPS) {
                                syslog_buf_counter = 0;
                            }
                            int string_len = strlen(buf);
                            if (string_len > JS_MAX) {
                                string_len = JS_MAX - 2;
                            }
//                            syslog(priority, "first save test buf %d %s",syslog_buf_counter, buf);
                            memcpy(syslog_buf[syslog_buf_counter], buf, string_len + 1);
                            print = 1;
                        }
                    }
                }
            } else if (syslog_dup_type == 1) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type-1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS - 1);
                }
//                syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);

                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len+1);
                    print = 1;
                }
            } else if (syslog_dup_type == 2) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type-1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS );
                }
 //               syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);
                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len+1);
                    print = 1;
                }
            }  else if (syslog_dup_type == 3) {
                if (syslog_sequential_counter < 0) {
                    syslog_sequential_counter = syslog_dup_type-1;
                }
                int counter = syslog_buf_counter - syslog_sequential_counter;
                if (counter < 0) {
                    counter = syslog_buf_counter - syslog_sequential_counter + (SYSLOG_DUPS );
                }
//                syslog(priority, "type %d buf_counter %d sequential_counter %d counter %d log:\"%s\"",syslog_dup_type,syslog_buf_counter, syslog_sequential_counter, counter, syslog_buf[counter]);
                if (!strcmp(syslog_buf[counter], buf)) {
                    syslog_sequential_counter--;
                    syslog_dup_counter++;
                } else {
                    if (++syslog_buf_counter == SYSLOG_DUPS) {
                        syslog_buf_counter = 0;
                    }
                    int string_len = strlen(buf);
                    if (string_len > JS_MAX) {
                        string_len = JS_MAX - 2;
                    }
                    memcpy(syslog_buf[syslog_buf_counter], buf, string_len+1);
                    print = 1;
                }
            }
        } else {
            print = 1;
        }

        if (print) {
            if (syslog_dup_counter) {
                print_vtun_shm_syslog(priority, "Last %d message(s) repeat %d times dups %d", syslog_dup_type, syslog_dup_counter/syslog_dup_type + 1, syslog_dup_counter);
                syslog_dup_counter = 0;
                syslog_dup_type = 0;
                syslog_sequential_counter = 0;
                for (int i = 0; i < SYSLOG_DUPS; i++) {
                    if (i == syslog_buf_counter)
                        continue;
                    memset(syslog_buf[i], 0, JS_MAX);
                }

            }
            print_vtun_shm_syslog(priority, "%s", buf);
        }
      in_syslog = 0;
   }
#else
    return;
#endif
}

/* Methods for periodic JSON logs */

int start_json(char *buf, int *pos) {
    int bs=0;
    memset(buf, 0, JS_MAX);
    *pos = 0;

    bs = sprintf(buf, "{");
    *pos = *pos + bs;
    return 0;
}

int add_json(char *buf, int *pos, const char *name, const char *format, ...) {
    va_list args;
    int bs = 0;
    if (*pos > (JS_MAX-2)) return -1;
    bs = sprintf(buf + *pos, "\"%s\":", name);
    *pos = *pos + bs;
    
    va_start(args, format);
    bs = vsnprintf(buf+*pos, JS_MAX-1, format, args);
    va_end(args);
    
    *pos = *pos + bs;

    bs = sprintf(buf + *pos, ",");
    *pos = *pos + bs;
    return bs;
}

int print_json(char *buf, int *pos) {
    buf[*pos-1] = 0;
    vtun_syslog(LOG_INFO, "%s}", buf);
    return 0;
}


/* Methods for fast changing variable logging */
int start_json_arr(char *buf, int *pos, const char *name) {
    int bs=0;
    memset(buf, 0, JS_MAX);
    //struct timeval dt;
    //gettimeofday(&dt, NULL);
    *pos = 0;

    //bs = sprintf(buf, "%ld.%06ld: {", dt.tv_sec, dt.tv_usec);
    bs = sprintf(buf, "{\"%s\": [", name); // no need for TS in slow-ticking jsons

    *pos = *pos + bs;
    return 0;
}

int add_json_arr(char *buf, int *pos, const char *format, ...) {
    va_list args;
    int bs = 0;
    if (*pos > (JS_MAX-20)) return -1; // 20 chars max per record

    va_start(args, format);
    bs = vsnprintf(buf+*pos, JS_MAX-*pos-1, format, args);
    va_end(args);
    
    *pos = *pos + bs;

    bs = sprintf(buf + *pos, ",");
    *pos = *pos + bs;
    return bs;
}

int print_json_arr(char *buf, int *pos) {
    buf[*pos-1] = 0;
    vtun_syslog(LOG_INFO, "%s]}", buf);
    return 0;
}



#ifdef TIMEWARP
int print_tw(char *buf, int *pos, const char *format, ...) {
    va_list args;
    int slen;
    struct timeval dt;
    gettimeofday(&dt, NULL);
    
    sprintf(buf + *pos, "\n%ld.%06ld:    ", dt.tv_sec, dt.tv_usec);
    *pos = *pos + 20;
    
    va_start(args, format);
    int out = vsprintf(buf+*pos, format, args);
    va_end(args);
    
    slen = strlen(buf+*pos);
    *pos = *pos + slen;
    if(*pos > TW_MAX - 10000) { // WARNING: 10000 max per line!
        sprintf(buf + *pos, "---- Overflow!\n");
        *pos = 0;
    }
    return out;
}

int flush_tw(char *buf, int *tw_cur) {
    // flush, memset
    int fd = open("/tmp/TIMEWARP.log", O_WRONLY | O_APPEND);
    int slen = strlen(buf);
    //vtun_syslog(LOG_INFO, "FLUSH! %d", slen);
    int len = write(fd, buf, slen);
    close(fd);
    memset(buf, 0, TW_MAX);
    *tw_cur = 0;
    return len;
}

int start_tw(char *buf, int *c) {
    memset(buf, 0, TW_MAX);
    *c = 0;
    return 0;
}
#endif

uint32_t getTcpSeq(char* buf) {
    struct my_ip *ip = (struct my_ip*) (buf);
    if ((ip->ip_p == 6)) { //tcp ack self test
        uint32_t seqNum;
        memcpy(&seqNum, buf + sizeof(struct my_ip) + 4, 4);
        seqNum = ntohl(seqNum);
        return seqNum;
    } else {
        return 0; //no tcp packet
    }
}

int isACK(char* buf, int len) {
    struct my_ip *ip = (struct my_ip*) (buf);
    if ((ip->ip_p == 6) && (len < 160)) { //tcp ack self test
        uint8_t tcpOffset;
        memcpy(&tcpOffset, buf + sizeof(struct my_ip) + 12, 1);
        tcpOffset = (0xF0 & tcpOffset) >> 2;
        int headerSize = sizeof(struct my_ip) + (int) tcpOffset;
        if (headerSize == len) { //if header size == full packet size
            return 1; //this is ACK
        }
    }
    return 0;
}

