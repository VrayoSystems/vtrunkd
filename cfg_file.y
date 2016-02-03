%{
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
 * cfg_file.y,v 1.1.1.2.2.13.2.4 2006/11/16 04:02:42 mtbishop Exp
 */ 

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <syslog.h>

#include "compat.h"
#include "vtun.h"
#include "lib.h"
#include "log.h"

int lineno = 1;

struct vtun_host *parse_host;
extern struct vtun_host default_host;

llist  *parse_cmds;
struct vtun_cmd parse_cmd;

llist host_list;

int  cfg_error(const char *fmt, ...);
int  add_cmd(llist *cmds, char *prog, char *args, int flags);
void *cp_cmd(void *d, void *u);
int  free_cmd(void *d, void *u);

void copy_addr(struct vtun_host *to, struct vtun_host *from);
int  free_host(void *d, void *u);
void free_addr(struct vtun_host *h);
void free_host_list(void);

int  parse_syslog(char *facility);

int yyparse(void);
int yylex(void);	
int yyerror(char *s); 

#define YYERROR_VERBOSE 1

%}

%union {
   char *str;
   int  num;
   struct { int num1; int num2; } dnum;
}
%expect 20

%token K_OPTIONS K_DEFAULT K_PORT K_BINDADDR K_PERSIST K_TIMEOUT
%token K_PASSWD K_PROG K_PPP K_SPEED K_IFCFG K_FWALL K_ROUTE K_DEVICE 
%token K_MULTI K_SRCADDR K_IFACE K_ADDR
%token K_TYPE K_PROT K_COMPRESS K_ENCRYPT K_KALIVE K_STAT
%token K_UP K_DOWN K_SYSLOG K_IPROUTE
%token K_TICK_SECS K_RXMIT_CNT_DROP_PERIOD K_MAX_WEIGHT_NORM K_WEIGHT_SCALE K_WEIGHT_SMOOTH_DIV K_WEIGHT_START_STICKINESS K_WEIGHT_SAW_STEP_UP_DIV K_WEIGHT_SAW_STEP_UP_MIN_STEP K_WEIGHT_SAW_STEP_DN_DIV K_PEN_USEC_IMMUNE
K_WEIGHT_MSEC_DELAY K_MAX_WINDOW K_MAX_LATENCY K_MAX_LATENCY_DROP K_MAX_ALLOWED_BUF_LEN K_MAX_REORDER K_MAX_IDLE_TIMEOUT K_FRAME_COUNT_SEND_LWS K_PING_INTERVAL K_TUN_TXQUEUE_LEN K_MAX_TUNNELS_NUM K_TCP_CONN_AMOUNT K_START_WEIGHT K_RT_MARK
%token <str> K_HOST K_ERROR
%token <str> WORD PATH STRING
%token <num> NUM 
%token <dnum> DNUM

%%
config: 
  | config statement 
  ;

statement: '\n'
  | K_OPTIONS   '{' options '}' 

  | K_DEFAULT   { 
		  parse_host = &default_host; 
                }        
    '{' host_options '}' 

  | K_HOST      { 
		  if( !(parse_host = malloc(sizeof(struct vtun_host))) ){
		     yyerror("No memory for the host");
		     YYABORT;
		  }

		  /* Fill new host struct with default values.
		   * MUST dup strings to be able to reread config.
		   */
	  	  memcpy(parse_host, &default_host, sizeof(struct vtun_host));
		  parse_host->host = strdup($1);
		  parse_host->passwd = NULL;

		  /* Copy local address */
		  copy_addr(parse_host, &default_host);

		  llist_copy(&default_host.up,&parse_host->up,cp_cmd,NULL);
		  llist_copy(&default_host.down,&parse_host->down,cp_cmd,NULL);

		}    
    '{' host_options '}'
		{
		  /* Check if session definition is complete */ 
		  if (!parse_host->passwd) {
		  	cfg_error("Ignored incomplete session definition '%s'", parse_host->host);
			free_host(parse_host, NULL);			
			free(parse_host);
		  } else {
		  	/* Add host to the list */
		  	llist_add(&host_list, (void *)parse_host);
		  }
		}

  | K_ERROR	{
		  cfg_error("Invalid clause '%s'",$1);
		  YYABORT;
		}
  ;

options:
    option
  | options option
  ;

/* Don't override command line options */
option:  '\n'
  | K_PORT NUM 		{ 
			  if(vtun.bind_addr.port == -1)
			     vtun.bind_addr.port = $2;
			} 

  | K_BINDADDR '{' bindaddr_option '}'

  | K_IFACE STRING	{ 
			  if(vtun.svr_addr == -1)
			    vtun.svr_addr = strdup($2);
			} 

  | K_TYPE NUM 		{ 
			  if(vtun.svr_type == -1)
			     vtun.svr_type = $2;
			} 

  | K_TIMEOUT NUM 	{  
			  if(vtun.timeout == -1)
			     vtun.timeout = $2; 	
			}

  | K_PPP   PATH	{
			  free(vtun.ppp);
			  vtun.ppp = strdup($2);
			}

  | K_IFCFG PATH	{
			  free(vtun.ifcfg);
			  vtun.ifcfg = strdup($2);
			}

  | K_ROUTE PATH 	{   
			  free(vtun.route);  
			  vtun.route = strdup($2); 	
			}		

  | K_FWALL PATH 	{   
			  free(vtun.fwall);  
			  vtun.fwall = strdup($2); 	
			}

  | K_IPROUTE PATH 	{   
			  free(vtun.iproute);  
			  vtun.iproute = strdup($2); 	
			}

  | K_SYSLOG  syslog_opt

  | K_ERROR		{
			  cfg_error("Unknown option '%s'",$1);
			  YYABORT;
			}

 | K_MAX_TUNNELS_NUM NUM 	{  
			  if(vtun.MAX_TUNNELS_NUM == -1)
			     vtun.MAX_TUNNELS_NUM = $2; 	
			}




 ;

bindaddr_option: 
  K_ADDR WORD		{
			  vtun.bind_addr.name = strdup($2);
			  vtun.bind_addr.type = VTUN_ADDR_NAME;
			}

  | K_IFACE WORD	{
			  vtun.bind_addr.name = strdup($2);
			  vtun.bind_addr.type = VTUN_ADDR_IFACE;
			}

  | K_IFACE STRING	{
			  vtun.bind_addr.name = strdup($2);
			  vtun.bind_addr.type = VTUN_ADDR_IFACE;
			}

  | K_ERROR		{
			  cfg_error("Unknown option '%s'",$1);
			  YYABORT;
			}
  ;

syslog_opt:
  NUM 			{
                          vtun.syslog = $1;
  			}

  | WORD 	        {
                          if (parse_syslog($1)) {
                            cfg_error("Unknown syslog facility '%s'", $1);
                            YYABORT;
                          }
                        }

  | K_ERROR 		{
   			  cfg_error("Unknown syslog option '%s'",$1);
  			  YYABORT;
			}
  ;

host_options:
    host_option
  | host_options host_option
  ;

/* Host options. Must free strings first, because they 
 * could be strduped from default_host */
host_option: '\n'
  | K_PASSWD WORD 	{
			  free(parse_host->passwd);
			  parse_host->passwd = strdup($2);
			}

  | K_DEVICE WORD 	{
			  free(parse_host->dev);
			  parse_host->dev = strdup($2);
			}	

  | K_MULTI NUM		{ 
			  parse_host->multi = $2;
			}

  | K_TIMEOUT NUM	{ 
			  parse_host->timeout = $2;
			}
  | K_TICK_SECS NUM 	{  
			     parse_host->TICK_SECS = $2; 	
			}
  | K_RXMIT_CNT_DROP_PERIOD NUM 	{  
			     parse_host->RXMIT_CNT_DROP_PERIOD = $2; 	
			}
  | K_MAX_WEIGHT_NORM NUM 	{  
			     parse_host->MAX_WEIGHT_NORM = $2; 	
			}
  | K_WEIGHT_SCALE NUM 	{  
			     parse_host->WEIGHT_SCALE = $2; 	
			}
  | K_WEIGHT_SMOOTH_DIV NUM 	{  
			     parse_host->WEIGHT_SMOOTH_DIV = $2; 	
			}


 | K_WEIGHT_START_STICKINESS NUM 	{  
			     parse_host->WEIGHT_START_STICKINESS = $2; 	
			}


 | K_WEIGHT_SAW_STEP_UP_DIV NUM 	{  
			     parse_host->WEIGHT_SAW_STEP_UP_DIV = $2; 	
			}

 | K_WEIGHT_SAW_STEP_UP_MIN_STEP NUM 	{  
			     parse_host->WEIGHT_SAW_STEP_UP_MIN_STEP = $2; 	
			}

 | K_WEIGHT_SAW_STEP_DN_DIV NUM 	{  
			     parse_host->WEIGHT_SAW_STEP_DN_DIV = $2; 	
			}


 | K_WEIGHT_MSEC_DELAY NUM 	{  
			     parse_host->WEIGHT_MSEC_DELAY = $2; 	
			}


 | K_MAX_WINDOW NUM 	{  
			     parse_host->MAX_WINDOW = $2; 	
			}
			
 | K_PEN_USEC_IMMUNE NUM 	{  
			    
			}

 | K_MAX_LATENCY NUM 	{  
			     parse_host->MAX_LATENCY = $2; 	
			}


 | K_MAX_LATENCY_DROP NUM 	{  
			     parse_host->MAX_LATENCY_DROP = $2; 	
			}


 | K_MAX_ALLOWED_BUF_LEN NUM 	{  
			     parse_host->MAX_ALLOWED_BUF_LEN = $2; 	
			}


 | K_MAX_REORDER NUM 	{  
			     parse_host->MAX_REORDER = $2; 	
			}


 | K_MAX_IDLE_TIMEOUT NUM 	{  
			     parse_host->MAX_IDLE_TIMEOUT = $2; 	
			}


 | K_FRAME_COUNT_SEND_LWS NUM 	{  
			     parse_host->FRAME_COUNT_SEND_LWS = $2; 	
			}


 | K_PING_INTERVAL NUM 	{  
			     parse_host->PING_INTERVAL = $2; 	
			}


 | K_TUN_TXQUEUE_LEN NUM 	{  
			     parse_host->TUN_TXQUEUE_LEN = $2; 	
			}


 | K_TCP_CONN_AMOUNT NUM	{  
			     parse_host->TCP_CONN_AMOUNT = $2; 	
			}

 | K_START_WEIGHT NUM	{  
			     parse_host->START_WEIGHT = $2; 	
			}

 | K_RT_MARK NUM	{  
			     parse_host->RT_MARK = $2; 	
			}






  | K_SPEED NUM 	{ 
			  if( $2 ){ 
			     parse_host->spd_in = parse_host->spd_out = $2;
			     parse_host->flags |= VTUN_SHAPE;
			  } else 
			     parse_host->flags &= ~VTUN_SHAPE;
			}

  | K_SPEED DNUM 	{ 
			  if( yylval.dnum.num1 || yylval.dnum.num2 ){ 
			     parse_host->spd_out = yylval.dnum.num1;
		             parse_host->spd_in = yylval.dnum.num2; 	
			     parse_host->flags |= VTUN_SHAPE;
			  } else 
			     parse_host->flags &= ~VTUN_SHAPE;
			}

  | K_COMPRESS 		{
			  parse_host->flags &= ~(VTUN_ZLIB | VTUN_LZO); 
			}
			compress

  | K_ENCRYPT NUM 	{  
			  if( $2 ){
			     parse_host->flags |= VTUN_ENCRYPT;
			     parse_host->cipher = $2;
			  } else
			     parse_host->flags &= ~VTUN_ENCRYPT;
			}

  | K_KALIVE 		{
			  parse_host->flags &= ~VTUN_KEEP_ALIVE; 
			}
			keepalive	

  | K_STAT NUM		{
			  if( $2 )
			     parse_host->flags |= VTUN_STAT;
			  else
			     parse_host->flags &= ~VTUN_STAT;
			}

  | K_PERSIST NUM 	{ 
	      		  parse_host->persist = $2;

			  if(vtun.persist == -1) 
			     vtun.persist = $2; 	
			}

  | K_TYPE NUM 		{  
			  parse_host->flags &= ~VTUN_TYPE_MASK;
			  parse_host->flags |= $2;
			}	

  | K_PROT NUM 		{  
			  parse_host->flags &= ~VTUN_PROT_MASK;
			  parse_host->flags |= $2;
			}

  | K_SRCADDR 		'{' srcaddr_options '}'

  | K_UP 	        { 
			  parse_cmds = &parse_host->up; 
   			  llist_free(parse_cmds, free_cmd, NULL);   
			} '{' command_options '}' 

  | K_DOWN 	        { 
			  parse_cmds = &parse_host->down; 
   			  llist_free(parse_cmds, free_cmd, NULL);   
			} '{' command_options '}' 

  | K_ERROR		{
			  cfg_error("Unknown option '%s'",$1);
			  YYABORT;
			} 
  ;

compress:  
  NUM	 		{ 
			  if( $1 ){  
      			     parse_host->flags |= VTUN_ZLIB; 
			     parse_host->zlevel = $1;
			  }
			}

  | DNUM		{
			  parse_host->flags |= yylval.dnum.num1;
		          parse_host->zlevel = yylval.dnum.num2;
  			}

  | K_ERROR		{
			  cfg_error("Unknown compression '%s'",$1);
			  YYABORT;
			} 
  ;

keepalive:  
  NUM	 		{ 
			  if( $1 )
			     parse_host->flags |= VTUN_KEEP_ALIVE;
			}

  | DNUM		{
			  if( yylval.dnum.num1 ){
			     parse_host->flags |= VTUN_KEEP_ALIVE;
			     parse_host->ka_interval = yylval.dnum.num1;
		             parse_host->ka_failure  = yylval.dnum.num2;
			  }
  			}

  | K_ERROR		{
			  cfg_error("Unknown keepalive option '%s'",$1);
			  YYABORT;
			} 
  ;

srcaddr_options: /* empty */
  | srcaddr_option
  | srcaddr_options srcaddr_option
  ;

srcaddr_option:  
  K_ADDR WORD		{
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup($2);
			  parse_host->src_addr.type = VTUN_ADDR_NAME;
			}

  | K_IFACE WORD	{
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup($2);
			  parse_host->src_addr.type = VTUN_ADDR_IFACE;
			}

  | K_IFACE STRING	{
			  free_addr(parse_host);
			  parse_host->src_addr.name = strdup($2);
			  parse_host->src_addr.type = VTUN_ADDR_IFACE;
			}

  | K_PORT NUM 		{
			  parse_host->src_addr.port = $2;
			}

  | K_ERROR		{
			  cfg_error("Unknown option '%s'",$1);
			  YYABORT;
			} 
  ;

command_options: /* empty */
  | command_option
  | command_options command_option
  ;

command_option: '\n' 
  | K_PROG		{
			  memset(&parse_cmd, 0, sizeof(struct vtun_cmd));
			} 
 	prog_options    {
			  add_cmd(parse_cmds, parse_cmd.prog, 
				  parse_cmd.args, parse_cmd.flags);
			}

  | K_PPP STRING 	{   
			  add_cmd(parse_cmds, strdup(vtun.ppp), strdup($2), 
					VTUN_CMD_DELAY);
			}		

  | K_IFCFG STRING 	{   
			  add_cmd(parse_cmds, strdup(vtun.ifcfg),strdup($2),
					VTUN_CMD_WAIT);
			}

  | K_ROUTE STRING 	{   
			  add_cmd(parse_cmds, strdup(vtun.route),strdup($2),
					VTUN_CMD_WAIT);
			}

  | K_FWALL STRING 	{   
			  add_cmd(parse_cmds, strdup(vtun.fwall),strdup($2),
					VTUN_CMD_WAIT);
			}

  | K_IPROUTE STRING 	{   
			  add_cmd(parse_cmds, strdup(vtun.iproute),strdup($2),
					VTUN_CMD_WAIT);
			}

  | K_ERROR		{
			  cfg_error("Unknown cmd '%s'",$1);
			  YYABORT;
			} 
  ;

prog_options:
    prog_option
  | prog_options prog_option
  ;

prog_option:
  PATH  		{
			  parse_cmd.prog = strdup($1);
			}

  | STRING 		{
			  parse_cmd.args = strdup($1);
			}

  | NUM		   	{
			  parse_cmd.flags = $1;
			}
  ;
%%

int yyerror(char *s) 
{
   vlog(LOG_ERR, "%s line %d\n", s, lineno);
   return 0;
}

int cfg_error(const char *fmt, ...)
{
   char buf[255];
   va_list ap;

   /* print the argument string */
   va_start(ap, fmt);
   vsnprintf(buf,sizeof(buf),fmt,ap);
   va_end(ap);

   yyerror(buf);
   return 0;
}

int add_cmd(llist *cmds, char *prog, char *args, int flags)
{
   struct vtun_cmd *cmd;
   if( !(cmd = malloc(sizeof(struct vtun_cmd))) ){
      yyerror("No memory for the command");
      return -1;
   }
   memset(cmd, 0, sizeof(struct vtun_cmd)); 		   			

   cmd->prog = prog;
   cmd->args = args;
   cmd->flags = flags;
   llist_add(cmds, cmd);

   return 0;
}		

void *cp_cmd(void *d, void *u)
{
   struct vtun_cmd *cmd = d, *cmd_copy; 

   if( !(cmd_copy = malloc(sizeof(struct vtun_cmd))) ){
      yyerror("No memory to copy the command");
      return NULL;
   }
 
   cmd_copy->prog = strdup(cmd->prog);
   cmd_copy->args = strdup(cmd->args);
   cmd_copy->flags = cmd->flags;
   return cmd_copy;
}

int free_cmd(void *d, void *u)
{
   struct vtun_cmd *cmd = d; 
   free(cmd->prog);
   free(cmd->args);
   free(cmd);
   return 0;
}

void copy_addr(struct vtun_host *to, struct vtun_host *from)
{  
   if( from->src_addr.type ){
      to->src_addr.type = from->src_addr.type;
      to->src_addr.name = strdup(from->src_addr.name);
   }
   to->src_addr.port = from->src_addr.port;
}

void free_addr(struct vtun_host *h)
{  
   if( h->src_addr.type ){
      h->src_addr.type = 0;
      free(h->src_addr.name);
   }
}

int free_host(void *d, void *u)
{
   struct vtun_host *h = d;

   if (u && !strcmp(h->host, u))
      return 1;

   free(h->host);   
   free(h->passwd);   
   
   llist_free(&h->up, free_cmd, NULL);   
   llist_free(&h->down, free_cmd, NULL);

   free_addr(h);

   /* releases only host struct instances which were
    * allocated in the case of K_HOST except default_host */
   if( h->passwd )
      free(h);
 
   return 0;   
}

/* Find host in the hosts list.
 * NOTE: This function can be called only once since it deallocates hosts list.
 */ 
inline struct vtun_host* find_host(char *host)
{
   return (struct vtun_host *)llist_free(&host_list, free_host, host);
}

inline void free_host_list(void)
{
   llist_free(&host_list, free_host, NULL);
}

static struct {
   char *c_name;
   int  c_val;
} syslog_names[] = {
    { "auth",   LOG_AUTH },
    { "cron",   LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern",   LOG_KERN },
    { "lpr",    LOG_LPR },
    { "mail",   LOG_MAIL },
    { "news",   LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user",   LOG_USER },
    { "uucp",   LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

int parse_syslog(char *facility)
{
   int i;

   for (i=0; syslog_names[i].c_name;i++) {
      if (!strcmp(syslog_names[i].c_name, facility)) {
         vtun.syslog = syslog_names[i].c_val;
         return(0);
      }
   }
}

/* 
 * Read config file. 
 */ 
int read_config(char *file) 
{
   static int cfg_loaded = 0;
   extern FILE *yyin;

   if( cfg_loaded ){
      free_host_list();
      vlog(LOG_INFO,"Reloading configuration file");
   }	 
   cfg_loaded = 1;

   llist_init(&host_list);

   if( !(yyin = fopen(file,"r")) ){
      vlog(LOG_ERR,"Can not open %s", file);
      return -1;      
   }

   yyparse();

   free_host(&default_host, NULL);

   fclose(yyin);
  
   return !llist_empty(&host_list);     
}
