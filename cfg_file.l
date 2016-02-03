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
 * cfg_file.l,v 1.1.1.2.2.1.2.2 2006/11/16 04:02:39 mtbishop Exp
 */ 

#include "config.h"

#include <string.h>

#include "vtun.h"

#include "cfg_file.tab.h"
#include "cfg_kwords.h"

/* static buffer for strings */
char str_buf[255];

int find_keyword(struct kword *kw, char *str);

#define ECHO {;}
#define YY_DECL int yylex(void)

/* Push and pop parser state */
static int stack[16];
static int ptr = 0;

#define PUSH_STATE()							  \
	 do {						  		  \
	   if( ptr == 16 ){						  \
	      yyerror("To many pushes to parser's state stack"); 	  \
	      return K_ERROR; 						  \
	   }								  \
	   stack[ptr++] = YY_START;					  \
         } while(0)

#define POP_STATE()	 						  \
	 do {						  		  \
	   if( !ptr ){							  \
	      yyerror("To many pops from parser's state stack"); 	  \
	      return K_ERROR; 						  \
	   }								  \
	   BEGIN(stack[--ptr]);						  \
         } while(0)

int cfg_error(const char *ftm, ...);

int yyerror(char *str);
%}

num		[0-9]+
dnum		{num}:{num}
word		[A-Za-z0-9\-\_+=\!\$\#\%\&\*\^\@@\\\~\.]+
wordnm		{word}:{num}
kword		[A-Za-z0-9\_\-]+	
comment		\#.*\n
fname		[A-Za-z0-9\_\.\-]+	
path		(\/{fname})+
string		\".*\"

%x OPTION PARAM  

%%
<*>[ \t]	;   /* Skip spaces and tabs (All stages) */

<*>\n		{ lineno++; } /* (All stages) */

<INITIAL,OPTION>{comment}	{ lineno++; } /* Skip comments */

{kword}		{
		  int kw = find_keyword(cfg_keyword,yytext);
		  if( kw != -1 )	
		     return kw;

		  /* Keyword not found, means host definition. */
		  yylval.str = yytext;
		  return K_HOST;
		}

{word}		{
		  yylval.str = yytext;
		  return K_ERROR;
		}

<*>\{		{ 
		  PUSH_STATE();
		  BEGIN(OPTION); 
		  return *yytext;
		}		
<*>\}		{
		  POP_STATE();
		  return *yytext;
		}

<OPTION>{word}	{
		  int kw = find_keyword(cfg_keyword,yytext);
		  if( kw != -1 ){	
		     /* Option found, switch to PARAM stage */
		     PUSH_STATE();
		     BEGIN(PARAM);
		     return kw;
		  }
		  yylval.str = yytext;
		  return K_ERROR;
		}

<PARAM>{string}	{
		  if(yyleng > sizeof(str_buf)-1){
		     yyerror("string to long");
		     return 0;
		  }
		  strncpy(str_buf, yytext+1, yyleng-2);
		  str_buf[yyleng-2] = '\0';

		  yylval.str = str_buf;
					  
		  return STRING;
		}

<PARAM>{dnum}   {
	          char *ptr = strchr(yytext,':') + 1;
		 
		  yylval.dnum.num1 = atoi(yytext);
		  yylval.dnum.num2 = atoi(ptr);
		  return DNUM;
		}

<PARAM>{num}	{
		  yylval.num = atoi(yytext);
		  return NUM;
		}

<PARAM>{word}	{
		  int kw = find_keyword(cfg_param,yytext);
		  if( kw != -1 ){	
		     /* Special parameter found (yes,no,etc) */
		     yylval.num = kw;
		     return NUM;
		  }
		  yylval.str = yytext;
		  return WORD;
		}

<PARAM>{wordnm} {
	          char *ptr = strchr(yytext,':'); *ptr='\0'; 
		  yylval.dnum.num1 = find_keyword(cfg_param,yytext);
		  yylval.dnum.num2 = atoi(++ptr);
		  return DNUM;
		}

<PARAM>{path}	{
		  yylval.str = yytext;
		  return PATH;
		}

<PARAM>\;	{ 
		  POP_STATE();
		}

<*>.		{ /* Garbage (All stages) */
		  cfg_error("Invalid character \'%s\'", yytext); 
		}
%%

int yywrap(void) 
{
    return 1;
}

int find_keyword(struct kword *kw, char *str)
{
    while( kw->str ){
	if( !strncmp(str,kw->str,20) )
	   return kw->type;
	kw++;
    }
    return -1;
}
