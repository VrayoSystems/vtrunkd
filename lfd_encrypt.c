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
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)       
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with
 * several improvements and modifications by me.
 */

/*
 * The current lfd_encrypt module is based on code attributed above and 
 * uses new code written by Dale Fountain <dpf-vtun@fountainbay.com> to 
 * allow multiple ciphers, modes, and key sizes. Feb 2004.
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "log.h"

#ifdef HAVE_SSL

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>

/*
 * #define LFD_ENCRYPT_DEBUG
 */

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 128 
#define ENC_KEY_SIZE 16

BF_KEY key;
char * enc_buf;
char * dec_buf;

#define CIPHER_INIT		0
#define CIPHER_CODE		1	
#define CIPHER_SEQUENCE 	2
#define CIPHER_REQ_INIT 	3

struct vtun_host *phost;

extern int send_a_packet;

/* out of sync packet threshold before forcing a re-init */ 
#define MAX_GIBBERISH	10
#define MIN_GIBBERISH   1
#define MAX_GIBBERISH_TIME   2
int gibberish;
time_t gib_time_start;

int cipher_enc_state;
int cipher_dec_state;
int cipher;
int blocksize;
int keysize;
int enc_init_first_time;
int dec_init_first_time;
unsigned long sequence_num;
char * pkey;
char * iv_buf;

EVP_CIPHER_CTX ctx_enc;	/* encrypt */
EVP_CIPHER_CTX ctx_dec;	/* decrypt */

EVP_CIPHER_CTX ctx_enc_ecb;	/* sideband ecb encrypt */
EVP_CIPHER_CTX ctx_dec_ecb;	/* sideband ecb decrypt */

int prep_key(char **key, int size, struct vtun_host *host)
{
   int tmplen, halflen;
   char *hashkey;

   if ( !(hashkey = malloc(size)) )
   {
      vlog(LOG_ERR,"Can't allocate buffer for key hash");
      return -1;
   }
   memset(hashkey,0,size);

   if (size == 32)
   {
      tmplen = strlen(host->passwd);
      if (tmplen != 0) halflen = tmplen>>1;
      else halflen = 0;
      MD5(host->passwd, halflen, hashkey);
      MD5((host->passwd)+halflen, tmplen-halflen, hashkey+16);
   }
   else if (size == 16)
   {
      MD5(host->passwd,strlen(host->passwd), hashkey);
   }
   else
   {
      /* don't know what to do */
      free(hashkey);
      *key = NULL;
      return -1;
   }
   *key = hashkey;
   return 0;
}

void free_key (char *key)
{
   free(key);
}

int alloc_encrypt(struct vtun_host *host)
{
   int sb_init = 0;
   int var_key = 0;
   const EVP_CIPHER *cipher_type;
   char tmpstr[64];
   char cipher_name[32];
   EVP_CIPHER_CTX *pctx_enc;
   EVP_CIPHER_CTX *pctx_dec;

   enc_init_first_time = 1;   
   dec_init_first_time = 1;   

   if( !(enc_buf = lfd_alloc(ENC_BUF_SIZE)) ){
      vlog(LOG_ERR,"Can't allocate buffer for encryptor");
      return -1;
   }
   if( !(dec_buf = lfd_alloc(ENC_BUF_SIZE)) ){
      vlog(LOG_ERR,"Can't allocate buffer for decryptor");
      return -1;
   }

   RAND_bytes((char *)&sequence_num, 4);
   gibberish = 0;
   gib_time_start = 0;
   phost = host;
   cipher = host->cipher;
   switch(cipher)
   {
      case VTUN_ENC_AES256OFB:
      case VTUN_ENC_AES256CFB:
      case VTUN_ENC_AES256CBC:
         blocksize = 16;
         keysize = 32;
         sb_init = 1;
         cipher_type = EVP_aes_256_ecb();
         pctx_enc = &ctx_enc_ecb;
         pctx_dec = &ctx_dec_ecb;
      break;
      
      case VTUN_ENC_AES256ECB:
         blocksize = 16;
         keysize = 32;
         pctx_enc = &ctx_enc;
         pctx_dec = &ctx_dec;
         cipher_type = EVP_aes_256_ecb();
         strcpy(cipher_name,"AES-256-ECB");
      break;      
      case VTUN_ENC_AES128OFB:
      case VTUN_ENC_AES128CFB:
      case VTUN_ENC_AES128CBC:
         blocksize = 16;
         keysize = 16;
         sb_init=1;
         cipher_type = EVP_aes_128_ecb();
         pctx_enc = &ctx_enc_ecb;
         pctx_dec = &ctx_dec_ecb;
      break;
      case VTUN_ENC_AES128ECB:
         blocksize = 16;
         keysize = 16;
         pctx_enc = &ctx_enc;
         pctx_dec = &ctx_dec;
         cipher_type = EVP_aes_128_ecb();
         strcpy(cipher_name,"AES-128-ECB");
      break;

      case VTUN_ENC_BF256OFB:
      case VTUN_ENC_BF256CFB:
      case VTUN_ENC_BF256CBC:
         blocksize = 8;
         keysize = 32;
         var_key = 1;
         sb_init = 1;
         cipher_type = EVP_bf_ecb();
         pctx_enc = &ctx_enc_ecb;
         pctx_dec = &ctx_dec_ecb;
      break;

      case VTUN_ENC_BF256ECB:
         blocksize = 8;
         keysize = 32;
         var_key = 1;
         pctx_enc = &ctx_enc;
         pctx_dec = &ctx_dec;
         cipher_type = EVP_bf_ecb();
         strcpy(cipher_name,"Blowfish-256-ECB");
      break;

      case VTUN_ENC_BF128OFB:
      case VTUN_ENC_BF128CFB:
      case VTUN_ENC_BF128CBC:
         blocksize = 8;
         keysize = 16;
         var_key = 1;
         sb_init = 1;
         cipher_type = EVP_bf_ecb();
         pctx_enc = &ctx_enc_ecb;
         pctx_dec = &ctx_dec_ecb;
      break;
      case VTUN_ENC_BF128ECB: /* blowfish 128 ecb is the default */
      default:
         blocksize = 8;
         keysize = 16;
         var_key = 1;
         pctx_enc = &ctx_enc;
         pctx_dec = &ctx_dec;
         cipher_type = EVP_bf_ecb();
         strcpy(cipher_name,"Blowfish-128-ECB");
      break;
   } /* switch(host->cipher) */

   if (prep_key(&pkey, keysize, host) != 0) return -1;
   EVP_CIPHER_CTX_init(pctx_enc);
   EVP_CIPHER_CTX_init(pctx_dec);
   EVP_EncryptInit_ex(pctx_enc, cipher_type, NULL, NULL, NULL);
   EVP_DecryptInit_ex(pctx_dec, cipher_type, NULL, NULL, NULL);
   if (var_key)
   {
      EVP_CIPHER_CTX_set_key_length(pctx_enc, keysize);
      EVP_CIPHER_CTX_set_key_length(pctx_dec, keysize);
   }
   EVP_EncryptInit_ex(pctx_enc, NULL, NULL, pkey, NULL);
   EVP_DecryptInit_ex(pctx_dec, NULL, NULL, pkey, NULL);
   EVP_CIPHER_CTX_set_padding(pctx_enc, 0);
   EVP_CIPHER_CTX_set_padding(pctx_dec, 0);
   if (sb_init)
   {
      cipher_enc_state=CIPHER_INIT;
      cipher_dec_state=CIPHER_INIT;
   }
   else
   {
      cipher_enc_state=CIPHER_CODE;
      cipher_dec_state=CIPHER_CODE;
      sprintf(tmpstr,"%s encryption initialized", cipher_name);
      vlog(LOG_INFO, tmpstr);
   }
   return 0;
}

int free_encrypt()
{
   free_key(pkey); pkey = NULL;

   lfd_free(enc_buf); enc_buf = NULL;
   lfd_free(dec_buf); dec_buf = NULL;

   EVP_CIPHER_CTX_cleanup(&ctx_enc);
   EVP_CIPHER_CTX_cleanup(&ctx_dec);
   EVP_CIPHER_CTX_cleanup(&ctx_enc_ecb);
   EVP_CIPHER_CTX_cleanup(&ctx_dec_ecb);

   return 0;
}

int encrypt_buf(int len, char *in, char **out)
{ 
   register int pad, p, msg_len;
   int outlen;
   char *in_ptr, *out_ptr = enc_buf;

   msg_len = send_msg(len, in, out);
   in = *out;
   in_ptr = in+msg_len;
   memcpy(out_ptr,in,msg_len);
   out_ptr += msg_len;
   
   send_ib_mesg(&len, &in_ptr);
   if (!len) return 0;
   /* ( len % blocksize ) */
   p = (len & (blocksize-1)); pad = blocksize - p;
   
   memset(in_ptr+len, pad, pad);
   outlen=len+pad;
   if (pad == blocksize)
      RAND_bytes(in_ptr+len, blocksize-1);
   EVP_EncryptUpdate(&ctx_enc, out_ptr, &outlen, in_ptr, len+pad);
   *out = enc_buf;

   sequence_num++;

   return outlen+msg_len;
}

int decrypt_buf(int len, char *in, char **out)
{
   register int pad;
   char *tmp_ptr, *in_ptr, *out_ptr = dec_buf;
   int outlen;

   len = recv_msg(len, in, out);
   in = *out;
   in_ptr = in;

   outlen=len;
   if (!len) return 0;
   EVP_DecryptUpdate(&ctx_dec, out_ptr, &outlen, in_ptr, len);
   recv_ib_mesg(&outlen, &out_ptr);
   if (!outlen) return 0;
   tmp_ptr = out_ptr + outlen; tmp_ptr--;
   pad = *tmp_ptr;
   if (pad < 1 || pad > blocksize) {
      vlog(LOG_INFO, "decrypt_buf: bad pad length");
      return 0;
   }
   *out = out_ptr;
   return outlen - pad;
}

int cipher_enc_init(char * iv)
{
   int var_key = 0;
   const EVP_CIPHER *cipher_type;
   char tmpstr[64];
   char cipher_name[32];

   switch(cipher)
   {
      case VTUN_ENC_AES256OFB:
         cipher_type = EVP_aes_256_ofb();
         strcpy(cipher_name, "AES-256-OFB");
      break;

      case VTUN_ENC_AES256CFB:
         cipher_type = EVP_aes_256_cfb();
         strcpy(cipher_name, "AES-256-CFB");
      break;

      case VTUN_ENC_AES256CBC:
         cipher_type = EVP_aes_256_cbc();
         strcpy(cipher_name, "AES-256-CBC");
      break;

      case VTUN_ENC_AES128OFB:
         cipher_type = EVP_aes_128_ofb();
         strcpy(cipher_name, "AES-128-OFB");
      break;
      case VTUN_ENC_AES128CFB:
         cipher_type = EVP_aes_128_cfb();
         strcpy(cipher_name, "AES-128-CFB");
      break;
      case VTUN_ENC_AES128CBC:
         cipher_type = EVP_aes_128_cbc();
         strcpy(cipher_name, "AES-128-CBC");
      break;

      case VTUN_ENC_BF256OFB:
         var_key = 1;
         cipher_type = EVP_bf_ofb();
         strcpy(cipher_name, "Blowfish-256-OFB");
      break;
      case VTUN_ENC_BF256CFB:
         var_key = 1;
         cipher_type = EVP_bf_cfb();
         strcpy(cipher_name, "Blowfish-256-CFB");
      break;

      case VTUN_ENC_BF256CBC:
         var_key = 1;
         cipher_type = EVP_bf_cbc();
         strcpy(cipher_name, "Blowfish-256-CBC");
      break;

      case VTUN_ENC_BF128OFB:
         var_key = 1;
         cipher_type = EVP_bf_ofb();
         strcpy(cipher_name, "Blowfish-128-OFB");
      break;
      case VTUN_ENC_BF128CFB:
         var_key = 1;
         cipher_type = EVP_bf_cfb();
         strcpy(cipher_name, "Blowfish-128-CFB");
      break;
      case VTUN_ENC_BF128CBC:
         var_key = 1;
         cipher_type = EVP_bf_cbc();
         strcpy(cipher_name, "Blowfish-128-CBC");
      break;
      default:
      /* if we're here, something weird's going on */
         return -1;
      break;
   } /* switch(cipher) */

   EVP_CIPHER_CTX_init(&ctx_enc);
   EVP_EncryptInit_ex(&ctx_enc, cipher_type, NULL, NULL, NULL);
   if (var_key)
      EVP_CIPHER_CTX_set_key_length(&ctx_enc, keysize);
   EVP_EncryptInit_ex(&ctx_enc, NULL, NULL, pkey, NULL);
   EVP_EncryptInit_ex(&ctx_enc, NULL, NULL, NULL, iv);
   EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
   if (enc_init_first_time)
   {
      sprintf(tmpstr,"%s encryption initialized", cipher_name);
      vlog(LOG_INFO, tmpstr);
      enc_init_first_time = 0;
   }
   return 0;
}

int cipher_dec_init(char * iv)
{
   int var_key = 0;
   const EVP_CIPHER *cipher_type;
   char tmpstr[64];
   char cipher_name[32];

   switch(cipher)
   {
      case VTUN_ENC_AES256OFB:
         cipher_type = EVP_aes_256_ofb();
         strcpy(cipher_name, "AES-256-OFB");
      break;

      case VTUN_ENC_AES256CFB:
         cipher_type = EVP_aes_256_cfb();
         strcpy(cipher_name, "AES-256-CFB");
      break;

      case VTUN_ENC_AES256CBC:
         cipher_type = EVP_aes_256_cbc();
         strcpy(cipher_name, "AES-256-CBC");
      break;

      case VTUN_ENC_AES128OFB:
         cipher_type = EVP_aes_128_ofb();
         strcpy(cipher_name, "AES-128-OFB");
      break;
      case VTUN_ENC_AES128CFB:
         cipher_type = EVP_aes_128_cfb();
         strcpy(cipher_name, "AES-128-CFB");
      break;
      case VTUN_ENC_AES128CBC:
         cipher_type = EVP_aes_128_cbc();
         strcpy(cipher_name, "AES-128-CBC");
      break;

      case VTUN_ENC_BF256OFB:
         var_key = 1;
         cipher_type = EVP_bf_ofb();
         strcpy(cipher_name, "Blowfish-256-OFB");
      break;
      case VTUN_ENC_BF256CFB:
         var_key = 1;
         cipher_type = EVP_bf_cfb();
         strcpy(cipher_name, "Blowfish-256-CFB");
      break;
      case VTUN_ENC_BF256CBC:
         var_key = 1;
         cipher_type = EVP_bf_cbc();
         strcpy(cipher_name, "Blowfish-256-CBC");
      break;

      case VTUN_ENC_BF128OFB:
         var_key = 1;
         cipher_type = EVP_bf_ofb();
         strcpy(cipher_name, "Blowfish-128-OFB");
      break;
      case VTUN_ENC_BF128CFB:
         var_key = 1;
         cipher_type = EVP_bf_cfb();
         strcpy(cipher_name, "Blowfish-128-CFB");
      break;
      case VTUN_ENC_BF128CBC:
         var_key = 1;
         cipher_type = EVP_bf_cbc();
         strcpy(cipher_name, "Blowfish-128-CBC");
      break;
      default:
      /* if we're here, something weird's going on */
         return -1;
      break;
   } /* switch(cipher) */

   EVP_CIPHER_CTX_init(&ctx_dec);
   EVP_DecryptInit_ex(&ctx_dec, cipher_type, NULL, NULL, NULL);
   if (var_key)
      EVP_CIPHER_CTX_set_key_length(&ctx_dec, keysize);
   EVP_DecryptInit_ex(&ctx_dec, NULL, NULL, pkey, NULL);
   EVP_DecryptInit_ex(&ctx_dec, NULL, NULL, NULL, iv);
   EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
   if (dec_init_first_time)
   {
      sprintf(tmpstr,"%s decryption initialized", cipher_name);
      vlog(LOG_INFO, tmpstr);
      dec_init_first_time = 0;
   }
   return 0;
}

int send_msg(int len, char *in, char **out)
{
   char * iv; char * in_ptr;
   int outlen;

   switch(cipher_enc_state)
   {
      case CIPHER_INIT:
         in_ptr = in - blocksize*2;
         iv = malloc(blocksize);
         RAND_bytes(iv, blocksize);
         strncpy(in_ptr,"ivec",4);
         in_ptr += 4;
         memcpy(in_ptr,iv,blocksize);
         in_ptr += blocksize;
         cipher_enc_init(iv);

         memset(iv,0,blocksize); free(iv); iv = NULL;
         RAND_bytes(in_ptr, in - in_ptr);

         in_ptr = in - blocksize*2;
         outlen = blocksize*2;
         EVP_EncryptUpdate(&ctx_enc_ecb, in_ptr, 
            &outlen, in_ptr, blocksize*2);
         *out = in_ptr;
         len = outlen;
         cipher_enc_state = CIPHER_SEQUENCE;
      break;

      case CIPHER_CODE:
      default:
         *out = in;
         len = 0;
      break;
   }
   return len;
}

int recv_msg(int len, char *in, char **out)
{
   char * iv; char * in_ptr;
   int outlen;

   switch(cipher_dec_state)
   {
      case CIPHER_INIT:
         in_ptr = in;
         iv = malloc(blocksize);
         outlen = blocksize*2;
         EVP_DecryptUpdate(&ctx_dec_ecb, in_ptr, &outlen, in_ptr, blocksize*2);
         
         if ( !strncmp(in_ptr, "ivec", 4) )
         {
            memcpy(iv, in_ptr+4, blocksize);
            cipher_dec_init(iv);

            *out = in_ptr + blocksize*2;
            len -= blocksize*2;
            cipher_dec_state = CIPHER_SEQUENCE;
            gibberish = 0;
            gib_time_start = 0;
         } 
         else 
         {
            len = 0;
            *out = in;
            gibberish++;
            if (gibberish == 1) gib_time_start = time(NULL);

            if (gibberish == MIN_GIBBERISH)
            {
               cipher_enc_state = CIPHER_REQ_INIT;
               send_a_packet = 1;
#ifdef LFD_ENCRYPT_DEBUG
               vlog(LOG_INFO, 
                  "Min. gibberish threshold reached");
#endif
            }
            if (gibberish >= MAX_GIBBERISH || 
                difftime(time(NULL), gib_time_start) >= MAX_GIBBERISH_TIME)
            {
               gibberish = 0;
               gib_time_start = 0;
               send_a_packet = 1;

#ifdef LFD_ENCRYPT_DEBUG
               vlog(LOG_INFO, 
                  "Max. gibberish threshold reached");
#endif
               if (cipher_enc_state != CIPHER_INIT)
               {
                  cipher_enc_state = CIPHER_INIT;
                  EVP_CIPHER_CTX_cleanup(&ctx_enc);
#ifdef LFD_ENCRYPT_DEBUG
                  vlog(LOG_INFO, 
                     "Forcing local encryptor re-init");
#endif
               }
            }
         }
         memset(iv,0,blocksize); free(iv); iv = NULL;
         memset(in_ptr,0,blocksize*2);         
      break;

      case CIPHER_CODE:
      default:
         *out = in;
      break;
   }
   return len;
}

/* Send In-Band Message */
int send_ib_mesg(int *len, char **in)
{
   char *in_ptr = *in;

   /* To simplify matters, I assume that blocksize
         will not be less than 8 bytes */
   if (cipher_enc_state == CIPHER_SEQUENCE)
   {
      in_ptr -= blocksize;
      memset(in_ptr,0,blocksize);
      strncpy(in_ptr,"seq#",4);
      in_ptr+=4;
      *((unsigned long *)in_ptr) = htonl(sequence_num);
      in_ptr-=4;

      *in = in_ptr;
      *len += blocksize;
   }
   else if (cipher_enc_state == CIPHER_REQ_INIT)
   {
      in_ptr -= blocksize;
      memset(in_ptr,0,blocksize);
      strncpy(in_ptr,"rsyn",4);
      in_ptr+=4;
      *((unsigned long *)in_ptr) = htonl(sequence_num);
      in_ptr-=4;

      *in = in_ptr;
      *len += blocksize;
#ifdef LFD_ENCRYPT_DEBUG
      vlog(LOG_INFO, "Requesting remote encryptor re-init");      
#endif
      cipher_enc_state = CIPHER_SEQUENCE;
      send_a_packet = 1; 
   }
   return 0;
}

/* Receive In-Band Message */
int recv_ib_mesg(int *len, char **in)
{
   char *in_ptr = *in;

   if (cipher_dec_state == CIPHER_SEQUENCE)
   {
      /* To simplify matters, I assume that blocksize
         will not be less than 8 bytes */
      if ( !strncmp(in_ptr, "seq#", 4) )
      {
         *in += blocksize;
         *len -= blocksize;
      }
      else if ( !strncmp(in_ptr, "rsyn", 4) )
      {
         *in += blocksize;
         *len -= blocksize;

         if (cipher_enc_state != CIPHER_INIT)
         {
            cipher_enc_state = CIPHER_INIT;
            EVP_CIPHER_CTX_cleanup(&ctx_enc);
         }
#ifdef LFD_ENCRYPT_DEBUG
         vlog(LOG_INFO, "Remote requests encryptor re-init");
#endif
      }
      else
      {
         *len = 0;

         if (cipher_dec_state != CIPHER_INIT &&
             cipher_enc_state != CIPHER_REQ_INIT &&
             cipher_enc_state != CIPHER_INIT)
         {
            EVP_CIPHER_CTX_cleanup (&ctx_dec);
            cipher_dec_state = CIPHER_INIT;
            cipher_enc_state = CIPHER_REQ_INIT;
         }
#ifdef LFD_ENCRYPT_DEBUG
         vlog(LOG_INFO, "Local decryptor out of sync");
#endif
      }
   }
   return 0;
}
/* 
 * Module structure.
 */
struct lfd_mod lfd_encrypt = {
     "Encryptor",
     alloc_encrypt,
     encrypt_buf,
     NULL,
     decrypt_buf,
     NULL,
     free_encrypt,
     NULL,
     NULL
};

#else  /* HAVE_SSL */

int no_encrypt(struct vtun_host *host)
{
     vlog(LOG_INFO, "Encryption is not supported");
     return -1;
}

struct lfd_mod lfd_encrypt = {
     "Encryptor",
     no_encrypt, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_SSL */
