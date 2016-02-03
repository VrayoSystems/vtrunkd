[![Build Status](https://travis-ci.org/VrayoSystems/vtrunkd.svg?branch=master)](https://travis-ci.org/VrayoSystems/vtrunkd)

vtrunkd - universal netork link bonding and multichannel VPN.
Copyright (C) 2011-2016 Vrayo Systems Ltd. team 

Vtrunkd is a Linux VPN daemon used to combine several connection paths 
into one aggregated channel. Features latency, reordering and jitter 
management, behaviour analysis optimizations for encapsulated protocols, 
bufferbloat control, packet redundancy, and multiple cpu cores utilization. 
Up to 30 heterogenous links bonding supported. Used for live streaming, 
LTE/3G/Wi-Fi link bonding. 32/64-bit, x86, MIPS and ARM supported. 
Supports python plug-ins for new algorithms implementation. 

Based on original package vtun - Copyright (C) 1998-2004 
Maxim Krasnyansky <max_mk@yahoo.com>

This product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit. (http://www.openssl.org/).
Copyright (c) 1998-2004 The OpenSSL Project.  All rights reserved.

Compilation and Installation:

In order to compile vtrunkd you need several software packages.
Required packages: 
  - Good C compiler (gcc, egcs, etc)
  - GNU Make (make)
  - GNU libtool (libtool)
  - Lexical Analyzer (flex, lex)
  - YACC (yacc, bison, byacc)
  - Universal TUN/TAP driver 	http://vtun.sourceforge.net/tun
  
On ubuntu, run: 
    $ sudo apt-get install build-essential flex bison

To configure run:
  ./configure 

To compile and install run:
  make install

If you have any suggestions, ideas, wishes send them to 
Andrew Gryaznov 
  ag@vrayo.com, 
  https://www.linkedin.com/in/grandrew
  
vtrunkd and vtrunkd algorithm (C) Andrew Gryaznov
Vtun (c) Maxim Krasnyansky
