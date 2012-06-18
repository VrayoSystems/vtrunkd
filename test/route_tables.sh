#!/bin/bash
ip rule add fwmark 0x1 lookup 101
ip route add dev eth0 table 101

ip rule add fwmark 0x2 lookup 102
ip route add dev eth1 table 102

ip rule add fwmark 0x3 lookup 103
ip route add dev eth2 table 103
