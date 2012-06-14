#!/bin/bash
vtrunkd -f /etc/vtrunkd-cli.test.conf atest1 192.168.57.101 -P 5003
vtrunkd -f /etc/vtrunkd-cli.test.conf atest2 192.168.58.101 -P 5003
vtrunkd -f /etc/vtrunkd-cli.test.conf atest3 192.168.59.101 -P 5003
