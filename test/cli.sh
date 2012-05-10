#!/bin/bash
cd /home/andrew
vtrunkd -f ./vtrunkd-cli.test.conf atest3 172.16.1.1 -P 5003
vtrunkd -f ./vtrunkd-cli.test.conf atest1 172.16.2.1 -P 5003
vtrunkd -f ./vtrunkd-cli.test.conf atest2 172.16.3.1 -P 5003

