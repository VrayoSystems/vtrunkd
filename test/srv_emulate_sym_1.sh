#!/bin/sh

# eth1
echo "eth1 - bad yota:"
tc qdisc del dev eth1 root
tc qdisc add dev eth1 root handle 1: htb default 12
tc class add dev eth1 parent 1:1 classid 1:12 htb rate 1mbit ceil 1mbit
#tc qdisc add dev eth1 parent 1:12 netem delay 150ms 50ms 50%
tc -s qdisc ls dev eth1
tc -s class ls dev eth1

# eth2
echo "eth2 : fine 3g/cdma"
tc qdisc del dev eth2 root
tc qdisc add dev eth2 root handle 1: htb default 12
tc class add dev eth2 parent 1:1 classid 1:12 htb rate 1mbit ceil 1mbit
#tc qdisc add dev eth2 parent 1:12 netem delay 170ms 30ms 10%
tc -s qdisc ls dev eth2
tc -s class ls dev eth2

# eth3
echo "eth3 : fine 3g/cdma"
tc qdisc del dev eth3 root
tc qdisc add dev eth3 root handle 1: htb default 12
tc class add dev eth3 parent 1:1 classid 1:12 htb rate 1mbit ceil 1mbit
#tc qdisc add dev eth3 parent 1:12 netem delay 120ms 50ms 10%
tc -s qdisc ls dev eth3
tc -s class ls dev eth3

