#!/bin/sh

# eth1
echo "eth1 - bad yota:"
tc qdisc del dev eth1 root
tc qdisc add dev eth1 root handle 1: htb default 12
tc class add dev eth1 parent 1:1 classid 1:12 htb rate 600kbit ceil 600kbit
tc qdisc add dev eth1 parent 1:12 netem delay 100ms 50ms 50%
#tc qdisc add dev eth1 root handle 1:0 netem delay 60ms 5ms 25%
#tc qdisc add dev eth1 parent 1:1 handle 10: tbf rate 20mbit buffer 100kb limit 3000
tc -s qdisc ls dev eth1
tc -s class ls dev eth1

# eth2
echo "eth2 : good 3g/cdma"
tc qdisc del dev eth2 root
tc qdisc add dev eth2 root handle 1: htb default 12
tc class add dev eth2 parent 1:1 classid 1:12 htb rate 100kbit ceil 100kbit
tc qdisc add dev eth2 parent 1:12 netem delay 200ms 50ms 10%
#tc qdisc add dev eth2 root handle 1:0 netem delay 200ms 50ms 50%
#tc qdisc add dev eth2 parent 1:1 handle 10: tbf rate 7mbit buffer 50kb limit 3000
tc -s qdisc ls dev eth2
tc -s class ls dev eth2

# eth3
echo "eth3 : goog 3g/cdma"
tc qdisc del dev eth3 root
#tc qdisc del dev eth3 parent
tc qdisc add dev eth3 root handle 1: htb default 12
tc class add dev eth3 parent 1:1 classid 1:12 htb rate 6mbit ceil 6mbit
tc qdisc add dev eth3 parent 1:12 netem delay 120ms 50ms 10%
#tc qdisc add dev eth3 root handle 1:0 netem delay 300ms 200ms 25%
#tc qdisc add dev eth3 parent 1:1 handle 10: tbf rate 800mbps buffer 1mb limit 3000
tc -s qdisc ls dev eth3
tc -s class ls dev eth3

# qdisc netem 1: limit 1000 delay 100.0ms
#  Sent 0 bytes 0 pkts (dropped 0, overlimits 0 )
# qdisc tbf 10: rate 256Kbit burst 1599b lat 26.6ms
#  Sent 0 bytes 0 pkts (dropped 0, overlimits 0 )
