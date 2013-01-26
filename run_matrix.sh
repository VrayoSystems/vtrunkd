#!/bin/bash
# Run a series of tests
OPTARG=$1
# VALUES: 
#RATE1    DELAY1 JITTR1 PERCENT1      RATE2 ...
MAT='
 100kbit 200ms 50ms 50%    100kbit 200ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%    200kbit 200ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%    300kbit 150ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%    600kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%    800kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
 100kbit 200ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

 200kbit 200ms 50ms 50%    300kbit 200ms 50ms 50%    100kbit 200ms 50ms 50%
 200kbit 200ms 50ms 50%    600kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 200kbit 200ms 50ms 50%    800kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 200kbit 200ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
 200kbit 200ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

 300kbit 150ms 50ms 50%    300kbit 200ms 50ms 50%    100kbit 200ms 50ms 50%
 300kbit 150ms 50ms 50%    600kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 300kbit 150ms 50ms 50%    800kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 300kbit 150ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
 300kbit 150ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

 600kbit 100ms 50ms 50%    600kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 600kbit 100ms 50ms 50%    800kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 600kbit 100ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
 600kbit 100ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

 800kbit 100ms 50ms 50%    800kbit 100ms 50ms 50%    100kbit 200ms 50ms 50%
 800kbit 100ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
 800kbit 100ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

1200kbit  80ms 50ms 50%   1200kbit  80ms 50ms 50%    100kbit 200ms 50ms 50%
1200kbit  80ms 50ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%

5000kbit  20ms 10ms 50%   5000kbit  10ms 10ms 50%    100kbit 200ms 50ms 50%
';


while getopts :p:f OPTION
do
 case $OPTION in
 f) echo "Fast test mode"
  FASTT=true
  ;;
 p) echo "Prefix set $OPTARG"
  PREFIX=$OPTARG
  ;;
 :)
  echo "Option -$OPTARG requires an argument." >&2
  exit 1
 ;;
 esac
done

if [[ ! -v FASTT ]]
then
  FASTT=false   # Initialize it to zero!
fi



TCRULES=/tmp/tcrules.sh
LCNT=~/log_getter.counter
COUNT=$((`cat $LCNT`+1));
CSV=~/result${COUNT}${PREFIX}.csv
echo "rate1,delay1,jit1,percent1,rate2,delay2,jit2,percent2,rate3,delay3,jit3,percent3,SPEED,AG_EFF,C_GROW,C_USE,prefix" >> $CSV

re="([A-Za-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9\%]+)\s+([A-Za-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9\%]+)\s+([A-Za-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9]+)\s+([a-z0-9\%]+)$"

IFS=$'\n'
for VALSET in $MAT; do

echo "Doing $VALSET"
# IFS=" "; echo $VALSET | read rate1 delay1 jit1 percent1 rate2 delay2 jit2 percent2 rate3 delay3 jit3 percent3
[[ $VALSET =~ $re ]] && rate1="${BASH_REMATCH[1]}" && delay1="${BASH_REMATCH[2]}" && jit1="${BASH_REMATCH[3]}" && percent1="${BASH_REMATCH[4]}" && rate2="${BASH_REMATCH[5]}" && delay2="${BASH_REMATCH[6]}" && jit2="${BASH_REMATCH[7]}" && percent2="${BASH_REMATCH[8]}" && rate3="${BASH_REMATCH[9]}" && delay3="${BASH_REMATCH[10]}" && jit3="${BASH_REMATCH[11]}" && percent3="${BASH_REMATCH[12]}" 

IFS=$'\n'

cat > $TCRULES<<EOF
#!/bin/sh

# eth1
echo "eth1 - bad yota:"
tc qdisc del dev eth1 root
tc qdisc add dev eth1 root handle 1: htb default 12
tc class add dev eth1 parent 1:1 classid 1:12 htb rate $rate1 ceil $rate1
tc qdisc add dev eth1 parent 1:12 netem delay $delay1 $jit1 $percent1
tc -s qdisc ls dev eth1
tc -s class ls dev eth1

# eth2
echo "eth2 : good 3g/cdma"
tc qdisc del dev eth2 root
tc qdisc add dev eth2 root handle 1: htb default 12
tc class add dev eth2 parent 1:1 classid 1:12 htb rate $rate2 ceil $rate2
tc qdisc add dev eth2 parent 1:12 netem delay $delay2 $jit2 $percent2
tc -s qdisc ls dev eth2
tc -s class ls dev eth2

# eth3
echo "eth3 : goog 3g/cdma"
tc qdisc del dev eth3 root
tc qdisc add dev eth3 root handle 1: htb default 12
tc class add dev eth3 parent 1:1 classid 1:12 htb rate $rate3 ceil $rate3
tc qdisc add dev eth3 parent 1:12 netem delay $delay3 $jit3 $percent3
tc -s qdisc ls dev eth3
tc -s class ls dev eth3
EOF

# TODO: dynamic tests!

chmod 777 $TCRULES

#done rules

# run log_getter_srv.sh
if $FASTT; then
    ./log_getter_srv.sh -n -f
else
    ./log_getter_srv.sh -n
fi

LCNT=~/log_getter.counter
COUNT=`cat $LCNT`;


# now parse results knowing the COUNTER for this run...
RESULT=/tmp/${COUNT}_.nojson
echo "Result is $RESULT"
SPEED=`cat $RESULT | grep speed_download | cut -d' ' -f6 | cut -d',' -f1`
# now calculate AG percentage given that we AG'd two channels:
echo "Speed is $SPEED"
SPEED_AG=$(($SPEED*8))
SPEED_ETH1=`echo $rate1 | cut -d'k' -f1`
SPEED_ETH2=`echo $rate2 | cut -d'k' -f1`
SPEED_ETH1=$(($SPEED_ETH1*1000))
SPEED_ETH2=$(($SPEED_ETH2*1000))
echo "ETHis $SPEED_ETH1"

 if [ ${SPEED_ETH1} -gt ${SPEED_ETH2} ]; then
  AG_EFF=`python -c "print (${SPEED_AG} - ${SPEED_ETH1}) * 100.0 / ${SPEED_ETH2}"`
  C_GROW=`python -c "print (${SPEED_AG} *100.0) / ${SPEED_ETH1}"`
  fdsfsdf=`python -c "print (${SPEED_AG}) * 100.0 /  (${SPEED_ETH1} + ${SPEED_ETH2})"`
 else
  AG_EFF=`python -c "print (${SPEED_AG} - ${SPEED_ETH2}) * 100.0 / ${SPEED_ETH1}"`
  C_GROW=`python -c "print (${SPEED_AG} *100.0) / ${SPEED_ETH2}"`
  fdsfsdf=`python -c "print (${SPEED_AG}) * 100.0 /  (${SPEED_ETH1} + ${SPEED_ETH2})"`
 fi
 
# now set up a CSV
echo "$rate1,$delay1,$jit1,$percent1,$rate2,$delay2,$jit2,$percent2,$rate3,$delay3,$jit3,$percent3,$SPEED,$AG_EFF,$C_GROW,$fdsfsdf,$COUNT" >> $CSV

done

echo "Uploading result..."
DBOXHOST=grandrew@alternet.homelinux.net # host to upload JSON logs to and parse them on
DBOXHOST_PORT=10023
scp -P $DBOXHOST_PORT $CSV $DBOXHOST:~/Dropbox/alarm_logs/


rm $TCRULES

