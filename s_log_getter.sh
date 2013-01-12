#!/bin/bash

# 1. name server VM srv-32
# 2. name client VM cli-32
# 3. set up 3 net cards eth1...eth3 for each VM 
# 4. add frac_digits(3) to syslog-ng options

DBOXHOST=grandrew@alternet.homelinux.net # host to upload JSON logs to and parse them on
DBOXHOST_PORT=10023
LOGS_FOLDER=~/sandbox/alarm_logs
VTRUNKD_L_ROOT=/home/andrey/workspace-cpp/vtrunkd
VTRUNKD_V_ROOT=/home/user/sandbox/test_folder
LCNT=~/log_getter.counter

VSRV_ETH1_IP=192.168.57.101
VSRV_ETH2_IP=192.168.58.101
VSRV_ETH3_IP=192.168.59.101

VCLI_ETH1_IP=192.168.57.100
VCLI_ETH2_IP=192.168.58.100
VCLI_ETH3_IP=192.168.59.100

SRV_MACHINE="user@srv-32"
CLI_MACHINE="user@cli-32"

#NTP_SERVER="0.ubuntu.pool.ntp.org"
NTP_SERVER="192.168.0.101"

if [ ! -f $LCNT ]; then
    RND=`$(($RANDOM % 99))`
    echo -n "$RND"00 > $LCNT
fi

TEST="0"
EXEC="0"

COUNT=$((`cat $LCNT`+1));
echo -n $COUNT > $LCNT

PREFIX="$COUNT"_
TITLE=""
ONE=""
while getopts :oetpT: OPTION
do
 case $OPTION in
 o) echo "One thread"
  ONE="1111"
  TITLE = "One_thread"
  ;;
 e) echo "Execute vtrunkd only"
  EXEC="1"
  ;;
 t) echo "Full speed test"
  TEST="1"
  ;;
 T) echo "Set title"
  TITLE="$OPTARG"
  ;;
 p) echo "Prefix set $OPTARG"
  PREFIX="$OPTARG""_$PREFIX"
  ;;
 :)
  echo "Option -$OPTARG requires an argument." >&2
  exit 1
 ;;
 esac
done

echo "Doing with prefix $PREFIX"
if [ -z "$TITLE" ]; then
    echo "Title is $TITLE"
fi
echo "Starting..."
echo "killall vtrunkd ... "
ssh user@srv-32 "sudo killall -9 vtrunkd 2> /dev/null && sudo ipcrm -M 567888"
ssh user@cli-32 "sudo killall -9 vtrunkd 2> /dev/null && sudo ipcrm -M 567888"
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "Copying vtrunkd sources ..."
ssh user@cli-32 "rm -r -f $VTRUNKD_V_ROOT 2> /dev/null"
ssh user@srv-32 "rm -r -f $VTRUNKD_V_ROOT 2> /dev/null"
ssh user@cli-32 "mkdir -p $VTRUNKD_V_ROOT 2> /dev/null"
ssh user@srv-32 "mkdir -p $VTRUNKD_V_ROOT 2> /dev/null"
scp -r $VTRUNKD_L_ROOT/* user@srv-32:$VTRUNKD_V_ROOT/ > /dev/null
scp -r $VTRUNKD_L_ROOT/* user@cli-32:$VTRUNKD_V_ROOT/ > /dev/null
echo "Compiling vtrunkd ..."
if ssh user@srv-32 "cd $VTRUNKD_V_ROOT; make 2>dev/null"; then 
    echo "OK"
else
    ssh user@srv-32 "cd $VTRUNKD_V_ROOT; ./configure --prefix= --enable-json" > /dev/null
    ssh user@srv-32 "cd $VTRUNKD_V_ROOT; make 2>/dev/null 1>/dev/null"
#    echo "Compile Error!"
#    exit 0;
fi
echo "Compiling ..."
if ssh user@cli-32 "cd $VTRUNKD_V_ROOT; make 2>/dev/null"; then
    echo "OK"
else
    ssh user@cli-32 "cd $VTRUNKD_V_ROOT; ./configure --prefix= --enable-json 2>/dev/null 1>/dev/null"
    ssh user@cli-32 "cd $VTRUNKD_V_ROOT; make 2>/dev/null 1>/dev/null"
#    echo "Compile Error!"
#    exit 0;
fi

echo "NTP sync..."
ssh user@cli-32 "sudo ntpdate $NTP_SERVER" &
sleep 1
ssh user@srv-32 "sudo ntpdate $NTP_SERVER"
echo "Setting IP addresses..."
if ssh user@srv-32 "sudo ifconfig eth1 $VSRV_ETH1_IP && sudo ifconfig eth2 $VSRV_ETH2_IP && sudo ifconfig eth3 $VSRV_ETH3_IP"; then
    echo "OK"
else 
    echo "IP setup error"
    exit 0
fi
if ssh user@cli-32 "sudo ifconfig eth1 $VCLI_ETH1_IP && sudo ifconfig eth2 $VCLI_ETH2_IP && sudo ifconfig eth3 $VCLI_ETH3_IP"; then
    echo "OK"
else 
    echo "IP setup error"
    exit 0
fi
echo "Applying emulation TC rules"
ssh user@srv-32 "sudo $VTRUNKD_V_ROOT/test/srv_emulate_2.sh > /dev/null"

echo "Starting server..."
ssh user@srv-32 "sudo $VTRUNKD_V_ROOT/vtrunkd -s -f $VTRUNKD_V_ROOT/test/vtrunkd-srv.test.conf -P 5003"
sleep 5
echo "Starting client 1..."
ssh user@cli-32 "sudo $VTRUNKD_V_ROOT/vtrunkd -f $VTRUNKD_V_ROOT/test/vtrunkd-cli.test.conf atest1 $VSRV_ETH1_IP -P 5003"
if [ -z $ONE ]; then
    sleep 1
    echo "Starting client 2..."
    ssh user@cli-32 "sudo $VTRUNKD_V_ROOT/vtrunkd -f $VTRUNKD_V_ROOT/test/vtrunkd-cli.test.conf atest2 $VSRV_ETH2_IP -P 5003"
fi
sleep 8
echo "Full started"
if [ $EXEC = "1" ]; then
    "Execute only!"
    exit 0;
fi
if [ $TITLE ]; then
    echo "$TITLE" > /tmp/${PREFIX}speed
fi
git branch -a | grep \*  | tr -d '\n' >> /tmp/${PREFIX}speed
git log --oneline -1 >> /tmp/${PREFIX}speed
echo "Worcking..."
ssh user@cli-32 'echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | curl -m 90 --connect-timeout 4 http://10.200.1.31/u -o /dev/null -w @-' >> /tmp/${PREFIX}speed
echo "" >>  /tmp/${PREFIX}speed
ssh user@cli-32 "ping -c 10 -q -a 10.200.1.31" | tail -1 >> /tmp/${PREFIX}speed
cat ./test/srv_emulate_2.sh | grep ceil | awk {'print$12" "'} | tr -d '\n' >> /tmp/${PREFIX}speed
echo "" >> /tmp/${PREFIX}speed
cat ./test/srv_emulate_2.sh | grep delay | grep -v "#" | awk {'print$10" "$11" "$12";"'} | tr -d '\n' >> /tmp/${PREFIX}speed
echo "" >> /tmp/${PREFIX}speed
echo "killall vtrunkd"
ssh user@srv-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
ssh user@cli-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
# NOT WORKING CODE -->>>>>>>>>>>>>>>
if [ $TEST = "1" ]; then
 echo "Speed testing..."
 echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | ssh $CLI_MACHINE curl -m 30 --connect-timeout 4 http://192.168.57.101/u -o /dev/null -w @- > /tmp/${PREFIX}speed_eth1
 echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | ssh $CLI_MACHINE curl -m 30 --connect-timeout 4 http://192.168.58.101/u -o /dev/null -w @- > /tmp/${PREFIX}speed_eth2
 echo "" >> /tmp/${PREFIX}speed_eth1
 echo "" >> /tmp/${PREFIX}speed_eth2
 SPEED_ETH1=`cat /tmp/${PREFIX}speed_eth1 | awk {'print $6'} | awk -F. {'print $1'}`
 SPEED_ETH2=`cat /tmp/${PREFIX}speed_eth2 | awk {'print $6'} | awk -F. {'print $1'}`
 SPEED_AG=`cat /tmp/${PREFIX}speed | head -1 | awk {'print $6'} | awk -F. {'print $1'}`
 if [ ${SPEED_ETH1} -gt ${SPEED_ETH2} ]; then
  AG_EFF=`python -c "print (${SPEED_AG} - ${SPEED_ETH1}) * 100 / ${SPEED_ETH2}"`
  C_GROW=`python -c "print (${SPEED_AG} *100) / ${SPEED_ETH1}"`
  fdsfsdf=`python -c "print (${SPEED_AG} * 100) / (${SPEED_ETH1} + ${SPEED_ETH2})"`
 else
  AG_EFF=`python -c "print (${SPEED_AG} - ${SPEED_ETH2}) * 100 / ${SPEED_ETH1}"`
  C_GROW=`python -c "print (${SPEED_AG} *100) / ${SPEED_ETH2}"`
  fdsfsdf=`python -c "print (${SPEED_AG} * 100) / ($SPEED_ETH2 + $SPEED_ETH1)"`
 fi
 ping -c 10 -q -a 192.168.57.101 | tail -3 >> /tmp/${PREFIX}speed_eth1
 ping -c 10 -q -a 192.168.58.101 | tail -3 >> /tmp/${PREFIX}speed_eth2
echo "efficiency factor - ${AG_EFF}% C_grow - ${C_GROW}% C_use - ${fdsfsdf}%" >> /tmp/${PREFIX}speed
fi
# <<<<<<<<<<<<<<-- END NOT WORKING CODE
echo "Transfer syslogs"
scp user@cli-32:/var/log/syslog /tmp/${PREFIX}syslog-cli
scp user@srv-32:/var/log/syslog /tmp/${PREFIX}syslog-srv
grep `grep " Session " /tmp/${PREFIX}syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1"]"'} | head -1` /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-1_cli
grep `grep " Session " /tmp/${PREFIX}syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1"]"'} | tail -1` /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-2_cli
grep `grep " Session " /tmp/${PREFIX}syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1"]"'} | head -1` /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-1_srv  
grep `grep " Session " /tmp/${PREFIX}syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1"]"'} | tail -1` /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-2_srv
grep "First select time" /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-1_cli_select_time
grep "{\"p_" /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-cli_json
grep "{\"p_" /tmp/${PREFIX}syslog-1_srv > /tmp/${PREFIX}syslog-1_srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-1_cli > /tmp/${PREFIX}syslog-1_cli_json
grep "{\"p_" /tmp/${PREFIX}syslog-2_srv > /tmp/${PREFIX}syslog-2_srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-2_cli > /tmp/${PREFIX}syslog-2_cli_json
grep speed /tmp/${PREFIX}speed >> /tmp/"$PREFIX".nojson
echo "Uploading logs..."
cp /tmp/${PREFIX}* $LOGS_FOLDER
cp $VTRUNKD_L_ROOT/speed_parse_json_fusion.py $LOGS_FOLDER
cd $LOGS_FOLDER; python ./speed_parse_json_fusion.py $COUNT
echo "Drawing graphs"
cp $VTRUNKD_L_ROOT/speed_parse_json_fusion.py $LOGS_FOLDER
cd $LOGS_FOLDER; python ./speed_parse_json_fusion.py $COUNT
#ssh -p $DBOXHOST_PORT $DBOXHOST "cd ~/Dropbox/alarm_logs/; python ./parse_json_fusion.py $COUNT"
echo "Compressing logs in background"
sh $VTRUNKD_L_ROOT/files_thread_compress.sh -d $LOGS_FOLDER &
echo "Clear syslog"
rm /tmp/${PREFIX}*
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "Complete!!!"
