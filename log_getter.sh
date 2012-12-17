#!/bin/bash
TEST="0"
PREFIX="prefix_"
while getopts :tp: OPTION
do
 case $OPTION in
 t) echo "Full speed test"
  TEST="1"
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
echo "Starting..."
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "NTP sync..."
ssh user@cli-32 "sudo ntpdate 192.168.0.101" &
sleep 1
ssh user@srv-32 "sudo ntpdate 192.168.0.101"
echo "Starting server..."
ssh user@srv-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -s -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-srv.test.conf -P 5003"
sleep 5
echo "Starting client 1..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest1 192.168.57.101 -P 5003"
echo "Starting client 2..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest2 192.168.58.101 -P 5003"
sleep 8
echo "Full started"
echo "Worcking..."
echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | curl -m 150 --connect-timeout 4 http://10.200.1.31/u -o /dev/null -w @- > /tmp/${PREFIX}speed
echo "" >>  /tmp/${PREFIX}speed
ping -c 10 -q -a 10.200.1.31 | tail -3 >> /tmp/${PREFIX}speed
echo "killall vtrunkd"
ssh user@srv-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
ssh user@cli-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
if [ $TEST = "1" ]; then
 echo "Speed testing..."
 echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | curl -m 150 --connect-timeout 4 http://192.168.57.101/u -o /dev/null -w @- > /tmp/${PREFIX}speed_eth1
 echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | curl -m 150 --connect-timeout 4 http://192.168.58.101/u -o /dev/null -w @- > /tmp/${PREFIX}speed_eth2
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
echo "Transfer syslogs"
scp user@cli-32:/var/log/syslog /tmp/${PREFIX}syslog-cli
scp user@srv-32:/var/log/syslog /tmp/${PREFIX}syslog-srv
grep `grep " Session " /tmp/${PREFIX}syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-1_cli
grep `grep " Session " /tmp/${PREFIX}syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-2_cli
grep `grep " Session " /tmp/${PREFIX}syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-1_srv  
grep `grep " Session " /tmp/${PREFIX}syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-2_srv
grep "First select time" /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-1_cli_select_time
grep "{\"p_" /tmp/${PREFIX}syslog-srv > /tmp/${PREFIX}syslog-srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-cli > /tmp/${PREFIX}syslog-cli_json
grep "{\"p_" /tmp/${PREFIX}syslog-1_srv > /tmp/${PREFIX}syslog-1_srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-1_cli > /tmp/${PREFIX}syslog-1_cli_json
grep "{\"p_" /tmp/${PREFIX}syslog-2_srv > /tmp/${PREFIX}syslog-2_srv_json
grep "{\"p_" /tmp/${PREFIX}syslog-2_cli > /tmp/${PREFIX}syslog-2_cli_json
scp /tmp/${PREFIX}* andrey@bonanza:~/sandbox/alarm_logs/
rm /tmp/${PREFIX}syslog*
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "Complete!!!"
