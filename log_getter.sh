#!/bin/bash
echo "Starting..."
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "NTP sync..."
ssh user@cli-32 "sudo ntpdate 192.168.0.101"
ssh user@srv-32 "sudo ntpdate 192.168.0.101"
echo "Starting server..."
ssh user@srv-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -s -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-srv.test.conf -P 5003"
sleep 5
echo "Starting client 1..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest1 192.168.57.101 -P 5003"
echo "Starting client 2..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest2 192.168.58.101 -P 5003"
sleep 1
echo "Full started"
echo "Worcking..."
echo "time_starttransfer %{time_starttransfer} time_total %{time_total} speed_download %{speed_download}" | curl -m 150 --connect-timeout 4 http://10.200.1.31/u -o /dev/null -w @- > /tmp/$1speed
echo "" >>  /tmp/$1speed
echo "killall vtrunkd"
ssh user@srv-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
ssh user@cli-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
echo "Transfer syslogs"
scp user@cli-32:/var/log/syslog /tmp/$1syslog-cli
scp user@srv-32:/var/log/syslog /tmp/$1syslog-srv
grep `grep " Session " /tmp/$1syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/$1syslog-cli > /tmp/$1syslog-1_cli
grep `grep " Session " /tmp/$1syslog-cli | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/$1syslog-cli > /tmp/$1syslog-2_cli
grep `grep " Session " /tmp/$1syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/$1syslog-srv > /tmp/$1syslog-1_srv  
grep `grep " Session " /tmp/$1syslog-srv | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/$1syslog-srv > /tmp/$1syslog-2_srv
grep "First select time" /tmp/$1syslog-1_cli > /tmp/$1syslog-1_cli_select_time
grep "First select time" /tmp/$1syslog-2_cli > /tmp/$1syslog-2_cli_select_time
grep 'write_buf_add called!' /tmp/$1syslog-1_cli > /tmp/$1syslog-1_cli_write_buf
grep 'write_buf_add called!' /tmp/$1syslog-2_cli > /tmp/$1syslog-2_cli_write_buf
grep 'select_devread_send() frame' /tmp/$1syslog-1_srv > /tmp/$1syslog-1_srv_select_devread_send
grep 'select_devread_send() frame' /tmp/$1syslog-2_srv > /tmp/$1syslog-2_srv_select_devread_send
grep 'max_of_max_send_q' /tmp/$1syslog-1_srv > /tmp/$1syslog-1_srv_max_of_max_send_q
grep 'max_of_max_send_q' /tmp/$1syslog-2_srv > /tmp/$1syslog-2_srv_max_of_max_send_q
scp /tmp/$1* andrey@bonanza:~/sandbox/alarm_logs/
rm /tmp/$1syslog*
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "Complete!!!"
