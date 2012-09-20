#!/bin/bash
echo "Starting..."
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "NTP sync..."
ssh user@cli-32 "sudo ntpdate 2.ru.pool.ntp.org"
ssh user@srv-32 "sudo ntpdate 2.ru.pool.ntp.org"
echo "Starting server..."
ssh user@srv-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -s -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-srv.test.conf -P 5003"
sleep 5
echo "Starting client 1..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest1 192.168.57.101 -P 5003"
sleep 5
echo "Starting client 2..."
ssh user@cli-32 "sudo /home/user/sandbox/vtrunkd_test1/vtrunkd -f /home/user/sandbox/vtrunkd_test1/test/vtrunkd-cli.test.conf atest2 192.168.58.101 -P 5003"
sleep 3
echo "Full started"
echo "Worcking..."
ssh user@cli-32 "curl -m 100 http://10.200.1.31/u -o /dev/null"
echo "killall vtrunkd"
ssh user@srv-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
ssh user@cli-32 "sudo killall -9 vtrunkd && sudo ipcrm -M 567888"
echo "Transfer syslogs"
scp user@cli-32:/var/log/syslog /tmp/syslog-cli$1
scp user@srv-32:/var/log/syslog /tmp/syslog-srv$1
grep `grep " Session " /tmp/syslog-cli* | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/syslog-cli* > /tmp/syslog-1_cli$1
grep `grep " Session " /tmp/syslog-cli* | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/syslog-cli* > /tmp/syslog-2_cli$1
grep `grep " Session " /tmp/syslog-srv* | awk -F[ {'print $2'} | awk -F] {'print $1'} | head -1` /tmp/syslog-srv* > /tmp/syslog-1_srv$1  
grep `grep " Session " /tmp/syslog-srv* | awk -F[ {'print $2'} | awk -F] {'print $1'} | tail -1` /tmp/syslog-srv* > /tmp/syslog-2_srv$1
grep "First select time" /tmp/syslog-1_cli$1 > /tmp/syslog-1_cli$1_select_time
grep "First select time" /tmp/syslog-2_cli$1 > /tmp/syslog-2_cli$1_select_time
grep 'write_buf_add called!' /tmp/syslog-1_cli$1 > /tmp/syslog-1_cli$1_write_buf
grep 'write_buf_add called!' /tmp/syslog-2_cli$1 > /tmp/syslog-2_cli$1_write_buf
grep 'select_devread_send' /tmp/syslog-1_srv$1 > /tmp/syslog-1_srv$1_select_devread_send
grep 'select_devread_send' /tmp/syslog-2_srv$1 > /tmp/syslog-2_srv$1_select_devread_send
scp /tmp/syslog* andrey@bonanza:~/Dropbox/alarm_logs/
rm /tmp/syslog*
echo "Clear syslog"
ssh user@cli-32 "cat /dev/null | sudo tee /var/log/syslog"
ssh user@srv-32 "cat /dev/null | sudo tee /var/log/syslog"
echo "Complete!!!"
