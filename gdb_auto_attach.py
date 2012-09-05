#/usr/bin/env python
import sys
import getopt
from time import sleep
import os
import subprocess

atest = "/var/run/vtrunkd/atest" + sys.argv[1]
while os.path.isfile(atest) == False:
	sleep(0.1)
f = open(atest,"r")
pid = f.readline()
p = subprocess.call("sudo gdb -x ./gdb_init ./vtrunkd " + pid, shell=True)
exit(0)
