#/usr/bin/env python
import sys
import getopt
from time import sleep
import os
import subprocess
import threading

class SubProcessStarter(threading.Thread):
	def __init__(self):
		self.stdout = None
		self.stderr = None
		threading.Thread.__init__(self)
	def run(self):
		p = subprocess.Popen('rsync -av /etc/passwd /tmp'.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.stdout, self.stderr = p.communicate()

atest = "/var/run/vtrunkd/atest" + sys.argv[1]
while os.path.isfile(atest) == False:
	sleep(0.1)
f = open(atest,"r")
pid = f.readline()
p = subprocess.call("sudo ddd --command=./gdb_init ./vtrunkd " + pid, shell=True)
exit(0)
