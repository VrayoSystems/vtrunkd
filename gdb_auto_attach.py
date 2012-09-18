#/usr/bin/env python
import sys
import getopt
from time import sleep
import os
import subprocess

atest = "/var/run/vtrunkd/atest" + sys.argv[1]
debugger = "sudo gdb -x ./gdb_init ./vtrunkd "
if sys.argv[2] == 'ddd':
	debugger = "sudo ddd --command=./gdb_init ./vtrunkd "
#gdb_init_file = open("./gdb_init_temp", "w")
#gdb_init_file.writeline("b linkfd.c:443")
#gdb_init_file.writeline("c")
while os.path.isfile(atest) == False:
	sleep(0.1)
f = open(atest,"r")
pid = f.readline()
p = subprocess.call(debugger + pid, shell=True)
exit(0)
