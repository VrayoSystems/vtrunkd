# py

import sys, time
prev = 0
for l in file(sys.argv[1]):
	dl = l.split(" ");
	sdtime = dl[2];
	dt = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f');
	ms = int(sdtime.split(".")[1])
	t = int(time.mktime(dt))*1000+ms
	if prev == 0: prev = t
	print (sdtime + " {0}").format(prev - t)
	prev = t
	
