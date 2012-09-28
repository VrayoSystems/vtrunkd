import sys, time, glob, os
def printTiming(fileName, stopLine):
        outFile = file("timing" + fileName)
        prev = 0
        for l in file(fileName):
                print l
                dl = l.split(" ");
                sdtime = dl[2];
                if sdtime.find(stopLine) != -1:
                        break
                dt = time.strptime(sdtime.split(".")[0], '%H:%M:%S');
                ms = int(sdtime.split(".")[1])
                t = int(time.mktime(dt))*1000+ms
                if prev == 0: prev = t
                print (sdtime + " {0}").format(prev - t)
                prev = t
        outFile.close()

def findTime(fileName):
        timeMs = 0
        timeLine = ''
        for line in file(fileName):
                if -1 != line.find("Requesting bad frame"):
                        splittedLine = line.split(" ");
                        sdtime = splittedLine[2];
                        splittedLine = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f');
                        ms = int(sdtime.split(".")[1])
                        timeMs = int(time.mktime(splittedLine))*1000+ms
                        timeLine = sdtime
                        print (timeLine + " "+timeMs)
                        break
        return timeMs, timeLine

prefix = ''
if len(sys.argv)>1:
        prefix = sys.argv[1]
folderStuff = glob.glob(prefix + '*')
timeMs = 99999999999999999999999
timeLine = ''
for logFile in folderStuff:
        timeMsNew, timeLineNew = findTime(logFile)
        if timeMsNew < timeMs:
                timeMs = timeMsNew
                timeLine = timeLineNew
if timeLine != '':
        for logFile in folderStuff:
                printTiming(logFile, timeLine[:-2])

