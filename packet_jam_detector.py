import sys, time, glob, os, numpy
import matplotlib.pyplot as plt
def printTiming(fileName, stopTime):
        outFile = open("timing_" + fileName, 'w')
        prev = 0
        timings = []
        for l in file(fileName):
                dl = l.split(" ");
                sdtime = dl[3];
                dt = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f')
                ms = int(sdtime.split(".")[1])
                t = int(time.mktime(dt))*1000+ms
                if (t > stopTime):
                        break
                if prev == 0:
                        prev = t
                timings.append(t - prev)
                outFile.write((sdtime + " {0}").format(prev - t) + '\n')
                prev = t
        print fileName
        print len(timings)
        plt.bar(numpy.arange(len(timings)), timings)
        plt.savefig("bar_chart_" + fileName)
        outFile.close()

def findTime(fileName):
        timeMs = 99999999999999999999999
        timeLine = ''
        for line in file(fileName):
                if -1 != line.find("Requesting bad frame"):
                        splittedLine = line.split(" ");
                        sdtime = splittedLine[3];
                        splittedLine = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f')
                        ms = int(sdtime.split(".")[1])
                        timeMs = int(time.mktime(splittedLine))*1000+ms
                        timeLine = sdtime
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
print ("jam time - " + timeLine + " " + str(timeMs))
if timeLine != '':
        for logFile in folderStuff:
                printTiming(logFile, timeMs)

