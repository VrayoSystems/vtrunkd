import sys, time, glob, os, numpy, datetime
import matplotlib.pyplot as plt

def printTiming(fileName, stopTime, parceDayFactor):
        outFile = open("parced_timing_" + fileName, 'w')
        prev = 0
        timings = []
        for l in file(fileName):
                dl = l.split(" ");
                sdtime = dl[2+parceDayFactor];
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
        plt.savefig("parced_bar_chart_" + fileName)
        outFile.close()

def findTime(fileName, parceDayFactor):
        timeMs = 99999999999999999999999
        timeLine = ''
        for line in file(fileName):
                if -1 != line.find("Requesting bad frame"):
                        splittedLine = line.split(" ");
                        sdtime = splittedLine[2+parceDayFactor];
                        splittedLine = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f')
                        ms = int(sdtime.split(".")[1])
                        timeMs = int(time.mktime(splittedLine))*1000+ms
                        timeLine = sdtime
                        break
        return timeMs, timeLine
def queueGrowingStat(fileName, stopTime, parceDayFactor):
        outFile = open("parced_queue_" + fileName, 'w')
        outFile.write("recv-q\tsend-q\n")
        prev = 0
        recvQlist = []
        sendQlist = []
        for line in file(fileName):
                dl = line.split(" ");
                if -1 != line.find("Recv"):
                        print line
                        recvQ = dl[6+parceDayFactor]
                        sendQ = dl[8+parceDayFactor]
                        outFile.write(recvQ + '\t' + sendQ + '\n')
                        recvQlist.append(recvQ)
                        sendQlist.append(sendQ)
                        print  recvQ + ' ' +sendQ
                sdtime = dl[2+parceDayFactor];
                dt = time.strptime("14/09/12 %s000" % sdtime, '%d/%m/%y %H:%M:%S.%f')
                ms = int(sdtime.split(".")[1])
                t = int(time.mktime(dt))*1000+ms
                if (t > stopTime):
                        break

        plt.subplot(211)
        plt.title('Send-Q')
        plt.plot(numpy.arange(len(sendQlist)), sendQlist)
#        plt.savefig("parced_Recv-Q_" + fileName)
        plt.subplot(212)
        plt.title('Recv-Q')
        plt.plot(numpy.arange(len(recvQlist)), recvQlist)
        plt.savefig("parced_queue_" + fileName)
        outFile.close()
                        
parceDayFactor = 0
if datetime.datetime.now().day < 10:
        parceDayFactor = 1
prefix = ''
if len(sys.argv)>1:
        prefix = sys.argv[1]
folderStuff = glob.glob(prefix + "*")
timeMs = 99999999999999999999999
timeLine = ''
for logFile in folderStuff:
        timeMsNew, timeLineNew = findTime(logFile, parceDayFactor)
        if timeMsNew < timeMs:
                timeMs = timeMsNew
                timeLine = timeLineNew
print ("jam time - " + timeLine + " " + str(timeMs))
if timeLine != '':
        for logFile in folderStuff:
                printTiming(logFile, timeMs, parceDayFactor)
                queueGrowingStat(logFile, timeMs, parceDayFactor)
