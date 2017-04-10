from socket import *
import os
import sys
import struct
import time
import select
import binascii


ICMP_ECHO_REQUEST = 8

def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count+1]) * 256 + ord(str[count])
        csum = csum + thisVal
        csum = csum & 0xffffffffL
        count = count + 2

    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return -1

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        icmpHeader= recPacket[20:28]
        type, code, checksum, packID, sequence = struct.unpack("bbHHh", icmpHeader)

        #Fetch the ICMP header from the IP packet
        if packID == ID:
            doubleBytes= struct.calcsize("d")
            sentTime = struct.unpack("d", recPacket[28:28 + doubleBytes])[0]
            return timeReceived - sentTime

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return -1


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects
    #which can be referenced by their position number within the object


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
#SOCK_RAW is a powerful socket type. For more details see:
#http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF  #Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    #timeout=1 means: If one second goes by without a reply from the server, ping or pong is lost

    #setting up thingies
    rate = 0
    delay = 0
    count = 0      #used for geting avg RTT
    totalcount = 0 #used for counting timeouts
    timeouts = 0
    min = 0
    max = 0

    dest = gethostbyname(host)
    print "Pinging " + host + "(" + dest + ")" + " using Python:"
    print ""

    #Send ping requests to a server separated by approximately one second
    while 1:
        tempDelay = doOnePing(dest, timeout)

        #get an accurate initial value for min
        if count == 0:
            min = tempDelay

        #check if we time out
        if tempDelay == -1:
            print "Request Timed out."
            timeouts += 1
            totalcount = count + 1 #we need this so we can get an accurate Avg RTT and an accurate timeout rate
        else:
            count += 1
            delay += tempDelay

            #update min and max
            if tempDelay < min:
                min = tempDelay
            if tempDelay > max:
                max = tempDelay

        #print some stats
        if totalcount > 0: #dont divide by 0 pls
            rate = float(timeouts/totalcount)

        print"Min RTT: " + str(min)
        print"Max RTT: " + str(max)
        print"Average RTT: " + str(delay / count)
        print"Timeout rate: " + str(rate)
        print""

        time.sleep(1)#nap time
    return delay

ping("www.xavier.edu")
