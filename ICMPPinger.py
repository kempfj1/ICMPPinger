from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

#Make a table of ICMP error codes for easy lookup
errormessage = dict({0: "Destination Network Unreachable", 1: "Destination Host Unreachable",
                     2: "Destination Protocol Unreachable", 3: "Destination Port Unreachable",
                     4: "Fragmentation Required",
                     5: "Source Route Failed", 6: "Destination Network Unknown", 7: "Destination Host Unknown",
                     8: "Source Host Isolated", 9: "Network Administratively Prohibited",
                     10: "Host Administratively Prohibited",
                     11: "Network Unreachable for ToS", 12: "Host Unreachable for ToS",
                     13: "Communication Administratively Prohibited",
                     14: "Host Precedence Violation", 15: "Precedence Cutoff in Effect"})

#Generate a checksum
def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count + 1]) * 256 + ord(str[count])
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

#Builds a packet without sending it
def build_packet():
    newCsum = 0
    newID = os.getpid() & 0xFFFF

    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, newCsum, newID, 1)
    data = struct.pack('d', time.time())

    newCsum = checksum(header + data)

    if sys.platform == 'darwin': #darwin refers to Mac OS X
        newCsum = htons(newCsum) & 0xffff
    else:
        newCsum = htons(newCsum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, newCsum, newID, 1)

    packet = header + data
    return packet

#This one... uh... receives a ping.
def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return -1

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packID, sequence = struct.unpack("bbHHh", icmpHeader)

        # If the destination was unreachable, print the appropriate error message
        if type == 3:
            print errormessage[code]

        # Fetch the ICMP header from the IP packet
        if packID == ID:
            doubleBytes = struct.calcsize("d")
            sentTime = struct.unpack("d", recPacket[28:28 + doubleBytes])[0]
            return timeReceived - sentTime

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return -1

#Builds and sends a packet
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
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

#Makes a socket then sends and receives packets
def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details see:
    # http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF  # Return the current process id
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay

#Traces a route to the target host
def get_route(hostname):
    icmp = getprotobyname("icmp")
    timeLeft = TIMEOUT
    for ttl in xrange(1, MAX_HOPS):
        for tries in xrange(TRIES):
            destAddr = gethostbyname(hostname)

            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (destAddr, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print " * * * Request timed out."
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print " * * * Request timed out."
            except timeout:
                continue
            else:
                #Grab the header and find out what type the packet it
                icmpHeader = recvPacket[20:28]
                type = struct.unpack("b", icmpHeader[:1])[0]

                if type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0])
                elif type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0])
                elif type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0])
                    return
                else:
                    print "error"
                break
            finally:
                mySocket.close()

#Repeatedly pings a host and prints some time stats
def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server, ping or pong is lost

    # setting up thingies
    rate = 0  # timeout rate
    delay = 0  # cumulative delay
    count = 0  # used for geting avg RTT
    totalcount = 0  # used for counting timeouts
    timeouts = 0
    min = 0  # minimum RTT
    max = 0  # maximum RTT

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
            print "Request Timed out."  #Specific error codes are handled in the receiveOnePing function
            timeouts += 1
            totalcount = count + 1  #we need this so we can get an accurate Avg RTT and an accurate timeout rate
        else:
            count += 1
            delay += tempDelay

            # update min and max
            if tempDelay < min:
                min = tempDelay
            if tempDelay > max:
                max = tempDelay

        #print some stats
        if totalcount > 0:  #don't divide by 0 pls
            rate = float(timeouts / totalcount) * 100  #figure out the timeout rate in %

        print"Min RTT: " + str(min)
        print"Max RTT: " + str(max)
        print"Average RTT: " + str(delay / count)
        print"Timeout rate: " + str(rate) + "%"
        print""

        time.sleep(1)  #nap time
    return delay

#Takes some user input and starts the program
def main():
    while 1:
        choice = raw_input("Ping(1), Traceroute(2)\n")
        host = raw_input("Host name: ")

        if choice == '1':
            print "Pinging " + host
            ping(host)
            continue
        elif choice == '2':
            print "Route to: " + host
            get_route(host)
            continue
        elif choice != '1' & choice != '2':
            print "Come on, man. Gimme a number"
            continue



main()
#ping("www.xavier.edu")
#get_route("www.google.com")
