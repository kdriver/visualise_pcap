import pcapy
import time
import socket
from struct import *
import sys


def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def parse_packet(packet) :
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
	#  print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
 
    if ord(packet[0]) & 0x01 :
        #this is a multicast packet
        return 0

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
         
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        answer =  s_addr + " -> " + d_addr  
        return answer


def convert_timefromepoch(epochTimestamp): 
      return time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(epochTimestamp))


r = pcapy.open_offline("5k.pcapng")

pkt = 1
tup = r.next()
while  tup :
	(header,payload ) = tup
	answer = parse_packet(payload)
        if answer is None :
            exit()

	ts = header.getts()[0]
        timeStamp = convert_timefromepoch(ts)

        if answer is not 0  :
            print( str(timeStamp) + " " + str(pkt) + " : " + answer  )
	else :
            print("mulicast")
	pkt = pkt + 1
	tup = r.next()



