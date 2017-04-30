from __future__ import print_function
import csv
import json
import re
import socket
import pcapy
import time
from struct import *
import sys

unique_ips = dict()
unique_routes = dict()

unique_ips_count =0
unique_routes_count =0
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
        answer = ( s_addr , d_addr ) 
        return answer
    else:
	print("\n th protocol is " + format(eth_protocol,'04x' ))
        return 0


print('opening pcap file ')
r = pcapy.open_offline("Friday2.pcapng")
pkt = 1
tup = r.next()
while  tup :
        (header,payload ) = tup
        answer = parse_packet(payload)
        if answer is None :
           print("\nPackets " + str(pkt) + " IPs " + str(unique_ips_count) + " Routes " + str(unique_routes_count ))
           break
        if answer is not 0:
            (src,dst) = answer 
        if ( src not in unique_ips ):
            unique_ips[src]=1
            unique_ips_count += 1
        if ( dst not in unique_ips ):
            unique_ips[dst]=1
            unique_ips_count += 1
        route =  (src,dst)
        if ( route not in unique_routes ):
        	unique_routes[route]=1
                unique_routes_count += 1
        else:
        	unique_routes[route]+=1
        pkt = pkt + 1
	if ( (pkt % 100) is 0 ) :
           print("Packets " + str(pkt) + " IPs " + str(unique_ips_count) + " Routes " + str(unique_routes_count ),end='\r')
        tup = r.next()
	


print("building network graph  ")

links_list = []

for route in unique_routes:
	record = { "source":route[0] , "target":route[1], "value":unique_routes[route] }
	links_list.append(record)
			
nodes_list = []

group =0
shape = "circle"

for ip in unique_ips:
	values = ip.split(".")
	group = 0
	shape = "circle"
	if ( values[0] == "192" and  values[1] == "168"  ):
		group = 1
		shape = "triangle" 
	name = "unknown"
	try:
		name=socket.gethostbyaddr(ip)
	except:
		name="unknown"
	nodes_list.append({ "id":ip , "group": group , "name": name , "shape": shape })

print("writing JSON ")


json_prep = {"nodes":nodes_list, "links":links_list}

json_out= open("network.json","w")
json_out.write(json.dumps(json_prep,indent=4))
json_out.close()
