import csv
import json
import re
import socket

unique_ips = dict()
unique_routes = dict()

with open('5k.csv') as csvfile:
	reader = csv.DictReader(csvfile)
	for row in reader:
		src = row["Source"]
		if ( src not in unique_ips ):
			unique_ips[src]=1
		dst = row["Destination"]
		if ( dst not in unique_ips ):
			unique_ips[dst]=1
		route =  (src,dst)
		if ( route not in unique_routes ):
			unique_routes[route]=1
		else:
			unique_routes[route]+=1
		

links_list = []

for route in unique_routes:
	record = { "source":route[0] , "target":route[1], "value":unique_routes[route] }
	links_list.append(record)
			
nodes_list = []

group =0

for ip in unique_ips:
	values = ip.split(".")
	group = 0
	if ( values[0] == "192" ):
		group = 1
	name = "unknown"
	try:
		name=socket.gethostbyaddr(ip)
	except:
		name="unknown"
	nodes_list.append({ "id":ip , "group": group , "name": name })



json_prep = {"nodes":nodes_list, "links":links_list}

json_out= open("network.json","w")
json_out.write(json.dumps(json_prep,indent=4))
json_out.close()
