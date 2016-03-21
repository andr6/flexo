#!/usr/bin/python
# Some modifications to a script originally written by Mark Baggett at SANS
#
# Flexo will notify you if it sees a DNS request for a domain not in the top million popular domains
# or if it sees an excessively long hostname.
# It will also alert you if it sees a DNS response with a low TTL (indicative of fast flux dns)
# We also have the capability to add domains to a watch list and alert on them if a request is made for that domain

print """
                      .-.
                     (   )
                      '-'
                      J L
                      | |
                     J   L
                     |   |
                    J     L
                  .-'.___.'-.
                 /___________\\
            _.-""'           `bmw._
          .'                       `.
        J                            `.
       F                               L
      J                                 J
     J                                  `
     |                                   L
     |                                   |
     |                                   |
     |                                   J
     |                                    L
     |                                    |
     |             ,.___          ___....--._
     |           ,'     `""""""""'           `-._
     |          J           _____________________`-.
     |         F         .-'   `-88888-'    `Y8888b.`.
     |         |       .'         `P'         `88888b \\
     |         |      J       #     L      #    q8888b L
     |         |      |             |           )8888D )
     |         J      \\             J           d8888P P
     |          L      `.         .b.         ,88888P /
     |           `.      `-.___,o88888o.___,o88888P'.'
     |             `-.__________________________..-'
     |                                    |
     |         .-----.........____________J
     |       .' |       |      |       |
     |      J---|-----..|...___|_______|
     |      |   |       |      |       |      That's some face you got. I think they got a cream for that.
     |      Y---|-----..|...___|_______|      Find malware with me, Flexo!
     |       `. |       |      |       |
     |         `'-------:....__|______.J
     |                           \\  /   |
     |                            \\/    |
      L___                              |
          '''----...______________....--'

"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import pickle
from scapy.all import *
from Queue import Queue
from threading import Thread
from collections import Counter

#Variable assignment
max_threads = 100
MINTTL=60
MINACOUNT=8
dnsid=[]
packetqueue = Queue()

def queue_packet(packet):
    packetqueue.put(packet)

def analyze_packet(q):
	while True:
        	packet = q.get()
		if packet.haslayer("DNS"):
			#First check the whitelist
			domain = string.lower(packet[DNSQR].qname)
			if domain.endswith("."):
				domain = domain[:-1]
			if domain.count(".")>=1:
				domain = ".".join( domain.split(".")[-2:])
			if not domain in whitelist:
				if (packet.getlayer("DNS").qr == 0):
					#Packet is a query
					dnsid.append(str(hex(packet.getlayer("DNS").id)))
					lendom = len(domain)
        	                	if domain in watch_domains:
        	                	        print "[*] ALERT: Requested domain is in watchlist %s \n" % (domain)
        	                	if not domain in alexa_top_million and not domain.endswith("localdomain"):
        	                	        #print "[*] ALERT: Domain Not in the top 1 million: %s \n" % (domain)
                	        	        file_handle=open("not_in_alexa.save","a")
                	        	        file_handle.write(domain+","+packet[DNSQR].qname+"\r\n")
                	        	        file_handle.flush()
                	        	        file_handle.close()
                	        	if lendom > 60:
                	        	        print "[*] ALERT: Hostname > 60 characters: %s \n" % (packet[DNSQR].qname)
                	        	if not domain_freq[domain]:
                	        	        #print "[*] ALERT: New Domain detected %s.   Full hostname is %s" % ( domain, packet[DNSQR].qname )
                	        	        domain_freq.update([ domain ])
                	        	        file_handle = open( "domains.save", "w" )
                	        	        pickle.dump(domain_freq, file_handle )
                	        	        file_handle.flush()
                	        	        file_handle.close()
				elif (packet.getlayer("DNS").qr == 1):
					#Packet is a response
					if str(hex(packet.getlayer("DNS").id)) in dnsid:
                	                	#print "ID %s found in valid ID table" % (hex(packet.getlayer("DNS").id))
                	                	dnsid.remove(str(hex(packet.getlayer("DNS").id)))
                	        	else:
                	                        if (packet.getlayer("DNS").rcode == 0):
                	                                print "ID %s unsolicited response for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSRR).rrname)
                	                        elif (packet.getlayer("DNS").rcode == 1):
                	                                print "ID %s returned unsolicited format-error for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSQR).qname)
                	                        elif  (packet.getlayer("DNS").rcode == 2):
                	                                print "ID %s returned unsolicited server-error for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSQR).qname)
                	                        elif (packet.getlayer("DNS").rcode == 3):
                	                                print "ID %s returned unsolicited name-error for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSQR).qname)
                	                        elif (packet.getlayer("DNS").rcode == 4):
                	                                print "ID %s returned unsolicited not-implemented-error for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSQR).qname)
                	                        elif (packet.getlayer("DNS").rcode == 5):
                	                                print "ID %s returned unsolicited refused-error for host %s" %(hex(packet.getlayer(DNS).id),packet.getlayer(DNSQR).qname)
					if packet.haslayer("DNSRR"):
                	        		RED="\033[91m"
                	        		END="\033[0m"
                	        		ttl=packet.getlayer(DNSRR).ttl
                	        		rrname=packet.getlayer(DNSRR).rrname
                	        		count=packet.getlayer(DNS).ancount
	
                	        		if rrname.endswith("."):
               		         		        domain=rrname[:-1]
	
	        	                	if domain.count(".") > 1:
	        	                	        domain=".".join(domain.split(".")[-2:])
	
	        	                	if count > 0:
	        	                	        #Detect single flux networks
	        	                	        if count > MINACOUNT and ttl < MINTTL and not domain in whitelist:
	        	                	                print RED+"Request for "+str(domain)+" with TTL of "+str(ttl)+" and record count of "+str(count)+END
				else:
					#Packet is weird
					print "Packet is weird"
		q.task_done()

for i in range(max_threads):
    worker = Thread(target=analyze_packet, args=(packetqueue,))
    worker.setDaemon(True)
    worker.start()


try:
    alexa_file = open("top-1m.csv").readlines()
    alexa_top_million = [ line.strip().split(",")[1] for line in alexa_file]
except:
    print "Download the alexa top million domains from here http://s3.amazonaws.com/alexa-static/top-1m.csv.zip.  Save as top-1m.csv in the current directory."
    alexa_top_million=[]

try:
	watch_file=open("watch.domains","r").readlines()
	watch_domains= [line.strip() for line in watch_file]
except:
	print "No watchlist found"
	watch_domains=[]

try:
	whitelist_file=open("whitelist.domains","r").readlines()
	whitelist=[line.strip() for line in whitelist_file]
except:
	print "No whitelist found"
	whitelist=[]

try:
    domain_freq = pickle.load(open("domains.save","r"))
except:
    domain_freq = Counter()

print "I am running..."
sniff(iface="eth5", filter="udp port 53", store=0, prn=queue_packet)
