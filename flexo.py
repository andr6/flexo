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

packetqueue = Queue()

def queue_packet(packet):
    packetqueue.put(packet)

def analyze_packet(q,i):
    while True:
        packet = q.get()
        #print packet.sprintf("Thread "+str(i)+" %IP.src% %IP.dst%\r\n")
 	if packet.haslayer("DNSQR"):
		domain = string.lower(packet[DNSQR].qname)
		#print domain
		lendom = len(domain)
		if domain.endswith("."):
			domain = domain[:-1]
		if domain.count(".")>=1:
			domain = ".".join( domain.split(".")[-2:])
		#print domain
		if domain in watch_domains:
			print "[*] ALERT: Requested domain is in watchlist %s \n" % (domain)
		if not domain in alexa_top_million and not domain.endswith("localdomain"):
			#print "[*] ALERT: Domain Not in the top 1 million: %s \n" % (domain)
			file_handle=open("not_in_alexa.save","a")
			file_handle.write(domain+","+packet[DNSQR].qname+"\r\n")
			file_handle.flush()
			file_handle.close()
		#if lendom > 60:
			#print "[*] ALERT: Long Domain name > 60 characters: %s \n" % (domain)
		if not domain_freq[domain]:
			#print "[*] ALERT: New Domain detected %s.   Full hostname is %s" % ( domain, packet[DNSQR].qname )
			domain_freq.update([ domain ])
			file_handle = open( "domains.save", "w" )
			pickle.dump(domain_freq, file_handle )
			file_handle.flush()
			file_handle.close()

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
                        #else:
                        #       print "Request for "+str(domain)+" with TTL of "+str(ttl)+" and record count of "+str(count)
                        #Try to detect double flux network
	#print "Queue size: "+str(q.qsize())+"\r\n"
        q.task_done()

for i in range(max_threads):
    worker = Thread(target=analyze_packet, args=(packetqueue,i))
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
sniff(iface="eth4", filter="udp port 53", store=0, prn=queue_packet)
