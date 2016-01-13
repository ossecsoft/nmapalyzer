#!/usr/bin/env python


import socket
import dpkt
import time
import re
def run(fname):
	f = open(fname,'r')
	pcap = dpkt.pcap.Reader(f)

	pktCounter = 0


	for ts,buff in pcap:
		pktCounter += 1

		try:
			ether = dpkt.ethernet.Ethernet(buff)

			# Mac address
			src_mac = (ether.dst).encode("hex")
			dst_mac = (ether.src).encode("hex")
			smac = ':'.join([src_mac[i:i+2] for i in range(0, len(src_mac), 2)])
			dmac = ':'.join([dst_mac[i:i+2] for i in range(0, len(dst_mac), 2)])

			# Packet
			ip = ether.data
			tcp = ip.data
			src = socket.inet_ntoa(ip.src)
			srcport = tcp.sport
			dst = socket.inet_ntoa(ip.dst)
			dstport = tcp.dport

			# Definition of Time
			showTime = time.gmtime(ts)
			timeF = time.strftime("%Y/%m/%d %H:%M:%S", showTime)

			# Packet Size
			sizeP = len(buff)


			# Data filtering
			p = re.compile("<Line>(.*?)\</Line>", re.IGNORECASE|re.DOTALL)



			# Packet print
			print "PktNr: %s" %(pktCounter)
			print "PktSize: %s" %(sizeP)
			print "Time: %s" %(timeF)
			print "src: (MAC: %s) \033[1;32m(IP:%s)\033[1;m (port:%s) --> dest: (MAC: %s) \033[1;31m(IP:%s)\033[1;m (port:%s)" % (smac,src,srcport,dmac,dst,dstport) + "\n"
			print ip



		except AttributeError:
			pass
