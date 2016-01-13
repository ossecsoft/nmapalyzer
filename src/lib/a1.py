import socket
import dpkt
import sys
def run(fname):
	pcapReader = dpkt.pcap.Reader(file(fname, "rb"))
	for ts, data in pcapReader:
		ether = dpkt.ethernet.Ethernet(data)
		try:
			if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
			ip = ether.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			print "src:%-16s >>>>>>   dst:%-20s" % (src, dst)
		except:
			pass
	
