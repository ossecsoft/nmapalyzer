#Tested on Ubuntu 14.04 LTS
#http://stackoverflow.com/questions/18256342/parsing-a-pcap-file-in-python
import dpkt
counter=0
ipcounter=0
tcpcounter=0
udpcounter=0
filename='1.pcap'
for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue
    ip=eth.data
    ipcounter+=1
    if ip.p==dpkt.ip.IP_PROTO_TCP: 
       tcpcounter+=1
    if ip.p==dpkt.ip.IP_PROTO_UDP:
       udpcounter+=1
print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter
'''
output:
Total number of packets in the pcap file:  2403
Total number of ip packets:  2399
Total number of tcp packets:  2359
Total number of udp packets:  20
'''