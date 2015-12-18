#!/usr/bin/env python
#http://dpkt.readthedocs.org/en/latest/_modules/examples/print_packets.html
#Tested on Ubuntu 14.04 LTS
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
import datetime
import socket
def mac_addr(mac_string):
    """Print out MAC address given a string

    Args:
        mac_string: the string representation of a MAC address
    Returns:
        printable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in mac_string)
def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address: the string representation of a MAC address
    Returns:
        printable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)
def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Print out the timestamp in UTC
        print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue
        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        # Print out the info
        print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
def test():
    """Open up a test pcap file and print out the packets"""
    with open('data/http.pcap') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)
if __name__ == '__main__':
    test()
'''
output:
Timestamp:  2015-12-07 14:20:06.525121
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.525166
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.547683
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1565 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.656779
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=461 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.713151
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2054
Non IP Packet type not supported ARP

Timestamp:  2015-12-07 14:20:06.713167
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2054
Non IP Packet type not supported ARP

Timestamp:  2015-12-07 14:20:06.739896
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.765983
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:06.853935
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.025697
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.125074
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.125481
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=141 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.140414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=173 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.305534
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.305788
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.311983
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=173 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.319827
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.424983
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.444708
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.444732
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.452386
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=157 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.452974
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=70 ttl=128 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.453068
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=73 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.453159
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=73 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.456639
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=130 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.456696
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=207 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.456739
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=207 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.467999
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.545146
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.594445
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.645188
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.645217
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.754453
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.755071
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.764418
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=781 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.940231
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.940380
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.940616
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.951571
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=141 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.989761
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:07.989961
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.120085
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.189649
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.189673
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.189904
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.294200
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.294268
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.314754
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=109 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.466543
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=72 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.478924
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=163 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.484464
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.528757
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.534917
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=93 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.534964
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.534972
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.541676
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=317 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.560408
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=3949 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.844351
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.844399
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.864374
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:08.871965
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.195572
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.324403
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1549 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.329527
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.339917
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.464742
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.573935
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=189 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.605316
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.674732
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.677189
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=28 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.683178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.683249
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.683287
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.683319
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.692657
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=28 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.695742
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.698274
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=40 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.698346
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=40 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.784945
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.792321
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.901535
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:09.929369
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.010723
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.044289
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.084150
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.088718
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.124135
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 71.6.216.36 -> 88.198.137.209   (len=40 ttl=231 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.124182
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 71.6.216.36   (len=44 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.139813
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.100.100   (len=70 ttl=128 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140287
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.100.100 -> 88.198.137.209   (len=96 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140794
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140816
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140836
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140856
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140875
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140894
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140913
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140933
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.140952
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.153381
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.153442
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.154085
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.154150
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.154181
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166803
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166833
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166855
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166875
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166894
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166913
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166951
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166970
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.166990
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.195848
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.196051
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.289981
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 71.6.216.36 -> 88.198.137.209   (len=40 ttl=40 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.323079
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=6429 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.381481
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.385309
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.449720
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.450344
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=157 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.463174
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.494601
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=70 ttl=128 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.497621
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=96 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.529233
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.550700
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=157 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.556859
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=781 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.624478
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.624522
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.681549
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=157 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.729782
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.790795
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.809350
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.899953
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.915130
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:10.924960
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=8200 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.025039
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.025757
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.124662
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234618
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234670
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234689
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234712
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234713
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234737
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.234746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.258878
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.258930
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.258962
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.258989
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259014
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259039
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259063
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259088
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259112
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259136
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259160
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259184
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259208
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259234
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.259261
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.271753
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.274567
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.367986
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368044
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368072
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368097
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368122
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368146
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368172
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368198
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368222
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368246
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368269
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368293
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368316
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.368340
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381083
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=44 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381103
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381199
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=44 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381207
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381224
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=44 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.381230
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383668
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383701
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383727
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383751
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383776
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383834
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383858
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383882
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383907
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383931
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.383979
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384003
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384028
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384052
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384076
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384100
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384124
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.384148
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477222
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477275
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477304
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477330
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477355
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477379
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477404
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477428
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477452
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.477501
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.492818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493267
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493382
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493418
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493450
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493480
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493511
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493541
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493573
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493603
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493633
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493659
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493690
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493726
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493757
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493787
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493848
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.493880
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.530027
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586369
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586423
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586459
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586488
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586516
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586549
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586577
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586608
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586639
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586670
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.586701
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.601957
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.601990
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602020
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602045
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602069
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602093
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602117
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602141
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602165
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602188
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602212
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602236
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602259
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602283
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602307
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602331
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602354
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602401
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.602424
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695622
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695673
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695729
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695759
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695784
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695832
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695857
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695880
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.695904
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.708598
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711174
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711205
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711231
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711255
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711279
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711302
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711326
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711349
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711373
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711397
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711420
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711444
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711467
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711491
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711516
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711540
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711563
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711587
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711611
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.711660
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804773
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804822
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804848
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804870
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804890
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804910
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804929
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804949
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804968
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.804988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820399
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820433
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820456
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820501
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820521
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820540
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820559
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820579
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820598
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820617
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820655
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820675
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820694
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820714
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820733
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820752
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820771
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820790
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.820810
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.882780
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.890292
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914022
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914067
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914095
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914120
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914145
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914169
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914193
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914217
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914241
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.914265
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929580
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929611
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929637
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929664
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929689
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929714
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929738
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929762
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929786
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929810
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929834
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929859
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929883
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929907
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929935
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929960
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.929983
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.930008
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.930032
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.930058
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:11.930082
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024432
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024488
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024544
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024568
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024592
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024616
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024644
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024669
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.024693
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038747
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038837
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038862
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038885
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038909
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038956
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.038980
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039004
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039027
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039050
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039074
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039098
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039121
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039144
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039168
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039191
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039215
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039238
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.039262
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.101153
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132418
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132463
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132490
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132544
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132571
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132619
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132646
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.132669
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148001
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148124
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148348
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148458
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148568
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148678
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148789
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.148897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149006
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149114
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149328
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149441
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149549
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149658
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149765
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149873
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.149980
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.150097
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.150204
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.184664
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.184691
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=3393 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241583
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241663
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241687
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241715
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241738
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241762
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241785
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.241831
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257185
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257219
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257248
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257278
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257310
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257335
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257360
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257383
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257407
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257455
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257479
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257503
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257550
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257574
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257598
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257622
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257645
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257669
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.257700
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.350846
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.350987
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351017
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351044
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351069
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351094
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351119
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351143
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351167
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.351191
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366341
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366375
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366402
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366427
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366451
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366476
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366499
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366524
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366548
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366572
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366644
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366682
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366708
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366732
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366755
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366779
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366802
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366828
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.366852
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460024
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460072
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460099
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460123
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460148
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460172
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460197
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460245
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460269
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460472
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460527
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460876
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=70 ttl=128 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.460955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 213.133.98.98   (len=74 ttl=128 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.464355
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=171 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.464404
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 213.133.98.98 -> 88.198.137.209   (len=165 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475598
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475663
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475695
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475721
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475770
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475794
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475842
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475866
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475890
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475915
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475940
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475963
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.475987
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476012
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476035
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476059
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476083
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476107
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.476130
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.559784
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569406
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=5053 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569577
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569613
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569634
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569656
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569675
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569694
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569715
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569734
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569752
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.569771
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584778
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584830
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584851
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584871
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584891
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584910
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584930
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584949
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.584988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585008
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585027
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585046
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585066
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585085
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585104
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585123
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585143
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585164
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.585184
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.678521
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1101 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685765
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685811
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685840
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685864
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685888
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685912
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685935
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685958
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.685982
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.686005
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694023
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694054
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694082
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694107
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694131
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694201
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694225
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694249
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694273
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694296
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694320
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694344
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694367
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694390
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694437
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694461
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694484
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.694507
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.698798
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709627
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709654
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709677
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709701
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709724
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709748
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709771
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709795
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709842
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709865
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709889
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709914
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709937
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709961
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.709984
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710008
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710034
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710058
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710082
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710106
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710129
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710152
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710176
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710199
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710223
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710246
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710270
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710293
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710316
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710343
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710367
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710391
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710438
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710461
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710485
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710508
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710531
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710578
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710602
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710625
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.710648
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.787892
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.787944
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.787969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.787989
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.788008
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.788027
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.788045
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.788064
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.788082
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803187
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803215
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803258
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803278
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803297
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803317
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803340
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803373
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803398
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803418
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803438
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803457
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803496
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803515
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803535
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803554
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803573
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.803614
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818809
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818839
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818859
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818878
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818915
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818933
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818951
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.818987
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819005
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819023
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819041
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819059
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819077
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819099
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819118
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819136
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819171
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819189
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819207
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819225
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819261
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819279
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819297
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819315
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819335
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819368
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819396
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819415
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819433
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819451
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819470
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819488
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819506
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819524
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819542
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819560
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819578
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819614
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819632
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.819653
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.820145
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.820169
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.870025
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.870049
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.870071
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.896811
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897007
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897049
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897076
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897101
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897125
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897149
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897174
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897197
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.897221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912404
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912440
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912469
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912495
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912543
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912567
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912591
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912615
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912639
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912664
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912689
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912713
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912737
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912784
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912832
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912856
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912881
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.912905
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928002
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928032
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928058
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928083
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928106
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928130
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928201
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928224
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928248
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928272
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928295
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928319
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928343
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928367
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928390
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928437
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928461
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928484
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928509
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928532
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928579
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928603
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928626
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928649
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928673
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928696
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928720
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928744
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928767
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928790
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928814
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928838
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928861
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928884
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928909
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.928978
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.929001
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.929025
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:12.929048
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.005988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006369
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006485
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006834
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.006945
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.007054
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.007163
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023177
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023304
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023411
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023515
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023617
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023717
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023821
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.023926
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024026
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024126
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024226
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024326
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024425
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024524
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024623
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024725
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024825
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.024925
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.025025
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.025128
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.025154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037230
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037293
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037324
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037345
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037365
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037385
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037405
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037424
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037443
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037463
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037483
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037507
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037546
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037565
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037585
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037604
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037623
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037643
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037664
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037683
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037742
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037780
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037800
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037819
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037839
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037858
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037878
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037916
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037936
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037975
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.037994
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038014
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038033
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038052
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038072
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038091
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038111
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038130
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.038149
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.039611
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115454
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115497
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115517
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115535
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115554
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115573
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.115591
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130817
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130848
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130872
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130892
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130910
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130928
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130947
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130965
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.130983
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131002
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131020
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131038
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131057
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131075
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131093
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131111
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131129
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131147
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131184
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.131202
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146414
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146444
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146466
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146486
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146507
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146546
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146565
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146585
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146604
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146624
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146643
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146680
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146702
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146741
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146780
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146799
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146819
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146838
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146857
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146876
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146896
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146915
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146934
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146954
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146973
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.146993
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147012
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147031
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147050
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147070
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147089
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147108
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147127
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147147
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147185
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147204
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147223
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147262
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147281
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.147300
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.161177
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.180427
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224434
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224631
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224664
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224684
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224721
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224740
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224759
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.224777
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.239954
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.239988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240009
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240028
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240046
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240065
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240083
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240102
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240120
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240139
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240157
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240175
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240193
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240212
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240230
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240252
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240272
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240290
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240313
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240335
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.240353
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.255623
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.255745
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.255852
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.255955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256056
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256157
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256257
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256357
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256458
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256559
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256660
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256760
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256861
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.256966
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257208
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257233
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257256
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257279
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257299
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257320
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257340
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257360
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257380
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257399
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257419
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257439
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257458
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257478
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257500
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257522
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257543
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257562
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257582
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257605
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257625
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257645
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257665
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257684
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257742
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257781
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257800
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.257819
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.333715
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1261 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341005
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341048
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341071
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341092
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341112
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341132
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341152
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341171
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.341191
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349194
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349245
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349266
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349286
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349305
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349325
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349344
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349363
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349383
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349402
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349422
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349441
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349461
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349480
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349499
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349538
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349557
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349576
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.349596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.350487
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364793
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364827
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364854
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364874
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364916
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364938
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364959
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.364981
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365003
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365024
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365044
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365064
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365085
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365107
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365129
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365150
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365170
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365189
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365209
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365228
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365247
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365268
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365290
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365312
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365332
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365353
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365380
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365402
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365424
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365446
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365467
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365487
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365509
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365531
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365550
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365572
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365615
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365657
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365676
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365696
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365717
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.365736
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.442912
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2893 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443063
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443100
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443122
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443142
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443161
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443180
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443199
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443217
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.443235
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458392
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458425
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458452
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458502
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458550
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458574
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458598
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458645
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458671
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458695
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458719
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458770
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458794
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458842
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458869
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.458893
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.460880
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489772
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489839
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489871
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489893
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489914
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489935
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489955
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.489979
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490001
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490022
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490043
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490064
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490085
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490106
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490128
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490150
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490170
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490191
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490211
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490233
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490254
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490274
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490296
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490316
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490337
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490359
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490381
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490403
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490425
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490446
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490467
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490489
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490511
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490530
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490551
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490573
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490616
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490638
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490658
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490678
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490697
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490718
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490740
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.490761
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552056
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=749 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552277
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552319
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552346
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552371
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552396
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552419
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552443
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552467
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.552491
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567582
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567651
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567671
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567691
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567709
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567727
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567745
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567763
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567782
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567800
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567836
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567855
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567873
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567891
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567909
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567926
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567944
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567962
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.567980
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.569551
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599499
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599539
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599562
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599582
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599602
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599640
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599656
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599676
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599695
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599714
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599733
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599752
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599771
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599790
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599809
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599828
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599847
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599866
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599885
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599904
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599923
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599942
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599961
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599980
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.599999
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600018
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600037
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600056
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600075
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600094
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600113
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600132
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600152
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600171
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600190
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600209
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600228
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600247
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600266
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600285
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600304
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600323
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600342
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.600361
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661226
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661373
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661410
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661436
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661457
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661477
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661496
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661516
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661535
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.661555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677078
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677106
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677158
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677196
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677218
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677255
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677273
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677291
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677314
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677335
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677353
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677372
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677392
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677411
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677430
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677450
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677469
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677492
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.677512
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.680172
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708007
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708038
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708061
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708081
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708100
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708120
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708139
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708158
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708197
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708217
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708236
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708255
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708275
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708294
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708313
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708333
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708352
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708371
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708394
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708412
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708449
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708468
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708485
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708504
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708522
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708540
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708558
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708576
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708612
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708630
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708648
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708667
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708685
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708721
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708739
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708756
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708774
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708792
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708810
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708828
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.708846
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.721334
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.723550
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.729799
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770418
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770580
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770615
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770659
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770681
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770702
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770741
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.770760
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.785986
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786015
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786040
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786061
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786088
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786108
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786127
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786147
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786186
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786205
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786224
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786244
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786263
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786283
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786302
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786321
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786341
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786360
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786380
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.786404
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.803918
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817216
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817247
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817271
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817291
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817311
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817331
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817350
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817369
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817389
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817409
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817429
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817448
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817467
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817487
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817506
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817525
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817545
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817564
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817583
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817603
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817622
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817641
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817660
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817679
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817699
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817718
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817737
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817756
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817775
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817795
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817814
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817833
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817853
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817872
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817891
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817910
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817929
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817948
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817968
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.817988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.818007
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.818026
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.818045
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.818064
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.832789
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.879680
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894278
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894301
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894321
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894340
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894359
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894396
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.894415
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895238
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895264
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895285
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895305
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895327
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895353
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895402
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895454
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895476
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895497
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895523
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895544
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895571
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895593
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895618
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895643
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895669
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895697
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.895717
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.914722
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926438
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926469
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926497
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926521
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926545
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926568
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926592
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926615
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926638
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926662
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926685
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926708
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926732
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926755
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926778
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926801
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926824
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926848
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926870
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926894
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926917
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926941
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926964
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.926987
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927011
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927034
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927057
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927080
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927103
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927127
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927150
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927173
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927197
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927220
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927267
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927290
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927313
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927336
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927360
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927383
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927406
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927429
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.927452
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.941999
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.988945
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2813 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989097
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989141
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989188
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989207
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989227
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989246
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989265
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:13.989285
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004397
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004455
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004475
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004493
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004512
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004530
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004548
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004567
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004585
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004603
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004648
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004668
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004687
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004705
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004723
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004741
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004759
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004777
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.004795
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035640
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035670
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035699
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035731
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035759
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035791
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035822
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035849
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035880
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035910
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035938
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035965
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.035996
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036023
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036051
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036078
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036105
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036135
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036193
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036220
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036250
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036281
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036311
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036342
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036372
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036411
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036442
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036473
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036503
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036533
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036563
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036594
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036624
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036655
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036684
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036714
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036742
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036773
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036803
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036831
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036861
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.036891
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.051168
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.074916
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098007
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098192
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098230
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098258
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098283
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098308
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098333
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098358
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098383
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.098408
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113557
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113624
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113649
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113675
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113703
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113728
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113752
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113777
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113801
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113825
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113849
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113873
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113924
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113948
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113973
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.113997
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.114021
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.114048
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.114074
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.124935
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144785
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144827
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144855
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144879
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144904
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144959
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.144986
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145017
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145043
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145068
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145092
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145117
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145141
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145165
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145189
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145213
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145261
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145285
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145309
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145333
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145358
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145382
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145406
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145454
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145478
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145502
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145553
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145577
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145601
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145625
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145648
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145673
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145698
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145721
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145745
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145769
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145793
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145817
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145841
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.145864
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.160431
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207238
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207375
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207410
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207439
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207465
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207489
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207513
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207537
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207561
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.207585
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222804
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222842
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222872
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222922
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222945
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.222993
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223016
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223039
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223062
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223086
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223109
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223132
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223155
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223178
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223201
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223224
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223247
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223271
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.223294
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.234496
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254026
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254067
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254093
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254113
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254132
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254151
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254169
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254187
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254205
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254225
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254261
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254279
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254298
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254316
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254334
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254353
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254371
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254389
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254408
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254426
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254453
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254473
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254492
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254510
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254529
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254547
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254566
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254584
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254602
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254646
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254668
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254687
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254705
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254724
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254742
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254760
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254778
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254796
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254814
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254833
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254851
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.254869
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.269578
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.284680
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.316532
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1101 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323626
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323667
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323688
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323708
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323727
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323764
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323783
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.323801
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.331993
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332023
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332045
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332063
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332082
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332101
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332119
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332138
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332156
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332174
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332193
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332211
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332229
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332248
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332266
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332284
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332303
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332321
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332339
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332361
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.332380
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.334338
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363235
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363277
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363305
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363326
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363349
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363369
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363391
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363415
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363453
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363481
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363509
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363533
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363553
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363575
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363617
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363636
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363659
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363680
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363701
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363723
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363745
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363764
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363785
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363805
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363825
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363847
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363866
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363886
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363905
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363929
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363949
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.363991
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364013
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364035
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364058
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364079
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364101
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364122
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364142
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364164
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364185
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.364206
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.378807
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441501
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=3357 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441702
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441744
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441778
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441811
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441840
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441869
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441902
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441961
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.441988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442016
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442044
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442072
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442099
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442126
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442154
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442182
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442211
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442239
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442267
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442298
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442327
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442355
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442384
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442412
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442441
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442470
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442498
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442526
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.442555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.444125
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472445
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472482
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472510
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472535
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472560
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472585
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472609
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472632
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472656
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472680
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472704
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472727
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472750
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472774
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472797
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472822
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472845
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472869
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472892
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472916
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472939
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472962
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.472985
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473009
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473033
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473057
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473080
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473104
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473127
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473151
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473174
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473202
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473231
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473254
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473278
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473302
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473325
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473348
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473371
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473394
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473417
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473440
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473463
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.473487
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.503166
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550441
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=205 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550604
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550644
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550671
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550696
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550721
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550745
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550770
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550794
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550843
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550867
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550891
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550915
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550940
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550964
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.550988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551012
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551037
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551061
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551085
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551110
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551134
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551158
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551182
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551213
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551238
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551262
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551286
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551315
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.551339
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.554555
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581561
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581597
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581624
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581648
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581672
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581697
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581775
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581799
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581822
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581846
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581869
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581892
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581915
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581939
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581962
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.581986
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582009
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582032
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582055
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582079
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582102
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582126
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582150
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582173
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582197
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582220
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582267
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582290
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582314
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582337
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582364
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582389
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582413
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582443
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582468
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582492
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582517
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582541
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582565
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582589
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.582613
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.597221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659589
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659664
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659701
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659729
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659750
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659770
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659789
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659808
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659827
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659846
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659866
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659885
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659904
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659922
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659942
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659961
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.659980
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660003
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660022
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660041
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660060
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660080
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660099
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660118
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660137
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660156
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660176
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660195
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660214
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660233
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.660251
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.664220
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690863
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690898
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690921
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690940
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690960
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690979
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.690998
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691018
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691037
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691056
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691075
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691094
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691114
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691133
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691152
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691171
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691190
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691210
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691229
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691248
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691267
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691286
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691305
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691325
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691344
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691363
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691382
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691401
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691420
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691439
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691458
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691480
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691499
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691538
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691557
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691576
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691615
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691634
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691655
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691675
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691694
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.691713
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.704101
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=72 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.706386
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.706415
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.706437
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.744132
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.768817
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.768958
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.768992
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769031
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769055
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769076
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769098
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769118
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769138
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769157
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769180
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769199
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769221
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769243
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769264
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769286
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769307
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769329
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769350
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769372
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769392
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769411
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769432
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769452
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769471
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769493
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769513
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769534
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769556
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769582
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.769614
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.794507
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800009
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800041
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800071
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800096
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800120
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800144
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800168
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800191
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800214
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800260
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800284
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800307
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800331
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800354
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800402
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800426
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800449
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800473
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800496
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800520
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800543
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800566
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800593
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800617
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800641
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800665
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800688
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800712
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800735
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800758
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800782
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800805
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800828
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800851
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800874
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800897
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800921
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800944
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800967
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.800990
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.801013
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.815583
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.815619
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.815652
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878014
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878161
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878199
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878229
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878254
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878279
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878303
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878327
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878351
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878375
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878398
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878422
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878445
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878481
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878506
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878531
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878578
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878603
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878627
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878651
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878676
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878700
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878723
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=43 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878753
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878777
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878800
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878824
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878847
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878871
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.878894
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909277
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909336
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909368
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909390
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909410
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909430
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.909450
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=42 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.914714
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.924825
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=40 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.987176
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994469
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994519
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994546
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=39 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994572
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994596
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994621
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994649
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994674
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994698
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994722
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994746
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994770
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994794
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994842
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994866
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994890
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994914
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994939
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994963
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.994987
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=56 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995011
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995035
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995059
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=53 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995083
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995107
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=45 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995131
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=50 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:14.995156
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=46 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018400
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018434
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018460
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018484
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=57 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018508
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018531
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=37 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.018555
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=44 ttl=52 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.024107
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.095092
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.096541
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2621 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.205598
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.239954
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.252377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.264970
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=60 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.264988
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.314810
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.349346
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.349411
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.361556
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=301 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.361610
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=51 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.374226
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=60 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.374241
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.400118
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.400179
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.470863
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.480139
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.483180
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=60 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.483198
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.486360
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=317 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.559701
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.580031
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=56 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.582151
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.594787
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=60 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.594804
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.595818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=4797 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.659792
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.689670
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=48 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.702231
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=60 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.702248
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.720387
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.740451
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.751614
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.798438
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=56 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.810860
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=56 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.810876
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.830190
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=148 ttl=53 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.846915
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=148 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.849741
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.860773
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=178 ttl=44 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.876391
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.877057
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=178 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.891953
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=328 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.905126
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=356 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.923204
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=52 ttl=55 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.935951
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=52 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.935970
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.954377
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=56 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.985818
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=5480 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:15.985882
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.005365
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.005383
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1757 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.005442
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.017439
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=58 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.021013
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.029862
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.79.66.237 -> 88.198.137.209   (len=40 ttl=54 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.047966
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.079245
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=43 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.094788
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.110373
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=59 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.141625
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=328 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.172806
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=56 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.203950
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.204003
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.229755
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.235216
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.266398
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=55 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.297639
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=49 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.310112
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.310176
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.313195
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.329370
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=328 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.359935
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=55 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.390284
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.390312
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.390326
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.390330
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.390333
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.391195
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.422347
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.422407
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=47 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.453616
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=50 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.484781
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.499907
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.516102
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=328 ttl=58 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.547181
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=47 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.578334
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=41 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.609571
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=38 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.609889
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.640725
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=57 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.672171
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.79.66.237   (len=60 ttl=54 DF=0 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.674377
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.674424
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.679704
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:16.729976
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:17.108720
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2054
Non IP Packet type not supported ARP

Timestamp:  2015-12-07 14:20:17.108885
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2054
Non IP Packet type not supported ARP

Timestamp:  2015-12-07 14:20:17.389561
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:17.674184
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:17.674252
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:17.709487
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=4120 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.019781
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.019817
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=5480 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.019841
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.019849
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.020235
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.329931
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.329965
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=4120 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.329987
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.329994
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2760 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.380359
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.380376
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1400 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631291
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631324
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=2760 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631349
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631361
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=3793 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631375
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.631419
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.684468
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.784749
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.905083
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.905145
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.905246
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.905305
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.924829
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.924874
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.924908
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.934237
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=8925 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:18.949625
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=717 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.006097
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.006395
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=141 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.012017
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=157 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226314
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226386
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226420
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226421
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226432
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226433
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.226734
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.230419
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.274649
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.274682
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.274715
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.275120
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.275169
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.277136
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=141 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.415398
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=93 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.525199
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.525742
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.525771
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.634203
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.654834
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.667245
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:19.791962
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.014912
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.014962
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=109 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.145039
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.150804
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.283924
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.493932
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.499367
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.730574
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.743599
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.840880
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:20.868512
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=1661 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.010670
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=141 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.010993
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.109632
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.110213
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.159653
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.210682
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.210707
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.227336
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=3149 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.370494
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=109 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.509756
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.509804
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=52 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.585977
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.590700
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.699875
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=77 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.804871
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=157 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.804900
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.805130
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.916181
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:21.929187
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.020827
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.160415
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.160448
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.163151
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.178799
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=109 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.240590
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.241140
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.256815
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.355277
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.465278
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.465312
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.465584
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.475168
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=93 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.540433
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.540476
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.560420
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=141 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.670789
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=173 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.670816
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.671071
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=77 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.677990
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.779530
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.780354
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=141 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.889941
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=125 ttl=111 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.889969
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=40 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.896397
Ethernet Frame:  00:50:56:bf:04:4b 00:0c:29:f5:70:9e 2048
IP: 88.198.137.209 -> 5.52.45.105   (len=125 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2015-12-07 14:20:22.969734
Ethernet Frame:  00:0c:29:f5:70:9e 00:50:56:bf:04:4b 2048
IP: 5.52.45.105 -> 88.198.137.209   (len=40 ttl=111 DF=1 MF=0 offset=0)
'''