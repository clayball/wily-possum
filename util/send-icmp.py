#!/usr/bin/env python

from scapy.all import *

msg = [] 
message = raw_input('[*] What\'s the encoded message you\'d like to send:\n')
destination = raw_input('[*] Where would you like to send your message?\n')

message = message.replace(',', '')
#print message

msg = message.split()

for m in msg:
    print '[*] m: %d' % int(m)
    code = int(m)
    pkt = IP(dst=destination)/ICMP(type=9,unused=code)
    #pkt = IP(src=destination, dst='65.199.32.22')/ICMP(type=9,unused=code)
    res = sr1(pkt, timeout=1)    

