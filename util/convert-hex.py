#!/usr/bin/env python

# Convert a message received that was received in hex.

import sys

#try:
#    hexmsg = sys.argv[1]
#    print '[*] Message: %d' % int(hexmsg, base=16)
#except:
#    print 'Usage: %s hex' % sys.argv[0]

# Open file will hex encoded message
# Convert the message to int then to char

try:
    hexfile = sys.argv[1]
    print '[*] Decoding message in %s' % hexfile
except:
    print '[-] A file including a hex message must be supplied.'

f = open(hexfile, 'r')

for line in f:
    print line
    line = line.split()
    for l in line:
        char = int(l, base=16)
        print chr(char)


f.close()

