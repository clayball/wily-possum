#!/usr/bin/env python

# Create the return an integer representing the Unicode code point of the
# character.
# c is each character of the message to encode.
# m is the encoded character to send.

msg = raw_input('Enter message: ') 
msglist = []

for c in msg:
    m = ord(c)    
    print '[*] %s: %d' % (c, m)
    msglist.append(m)

print '[*] Encoded message to send..'
print msglist
