#!/usr/bin/env python2

'''
          (
 (  (  (  )\(                        (     )
 )\))( )\((_)\ )   `  )   (  (  (   ))\   (
((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\  '
_(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))
\ V  V / | | || | | '_ \) _ (_-<_-< || | '  \()
 \_/\_/|_|_|\_, | | .__/\___/__/__/\_,_|_|_|_|
            |__/  |_|


All your packet belong to us.

What firewall capabilities should we test?
NOTE: We could make this modular so future improvements can be easily added.

- what gets blocked? (this is too broad)

- what gets through? (this is too broad)
  - Can we send a SA packet in hope of fooling the FW into thinking the flow
    was initiated from the remote machine?


- check for TLS MiTM

- test for stateful vs. stateless [1], [2]



References:

[1] Nmap, https://www.nmap.org
[2] Firewall Fingerprinting TODO: add URL

'''

# ######### IMPORTS #########
from sys import argv
from scapy.all import *

# ######### VARIABLES #########
dst = argv[1]

ofile = "possum-results.log"
# For reference:
#   FIN = 0x1
#   SYN = 0x2
#   RST = 0x4
#   PSH = 0x8
#   ACK = 0x10
#   URG = 0x20
#   ECE = 0x40
#   CWR = 0x80

# These are the ones we're interested in.
S  = 0x2
SR = 0x6
A  = 0x10
SA = 0x12
SP = 0xa
SE = 0x42
SC = 0x82

# EDIT: add your own ports of interest, not necessary
ports = ('22', '53', '80', '443', '1337', '8080')

# EDIT: add your own decoys, mostly not necessary
decoys = ('', '8.8.8.8', '')

# ######### FUNCTIONS #########
def display_banner():
    print ' \n'
    print '          ('
    print '  (  (  (  )\(                        (     )     '
    print '  )\))( )\((_)\ )   `  )   (  (  (   ))\   (      '
    print ' ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\     '
    print ' _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))   '
    print ' \ V  V / | | || | | \'_ \) _ (_-<_-< || | \'  \()' 
    print '  \_/\_/|_|_|\_, | | .__/\___/__/__/\_,_|_|_|_|   '
    print '             |__/  |_| '
    print ''
    print ' Firewall Testing Suite'
    print '\n'


# Determine stateful/stateless firewall based on packet sequences reaching
# their destination.
#
# Stateful firewall will mostly drop the following sets of sequences.
# Not sure if it's worth it to use and reference the paper that used this
# approach.
# SR SA, SR SE, SR SC | SE SR, SE SP, SE SA | SA SR, SA SP, SA SE

def send_packet(flags):
    print '[*] sending %s' % flags
    pkt = IP(dst=dst)/TCP(dport=80, flags=flags)
    res = sr1(pkt, timeout=1)
    return res

def get_result(res, val):
    is_response = -1
    if (res):
        is_response = 1
        print '[result] %s, IP.len: %s' % (val, str(res.len))
        out.write('[response] ' + val + '\n')
    else:
        is_response = 0
        print '[-] No response to %s' % val
        out.write('[DEADflag] ' + val + '\n')
    return is_response


# ######### MAIN PROGRAM #########
def main():
    count_responses = 0
    print '[*] Sending packets to %s' % dst
    out.write('Results for target: ' + dst + '\n\n')
    display_banner()
    r = 0
    # Iterate over test cases (do we really need to capture the same response
    # multiple times? Would it be worth it to send the packet multiple times
    # and check for variations?
    cases = ('SR', 'SA', 'SE', 'SC', 'SP', 'SU', 'A', 'AC', 'AE')
    count_cases = len(cases)

    for i, case in enumerate(cases):
        print '[*] running case %s' % case
        print 'case: %s' % case
        res = send_packet(case)
        r = get_result(res, case)
        count_responses += r

    ratio = float(count_responses) / float(count_cases)

    print '[*] Done.. all tests have been performed.'
    print '[*]'
    print '               ('
    print '       (  (  (  )\(                        (     )     '
    print '       )\))( )\((_)\ )   `  )   (  (  (   ))\   (      '
    print '      ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\     '
    print '      _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))   '
    print '[*] =================================================='
    print '[*]       Summary for target:   %s' % dst
    print '[*]    Total test cases sent:   %d' % count_cases
    print '[*] Total responses received:   %d' % count_responses
    print '[*]                    Ratio:   {:.2%}'.format(ratio)
    if ratio < 0.7:
        print '[*] A stateful firewall is likely present.'
    else:
        print '[*] A stateless firewall, if any, is likely present.'
    print '[*] =================================================='


if __name__ == '__main__':
    out = open(ofile, "w")
    main()
    out.close()
