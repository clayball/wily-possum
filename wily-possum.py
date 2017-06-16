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



NOTE: We could make this modular so future improvements can be easily added.

Lets not go too crazy with command-line arguments.
- target: IP
- test: basic, full, host
  basic - port, application, etc.. (TCP, UDP)
  full  - basic plus egress, ingress (TCP, UDP, ICMP, etc)
  host  - test host based firewalls (no ingress/egress, etc.)

What firewall capabilities should we test?
- what gets blocked? (this is too broad)
- what gets through? (this is too broad)
  - Can we send a SA packet in hope of fooling the FW into thinking the flow
    was initiated from the remote machine?
- check for TLS MiTM
- test for stateful vs. stateless [1], [2] (should we bother?)

References:

[1] Nmap, https://www.nmap.org
[2] Firewall Fingerprinting TODO: add URL
'''

# ######### IMPORTS #########
from sys import argv
from scapy.all import *
import IPy
from optparse import OptionParser


# Use OptionParser to make the interface and feedback nice
parser = OptionParser()
parser.add_option("-d", "--dest", dest="destination_ip", default="foo",
                  help="Destination IP to run scans against")
parser.add_option("-p", "--port", dest="destination_port", default="443",
                  help="Destination port")
parser.add_option("-s", "--spoof", dest="spoof_ip", default="66.249.66.1",
                  help="Spoof the source IP address as this value")
parser.add_option("-t", "--test", dest="runtest", default="full",
                  help="Type of test to run [basic|full|host]")
(options, args) = parser.parse_args()

dst = options.destination_ip
dport = options.destination_port
spoof = options.spoof_ip
runtest = options.runtest
#src = '127.0.0.1' ## USE FOR TESTING LOCALLY

# TODO: add check for required options


# ######### GLOBAL VARIABLES #########
ofile = "results-" + dst + "-" + dport + ".log"
# For reference:
#   FIN = 0x1
#   SYN = 0x2
#   RST = 0x4
#   PSH = 0x8
#   ACK = 0x10
#   URG = 0x20
#   ECE = 0x40
#   CWR = 0x80

# TODO: should the following settings be in a config file?
# 
# These are the TCP flags we're interested in setting.
# Add more if you'd like run other types of tests.
S  = 0x2
SR = 0x6
A  = 0x10
SA = 0x12
SP = 0xa
SE = 0x42
SC = 0x82

# EDIT: add your own ports of interest, not necessary
ports = ('22', '53', '80', '443', '8080')

# TODO: We could query atlas.torproject and specify exit nodes as decoys.
# EDIT: add your own decoys, mostly not necessary
decoys = ('www.google.com', '8.8.8.8', 'www.bing.com')

# Hosts used for bouncing packets
# TODO: add more.? 
bouncers = ('www.google.com', '8.8.8.8', 'www.bing.com')


# ######### FUNCTIONS #########
def display_banner():
    print ' '
    print '          ('
    print '  (  (  (  )\(                        (     )     '
    print '  )\))( )\((_)\ )   `  )   (  (  (   ))\   (      '
    print ' ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\     '
    print ' _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))   '
    print ' \ V  V / | | || | | \'_ \) _ (_-<_-< || | \'  \()' 
    print '  \_/\_/|_|_|\_, | | .__/\___/__/__/\_,_|_|_|_|   '
    print '             |__/  |_| '
    print ' '
    print ' Firewall Testing Suite'
    print ' '


# Determine stateful/stateless firewall based on packet sequences reaching
# their destination.
#
# Stateful firewall will mostly drop the following sets of sequences.
# Not sure if it's worth it to use and reference the paper that used this
# approach.
# SR SA, SR SE, SR SC | SE SR, SE SP, SE SA | SA SR, SA SP, SA SE

# Pass all fields of interest to this function
def send_packet(proto, dst, src, dport, sport, flags, data):
    print '[*] sending %s' % flags
    pkt = IP(dst=dst)/TCP(dport=80, flags=flags)
    res = sr1(pkt, timeout=1)
    return res

# This was the first scan implemented and works OK so leaving it here for now.
def simple_scan(flags):
    print '[*] sending %s' % flags
    pkt = IP(dst=dst)/TCP(dport=80, flags=flags)
    res = sr1(pkt, timeout=1)
    return res

# TODO: see notes below.
# We'll be running various tests and will want to compare results of those
# tests. We need a data structure to capture our results for each test.
# The results_syn structure seems to work.
def get_result(res, flags):
    is_response = -1
    # Did our packet generate a response from the destination?
    if (res):
        is_response = 1
        print '[result] %s, IP.len: %s' % (flags, str(res.len))
        out.write('[response] ' + flags + '\n')
    else:
        is_response = 0
        print '[-] No response to %s' % flags
        out.write('[DEADflag] ' + flags + '\n')
    return is_response

flags = [ 'S', 'A', 'P', 'F', 'R' ]
# Initializing to 2 since this will be set to 1 or 0 later.
results_syn = { 'S': 2,
                'A': 2,
                'P': 2,
                'F': 2,
                'R': 2}

def tcp_flag_scans(dst, dport):
    print '[*] Performing TCP flag scans..'
    for f in flags:
        print '[*]   dst: %s, dport: %d, flags: %s' % (dst, int(dport), f)
        pkt = IP(dst=dst)/TCP(dport=int(dport), flags=f)
        response = sr1(pkt, timeout=1)
        outcome = get_result(response, f)
        results_syn[f] = outcome
        print '[*] Outcome for %s: %d\n' % (f, outcome)

##### TCP scans #####

## SYN
def tcp_syn_scans():
    print '[+] Performing TCP SYN scans..'

def bounce_tcp():
    print '[+] Performing bounce scans..'

## ACK

# TODO

## RST

# TODO

##### UDP scans #####
def udp_scans():
    print '[+] Performing UDP scans..'

# TODO: hold off on this one
def arp_scans():
    print '[+] Performing ARP scans..'


##### ICMP scans #####
def icmp_scans():
    print '[*] Performing ICMP scans..'

def bounce_icmp():
    print '[+] Performing ICMP bounce scans..'


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

    '''
    cases = ('SR', 'SA', 'SE', 'SC', 'SP', 'SU', 'A', 'AC', 'AE')
    count_cases = len(cases)

    for i, case in enumerate(cases):
        print '[*] running case %s' % case
        print 'case: %s' % case
        res = simple_scan(case)
        r = get_result(res, case)
        count_responses += r

    # if we're going to use this we need to make sure we can defend why we're
    # checking this value and what it means (must be verifiable).
    ratio = float(count_responses) / float(count_cases)
    '''

    # Run our other scans
    tcp_flag_scans(dst, dport)

    print ' '
    print ' '
    print '            ('
    print '    (  (  (  )\(                        (     )     '
    print '    )\))( )\((_)\ )   `  )   (  (  (   ))\   (      '
    print '   ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\     '
    print '   _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))   '
    print '===================================================='
    print ' Results for target:  %s:%d' % (dst, int(dport))
    print ' '
    #print '    Total test cases sent:   %d' % count_cases
    #print ' Total responses received:   %d' % count_responses
    #print '                    Ratio:   {:.2%}'.format(ratio)
    #if ratio < 0.7:
    #    print ' A stateful firewall is likely present.'
    #else:
    #    print ' A stateless firewall, if any, is likely present.'
    print ' TCP Flag Scan'
    print ' '
    for flag, outcome in results_syn.iteritems():
        if outcome == 1:
            print '   %s, %d' % (flag, outcome)
    print '===================================================='


if __name__ == '__main__':
    out = open(ofile, "w")
    main()
    out.close()
