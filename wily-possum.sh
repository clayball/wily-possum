#!/bin/bash

#
#           (
#  (  (  (  )\(                        (     )
#  )\))( )\((_)\ )   `  )   (  (  (   ))\   (
# ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\  '
# _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))
# \ V  V / | | || | | '_ \) _ (_-<_-< || | '  \()
#  \_/\_/|_|_|\_, | | .__/\___/__/__/\_,_|_|_|_|
#             |__/  |_|
#
#
# This will run various firewall testing commands.
#
# What capabilities of the firewall do we want to test?
#
# - what gets blocked? (this is too broad)
# - what gets through? (this is too broad)
# - check for TLS MiTM
#
# Options for the various tests:
#

DEST=$1

# ######### NOTES #########
#
# - A tcp_syn test returned ICMP type 3 code 10
#   This implies it's a response to you from another firewall. If an iptables
#   rule that ends with: REJECT --reject-with icmp-net-prohibited
#   TODO: add check for this nping result
#       (perhaps a function that other functions can call?)

# ######### FUNCTIONS #########
# Create a function for each test
# TODO: add a description for each test
function test_tcp_syn()
{
    printf %b "[TEST_TCP_SYN]\n"
    result=`nping -c 1 -H --tcp -p 80 --seq 31337 --ttl 64 --flags SYN $DEST | grep RCVD | awk {'print $7, $8, $9, $12'}`
    printf %b "\t[result] $result\n"
    flag=`echo $result | awk {'print $1'}`
    ttl=`echo $result | awk {'print $2'}`
    if [ "$flag" == "RA" ]
    then
        printf %b "\t[flag] Reset Ack\n"
    else
        printf %b "\t[flag] $flag\n"
    fi
    printf %b "\t[ttl] $ttl\n"
    printf %b "__________________________________________________\n"
}

function test_tcp_ack()
{
    printf %b "[TEST_TCP_ACK]\n"
    result=`nping -c 1 -H --tcp -p 80 --seq 31337 --ttl 64 --flags ACK $DEST | grep RCVD | awk {'print $7, $8, $9, $12'}`
    printf %b "\t[result] $result\n"
    flag=`echo $result | awk {'print $1'}`
    ttl=`echo $result | awk {'print $2'}`
    if [ "$flag" == "R" ]
    then
        printf %b "\t[flag] Reset\n"
    else
        printf %b "\t[flag] $flag\n"
    fi
    printf %b "\t[ttl] $ttl\n"
    printf %b "__________________________________________________\n"
}


# ######### MAIN SCRIPT #########
# Run all tests
printf %b " \n"
printf %b "           (\n"
printf %b "  (  (  (  )\(                        (     )\n"
printf %b "  )\))( )\((_)\ )   \`  )   (  (  (   ))\   (\n"
printf %b " ((_)()((_)_(()/(   /(/(   )\ )\ )\ /((_)  )\  '\n"
printf %b " _(()((_|_) |)(_)) ((_)_\ ((_|(_|(_|_))( _((_))\n"
printf %b " \ V  V / | | || | | '_ \) _ (_-<_-< || | '  \()\n"
printf %b "  \_/\_/|_|_|\_, | | .__/\___/__/__/\_,_|_|_|_|\n"
printf %b "             |__/  |_|\n"
printf %b "\n"
printf %b " Firewall testing tool suite\n\n"
printf %b "__________________________________________________\n\n"

test_tcp_syn
test_tcp_ack
