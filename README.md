Wily Possum
===========

A firewall penetration testing tool suite.


Most of these tools/tests are based on a client/server model where the client
is internal to the firewall and the server is external to the firewall.

The tools that are included as Git submodules can be updated to the most
recent commit by running the following Git command.

```git submodule update --remote```

Run the above command from time to time to get updates from the submodule
projects. Due to the fact that Dissembling Ferret uses covert TCP channels,
once the project has reached a mature state updates will become minimal. 

**Tools Included**

- Dissembling Ferret, https://github.com/clayball/Dissembling-Ferret

  Layer 3: data exfiltartion using covert TCP channels and steganography

- FireAway, https://github.com/tcstool/Fireaway

  Layer 7: data exfiltration (in packet data)

- wily-possum.py 

  TODO: should we include nping like functionality, via shell script(s)?
  - Perform firewall tests
  - Validate network connectivity and general packet flow

  Check for the presence of various attack vectors.
  See the section below for details.


## Dissembling Ferret

Exploiting covert channels in the TCP/IP protocol suite.


## FireAway

Next Generation Firewall Audit and Bypass Tool 

(c) 2016 Russell Butturini, https://github.com/tcstool/Fireaway


## wily-possum.py & wily-possum.sh

The shell script includes some initial tests using nping. Lets build on this.

TODO:
If any of the following checks succeed then further action is necessary
because a *potential* vulnerability is present. For example, all outbound SMB
connections from the local network to the WAN on TCP ports 139 and 445 and UDP
port 137 and 138 should be blocked.

### Determining Firewall Rules

TODO: Add the following scans and analyze the results appropriately.
      Have the ready for #Security2017.

- SYN scan
- ACK scan
- IPID tricks
- UDP version scanning

Run the above scans and analyze the results. Results stored in memory as a
dict.

### Bypassing Firewall Rules

TODO: future work

- Source port manipulation
- IPv6 attacks
- MAC address spoofing
- Source routing
- Taking an alternate path
  - various tracing techniques to be used 

### Other Firewall Checks

#### Egress tests

- Can we spoof a request from a remote system by sending SYN-ACK packets?
  - set sport > 30000
- Should we attempt to send more than 1000 packet per second for one minute?
  Not sure if this sort of testing should be included.
- Should we test for Tor functionality?
  - Can an internal machine be used as Tor relay?

#### Ingres tests

- Should we test for Tor functionality?
- Should we test for brute-force alerts?
- Are there any known ports that should be blocked, e.g. 3306?


#### Samba tests

Does it make sense to have that and/or other Samba tests?

- outbound TCP ports 139 and 445 (should be blocked)
- outbound UDP ports 137 and 138 (should be blocked)


## References

- https://nmap.org/book/
- https://www.cse.msu.edu/~alexliu/publications/FirewallFingerprinting/FirewallFingerprinting-INFOCOM2012.pdf


