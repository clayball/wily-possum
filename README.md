Wily Possum
===========

A firewall penetration testing tool suite.

TODO: build in some network intel.

Most of these tools/tests are based on a client/server model where the client
is internal to the firewall and the server is external to the firewall.

The tools that are included as Git submodules can be updated to the most
recent commit by running the following Git command.

```git submodule update --remote```

Run the above command from time to time to get recent updates. Due to the
nature of Dissembling Ferret, once the project has reached a mature state
updates will become minimal. 

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

TODO: a word about Dissembling Ferret

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

### Firewall Checks

#### SMB Checks

- outbound TCP ports 139 and 445 (should be blocked)
- outbound UDP ports 137 and 138 (should be blocked)


## References

- https://nmap.org/book/
- https://www.cse.msu.edu/~alexliu/publications/FirewallFingerprinting/FirewallFingerprinting-INFOCOM2012.pdf


