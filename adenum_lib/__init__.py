"""adenum - Universal Active Directory enumeration tool.

A staged, educational AD recon framework that wraps proven Kali tools
(nxc, impacket-*, enum4linux-ng, ldapsearch, smbclient, rpcclient,
bloodhound-python, certipy-ad) into a single workflow.

Stage 0:  adenum.py <ip>                                      -> domain/host/OS
Stage 1:  adenum.py <ip> --domain DOM                         -> users/groups
Stage 2:  adenum.py <ip> --domain DOM --users users.txt       -> AS-REP hashes
Stage 3:  adenum.py <ip> --domain DOM -u USER -p PASS         -> BH + secrets
"""

__version__ = "0.1.0"
