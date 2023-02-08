----------------------------------------------------------------------
|                            CS116 ALARM                             |
| Matheus de Lima Silva                                              |
| 10/13/22                                                           |
----------------------------------------------------------------------

                           ---- PURPOSE ----

This program is a tool to analyze a live stream or a set of network packets. 
It notifies incidents that are detected in the network, such as scans or
credentials sent in-the-clear.

It supports detections for:
- Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
- NULL scans
- FIN scans
- Xmas scans
- Nikto scans
- Someone scanning for the Server Message Block (SMB) protocol

If an incident is detected, an alert is displayed.

The program supports the following command line arguments:
-i INTERFACE: Sniff on a specified network interface`
-r PCAPFILE: Read in a PCAP file`
-h: Display message on how to use tool`

                          ---- PERFORMANCE ----

This program can successfuly detect on-going scans such as NULL, FIN, Xmas, 
and Nikto scans. It also checks for usernames and passwords sent 
in-the-clear via HTTP Basic Authentication, FTP, and IMAP. Finally, it can
detect someone scanning for the Server Message Block (SMB) protocol.

                        ---- DEPENDENCIES ----

                       Scapy, Argparse, Base64. 

                      ---- ACKNOWLEDGEMENTS ----

Online resources used:
https://docs.python.org/3/library/re.html
https://code-maven.com/catch-control-c-in-python
https://scapy.readthedocs.io/en/latest/

