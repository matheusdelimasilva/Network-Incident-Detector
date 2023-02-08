''' 
Script by Matt Silva for CS116

RESOURCES USED:
https://code-maven.com/catch-control-c-in-python

'''

#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident = 0

def packetcallback(packet):
  global incident
  global ftp_username
  try:
      # filter by TCP
      if packet.haslayer("TCP"):
          # decode payload
          payload = packet[TCP].load.decode("ascii").strip() 

          #search for credentials in HTTP
          if "Authorization: Basic" in payload:
              information1 = base64.b64decode(payload.split("Authorization: Basic ")[1]) # get converted Base64 string with username and password
              incident += 1
              username = str(information1).split(":")[0][2:] # getting username
              password = str(information1).split(":")[1][:-1] # getting password
              print(f"ALERT #{str(incident)}: Usernames and passwords sent in-the-clear (HTTP) (username: {str(username)}, password: {str(password)})")

          # search for credentials in FTP
          if packet[TCP].dport == 21:
            if "USER" in payload:
                ftp_username = payload.split(" ")[1]
            if "PASS" in payload:
                password2 = payload.split(" ")[1]
                incident += 1
                print(f"ALERT #{str(incident)}: Usernames and passwords sent in-the-clear (FTP) (username: {str(ftp_username)}, password: {str(password2)})")
              
          # search for credentials in IMAP
          if packet[TCP].dport == 143 and "LOGIN" in payload:
              imap_username = payload.split(" ")[2]
              password3 = payload.split(" ")[3]
              incident += 1
              print(f"ALERT #{str(incident)}: Usernames and passwords sent in-the-clear (IMAP) (username: {str(imap_username)}, password: {str(password3)})")

          # search for NULL scan
          if packet[TCP].flags == 0: 
              portnumber = packet[IP].src
              incident += 1
              print(f"ALERT #{str(incident)}: NULL scan is detected from {str(portnumber)} (TCP)!")
          
          # search for XMAS scan
          if packet[TCP].flags == 41:
              portnumber = packet[IP].src
              incident += 1
              print(f"ALERT #{str(incident)}: XMAS scan is detected from {str(portnumber)} (TCP)!")
          
          # search for FIN scan
          if packet[TCP].flags == 1:
              portnumber = packet[IP].src
              incident += 1
              print(f"ALERT #{str(incident)}: FIN scan is detected from {str(portnumber)} (TCP)!")
          
          # search for Nikto scan
          if packet[TCP].dport == 80 and "Nikto" in payload:
              portnumber = packet[IP].src
              incident += 1
              print(f"ALERT #{str(incident)}: Nikto scan is detected from {str(portnumber)} (TCP)!")
          
          # search for RDP
          if packet[TCP].dport == 445 or packet[TCP].dport == 139:
              portnumber = packet[IP].src
              incident += 1
              print(f"ALERT #{str(incident)}: RDP scan is detected from {str(portnumber)} (TCP)!")

  except Exception as e:
      #print(e)
      pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
