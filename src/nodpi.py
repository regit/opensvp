#!/usr/bin/env python
#
# Copyright 2012 Eric Leblond <eric@regit.org>
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

# need root privileges

import struct
import sys
import time
from scapy.all import *


# TLL low or invalid CRC

from socket import AF_INET, AF_INET6, inet_ntoa

sys.path.append('python')
sys.path.append('build/python')
import nfqueue


class generic_nodpi:
    def __init__(self, iface, queue = 0, verbose = False):
        self.iface = iface
        self.verbose = verbose
        self.conn_dict = {}
        self.queue = queue
        self.ttl = 60 # arbitrary overwritten later

    def get_attack_ttl(self, ttl):
        if ttl > 64:
            delta = 128 - ttl - 1
        else:
            delta = 64 - ttl - 1
        return delta

    def forged_payload(self):
        return ""

    def cb(self, payload):

        data = payload.get_data()
        # TODO handle IPv6.
        pkt = Ether()/IP(data)

        if pkt[IP].proto != 6:
            return 1

        if pkt[TCP].flags == 18:
            self.ttl = pkt[IP].ttl

        if pkt[TCP].flags == 'S':
            try:
                # Here we must get the TTL
                del self.conn_dict[ptk[TCP].sport]
            except:
                pass

        if pkt[TCP].flags & 8 != 0 and not self.conn_dict.has_key(pkt[TCP].sport):
            self.conn_dict[pkt[TCP].sport] = 1
            pkt[IP].ttl = self.get_attack_ttl(self.ttl)
            pkt[TCP].payload = self.forged_payload()
            del pkt[IP].chksum
            del pkt[TCP].chksum
            del pkt[IP].len
            if self.verbose:
                sendp(pkt, iface=self.iface)
            else:
                sendp(pkt, iface=self.iface, verbose=0)
        if self.verbose:
            print "Packet accepted\n"
        payload.set_verdict(nfqueue.NF_ACCEPT)
        return 1

    def run(self):
        q = nfqueue.queue()

        if self.verbose:
            print "NFQ: open"
        q.open()

        if self.verbose:
            print "NFQ: bind"
        q.bind(AF_INET)

        if self.verbose:
            print "NFQ: setting callback"
        q.set_callback(self.cb)

        if self.verbose:
            print "NFQ: creating queue"
        q.create_queue(self.queue)

        q.set_queue_maxlen(50000)

        if self.verbose:
            print "NFQ: trying to run"
        try:
            q.try_run()
        except KeyboardInterrupt, e:
            print "NFQ: interrupted"

        if self.verbose:
            print "NFQ: unbind"
        q.unbind(AF_INET)

        if self.verbose:
            print "NFQ: close"
        q.close()

class http_nodpi(generic_nodpi):
    def forged_payload(self):
        return """
GET /favicon.ico HTTP/1.1
Host: www.hopossum.org
"""
