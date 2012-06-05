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


# simple client: connect to a server for a protocol and send
# a command activating helper to it.
import socket

class generic_client:
    def __init__(self, ip, srv_port, port, verbose = False):
        self.ip = ip
        self.srv_port = srv_port
        self.port = port
        self.family = socket.AF_INET
        self.verbose = verbose
        self.conn = None

    def connect(self):
        self.conn = socket.socket(self.family, socket.SOCK_STREAM)
        self.conn.connect((self.ip, self.srv_port))

    def send_command(self):
        self.conn.sendall(self.message)
        data = self.conn.recv(1024)
        self.conn.close()
        return data

    def run(self):
        self.connect()
        self.message = self.build_command()
        if self.verbose:
            print "Attack message:\n%s\n" % self.message
        return self.send_command()

    def build_command(self):
        return ""

class irc(generic_client):
    def ipnumber(self, ip):
        ip=ip.rstrip().split('.')
        ipn=0
        while ip:
            ipn=(ipn<<8)+int(ip.pop(0))
        return ipn

    def build_command(self):
        (ipaddr, port) = self.conn.getsockname()
        return 'PRIVMSG opensvp :\x01DCC CHAT CHAT %d %d\x01\r\n' % (self.ipnumber(ipaddr), self.port)

class ftp(generic_client):
    def build_command(self):
        (ipaddr, port) = self.conn.getsockname()
        return 'PORT %s,%d,%d\r\n' % (ipaddr.replace('.',','), self.port >> 8 & 0xff, self.port & 0xff)

    def send_command(self):
        self.conn.sendall('USER opensvp\r\n')
        self.conn.recv(1024)
        self.conn.sendall(self.message)
        data = self.conn.recv(1024)
        self.conn.close()
        return data


class ftp6(ftp):
    def __init__(self, iface, ip, port, verbose = False):
        generic_client.__init__(self, iface, ip, port, verbose)
        self.family = socket.AF_INET6

    def build_command(self):
        (ipaddr, port, a, b) = self.conn.getsockname()
        return 'EPRT |2|%s|%d|\r\n' % (ipaddr, self.port)
