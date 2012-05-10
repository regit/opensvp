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

class generic_client:
    def __init__(self, ip, srv_port, port, verbose = False):
        self.ip = ip
        self.srv_port = srv_port
        self.port = port
        self.l3proto = 'IPv4'
        self.verbose = verbose

    def connect(self):

    def send_command(self):
        send(self.conn, self.message)

    def run(self):

    def build_command(self):
        return ""

class irc(generic_client):
    def build_command(self):
        return 'PRIVMSG opensvp :\x01DCC CHAT CHAT %d %d\x01\r\n' % (self.ipnumber(self.ip), self.port)

class ftp(generic_client):
    def build_command(self):
        return "Banzai"

class ftp6(generic_client):
    def __init__(self, iface, ip, port, verbose = False):
        ftp.__init__(self, iface, ip, port, verbose)
        self.l3proto = "IPv6"
    def build_command(self):
        return "Banzai"
