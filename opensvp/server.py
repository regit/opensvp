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

# simple server: listen on protocol and decode the command to provide
# the NATed information to the user.

import socket, struct, re

class generic_server:
    def __init__(self, port, verbose = False):
        self.port = port
        self.l3proto = 'IPv4'
        self.verbose = verbose
        self.conn = None
        self.message = None

    def listen(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.bind(('', self.port))
        self.conn.listen(1)
        conn, addr = self.conn.accept()
        self.message = conn.recv(1024)        
        conn.close()
        self.conn.close()

    def decode_command(self):
        return self.message

    def run(self):
        self.listen()
        if self.verbose:
            print "Received: %s" % self.message
        return self.decode_command()
    
    def numtodotquad(self, ip):
        return socket.inet_ntoa(struct.pack('!L',ip))

class irc(generic_server):
    def decode_command(self):
        r = re.search("CHAT (\d+) (\d+)", self.message)
        return (self.numtodotquad(int(r.group(1))), int(r.group(2)))

class ftp(generic_server):
    def decode_command(self):
        return "Banzai"
