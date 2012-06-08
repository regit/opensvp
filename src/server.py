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
import os

class generic_server:
    def __init__(self, ip, port, verbose = False):
        self.port = port
        self.family = socket.AF_INET
        self.verbose = verbose
        self.conn = None
        self.cconn = None
        self.message = None
        self.ip = ip

    def listen(self):
        if self.port < 1024 and not os.geteuid()==0:
            raise Exception('Need to be root')
        self.conn = socket.socket(self.family, socket.SOCK_STREAM)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((self.ip, self.port))
        self.conn.listen(1)
        self.cconn, addr = self.conn.accept()
        self.negotiate()
        res = self.decode_command()
        self.cconn.sendall("%s:%d" %res)
        self.cconn.close()
        self.conn.close()

    def negotiate(self):
        self.message = self.cconn.recv(1024)

    def decode_command(self):
        return self.message

    def run(self):
        try:
            self.listen()
        except socket.error:
            print socket.error.string
        except Exception, err:
            print err
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
        r = re.search('PORT ([\d,]+)\r\n', self.message)
        rsplit = r.group(1).split(',')
        return ('.'.join(rsplit[0:4]), int(rsplit[4]) * 256 + int(rsplit[5]))

    def negotiate(self):
        self.cconn.recv(1024)
        self.cconn.sendall('200 opensvp\r\n')
        self.message = self.cconn.recv(1024)

class ftp6(ftp):
    def __init__(self, ip, port, verbose = False):
        generic_server.__init__(self, ip, port, verbose)
        self.family = socket.AF_INET6

    def decode_command(self):
        r = re.search("EPRT \|2\|(.+)\|(\d+)\|\r\n", self.message)
        return (r.group(1), int(r.group(2)))


