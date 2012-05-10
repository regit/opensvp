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

class generic_server:
     def __init__(self, ip, port, verbose = False):
        self.ip = ip
        self.port = port
        self.l3proto = 'IPv4'
        self.verbose = verbose

    def listen(self):

    def decode_command(self):
        send(self.conn, self.message)

    def run(self):

class irc(generic_client):
    def decode_command(self):
        return "Banzai"

class ftp(generic_client):
    def decode_command(self):
        return "Banzai"
