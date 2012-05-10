#!/usr/bin/env python
#
# Copyright 2011-2012 Eric Leblond <eric@regit.org>
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

import argparse
import opensvp.helper

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
    target = opensvp.helper.ftp(args.iface, args.target, int(args.port), verbose=args.verbose)
elif args.helper == 'irc':
    target = opensvp.helper.irc(args.iface, args.target, int(args.port), verbose=args.verbose)
elif args.helper == 'ftp6':
    target = opensvp.helper.ftp6(args.iface, args.target, int(args.port), verbose=args.verbose)
else:
    sys.exit("Selected protocol is currently unsupported")

target.run()
