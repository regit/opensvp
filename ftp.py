#!/usr/bin/python
# Copyright 2011 Eric Leblond <eric@regit.org>

import ftplib
from time import sleep

ftp = ftplib.FTP("192.168.2.2")
ftp.login("anonymous", "opensvp")

sleep(2)
