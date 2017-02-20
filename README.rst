=======
Opensvp
=======

Introduction
============

Opensvp is a security tool implementing "attacks" to be able to test
the resistance of firewall to protocol level attack. It implements
classic attacks as well as some new kind of attacks against application
layer gateway (called helper in the Netfilter world).

For example, opensvp is able under some conditions (see explanation
below for details) to open a pin hole in a firewall protecting a
ftp server: even if the filtering policy garantee that only the 21
port is open to the server, you can open 'any' port on the server
by using opensvp.

Lets have 192.168.2.3 a server running ftp, placed behind a firewall.
If the user, as root, runs::

 opensvp --attacker -t 192.168.2.3 --helper ftp --port 23 -v -i eth0

Then he will have a temporary access on port 23 of the server independantly
of the firewall rules.

The document "Secure use of iptables and connection tracking helpers" 
https://home.regit.org/netfilter-en/secure-use-of-helpers/ describe
the protection method against this type of attack.

Implemented attacks
===================

Spoofed attack on helpers
-------------------------

See the following chapter for a precise description of the implemented attack.

Being on a network directly connected to the firewall via the eth0 interface,
the attacker can run the following command ::

 opensvp --attacker -t 192.168.2.3 --helper ftp --port 23 -v -i eth0

192.168.2.3 is the address of the FTP server and 23 is the port we want to
open on the server.

It is then possible to connect to 192.168.2.3 on port 23 after a successful
attack.

Abusive usage of helpers
------------------------

It is possible for a client to send a forged command message which is interpreted
as possible dynamic connection opening by the firewalls.

It is possible to use a standard server to send the attack but with a custom server
you will know the transformation made by the possible NAT gateway.

A typical session is the following. On the server which has IP address 1.2.3.4, you
can run ::

 $ opensvp --server --helper irc -v

On the client, you can then run ::

 $ opensvp --client -t 1.2.3.4 --helper irc --port 23 -v
 2.3.4.5:23 should be opened from outside

On the server, the following message is displayed ::

 You should be able to connect to 2.3.4.5:23

Here 2.3.4.5 is the public address of the client.

TTL attack on DPI solution
--------------------------

On the attacker, you need to start the opensvp and indicate what is the used
Netfilter queue and what is the output interface ::

 # opensvp -n -q 0 -i eth1

You then need to use iptables to userspace the trafic you want to hide to protocol
recognition mechanism ::

 iptables -I INPUT -p tcp --sport 443 -j NFQUEUE
 iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE

When you're done, press CTRL+C to interrupt the attack process.

Description of the attack against helper
========================================
Principle
---------

Some network protocols are using multiple connections  for the exchange
between a client and a server. The most known example is ftp where command
goes through a connection on port 21 and where data exchange are done with
two different mode (connection from port 20 or dynamic connection).

Some firewall implementation implement application layer gateway (ALG) to be
able to detect this parallel connection and be able to autorize them dynamically.
Other solutions are to use application relay (transparent proxy) or to open
all the possible flow (read almost everything).

The ALG analyse the traffic and detect and parse the command sent between the
peers to declare the parameters of the parallel connections. Once done they
open temporary pin hole in the firewall to let the probable traffic goes through.

The idea of this attack is to forge this type of messages to open pin hole in
the firewall but pin hole that should not have been open.


Condition:
 * Attacker computer is on a network directly connected to the firewall.
 * Firewall is sensible to the attack (for example, Netfilter with rp_filter
   set to 0)
 * Attacker is able to sniff data packet (or by pcap sniffing or by running
   himself a data connection)

The cinematic is the following :
 1. Sniffer on the attacker network capture one packet from the protocol flow

     * it reverse the ethernet dst and src
     * it increase id in IP and seq for TCP
     * it set payload to the wanted command (with selected
       port)

 2. The forged packet is sent on the interface connected to the firewall
 3. Firewall transmit the packet back to the client and is now expecting
    a packet with caracteristic based on attacker input

Attacking IRC
-------------

This attack is a direct application of the described principle. Once data packet
is received, the attacker send a forged DCC command.

Attacking FTP
-------------

In this attack, the client connection is open by the attacker. He connect to the
ftp server behind a firewall and initiate a real connection. Once the session is
setup, he launch the attack by sending a forged 227 command.

If IPv6 is used, the same attack is done with a forged 229 command.

Impact of the attack
--------------------
Possible target
~~~~~~~~~~~~~~~

The main contraint about these attack is that the attacker has to be on a network
directly connected to the firewall.

Thus, the main possibilities are:
 * Attack from a user LAN
 * Attack in a hosting farm

Both case can lead to severe information exposure by giving the attacker access to
unprotected services.

Linux
~~~~~

This attack is known to work on IPv4 Netfilter firewall if rp_filter is set to
0 (this is hopefully not the default value).

There is currently no reverse path filtering implementation for IPv6, the firewall
is thus not protected and the protection has to be setup in the firewall rules (see
next chapter).

Some firewall software are known to be vulnerable:
 * fwbuilder: a specific policy has to be set up
 * shorewall: recent version fix the issue
 * edenwall: vulnerable

The attack works for both gateway and local firewall. On a local firewall, FORWARD
filtering has to be activated and a ESTABLISHED ACCEPT rules has to be set up on
this chain. This could be the case of system running virtual machine.

Defense against the attack
==========================
Linux
-----

See the following document which is dedicated to the subject: https://home.regit.org/netfilter-en/secure-use-of-helpers/

Other OS and devices
--------------------

The basic requirement is to activate strict anti-spoofing and to control the loading of ALG is possible.
