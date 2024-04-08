#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUN_IP = "192.160.53.98"

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))
os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname)
os.system("ip link set dev {} up".format(ifname))
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip addr add 192.168.60.0/24 dev {}".format(ifname))
def cir(bytes_in):
	pkt_in = IP(bytes_in)
	if ICMP in pkt_in:
		if pkt_in[ICMP].type == 8:
			return True
	return False

def create_icmp_reply(bytes_in):
	pkt_in = IP(bytes_in)
	ip_out =  IP(src=pkt_in.dst, dst=pkt_in.src)
	pkt_out = ip_out / pkt_in.payload
	pkt_out[ICMP].type = 0
	return bytes(pkt_out)
	

while True:# Get a packet from the tun interface
	packet = os.read(tun, 2048)
	ip = IP(packet)
	print(ip.summary)
	if cir(packet):
		reply_bytes = create_icmp_reply(packet)
		os.write(tun, reply_bytes)
		

