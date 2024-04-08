#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *
import ssl
import socket

# Set the ip for the VPN server
SERVER_IP =  "10.9.0.11"
SERVER_PORT = 9090
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
os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip addr add 192.168.60.0/24 dev {}".format(ifname))

#routing
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('./cert.pem')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = context.wrap_socket(sock, server_hostname= SERVER_IP)
ssl_sock.connect((SERVER_IP, SERVER_PORT))



while True:
    packet = os.read(tun, 2048)
    if packet:
        ssl_sock.sendall(packet)
ssl_sock.close()
