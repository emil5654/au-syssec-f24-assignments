#!/usr/bin/env python3
from scapy.all import *
import fcntl 
import struct
import os 
import time
import ssl
import socket
#Tun interface
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

#interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface name:{}".format(ifname))

#configure tun
os.system("ip addr add 192.168.53.11/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

#SSL
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chaiSn(certfile='cert.pem', keyfile='key.pem')



#UDP server
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP_A, PORT))
sock.listen(5)


while True:
	newsocket, fromaddr = sock.accept()
	ssl_sock = context.wrap_socket(newsocket, server_side = True)

	try:
		while True:
			data = ssl_sock.recv(2048)
			if not data:
				break
			print (f"Got data from {fromaddr}")
			os.write(tun, data)
	finally:
		ssl_sock.shutdown(socket.SHUT_RDWR)
		ssl_sock.close()
sock.close()