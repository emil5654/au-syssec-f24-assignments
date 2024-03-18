import socket
from scapy.all import IP, ICMP, sniff
import os

def handle_icmp_message(packet):
    try:
        print('')
        print('Received message: '+(packet.load).decode())  
    except:pass
  

def main():
    # Server information
    dstip = '127.0.0.1'

    
    interface = 'eth0'

    print(f"Server listening on {dstip}:")
    try:
        while 1: 
            sniff(prn=handle_icmp_message, filter="host "+ dstip+ " and icmp and icmp[0]=0", store=0, count=10)
    except:
        print('\r\nError: Could not start sniffing for icmp packets on interface: '+interface)
        os._exit(0)

if __name__ == "__main__":
    main()
