from scapy.all import *
import codecs
from time import sleep 
from threading import Lock, Thread 
import sys
import argparse
import os

def receive_input(): 
    while 1: 
        print('')
        text=input("Type to send: ")
        if text == 'exit()': os._exit(0)    
        send_msg(text)
        sleep(0)


def send_msg(text):
    ip_part = IP(dst=dstip)
    icmp_part = ICMP(type=0) #need to be 47
    dstip = '127.0.0.1'

    packet=ip_part/icmp_part/text    #joining 2 parts into 1 packet
    sys.stdout = open(os.devnull, 'w') #blocks message 'Sent 1 packets.'
    send(packet)
    sys.stdout = sys.__stdout__

def main():
    # Server information
   
    interface = 'eth0'
    

    receive_input()


  

if __name__ == "__main__":
    main()
