from scapy.all import *
import sys
import argparse
import os
import string
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import secrets


preshared_secret_key = '8efbcfc8668336a12c7fd5f81e7bc276fcf46d87a686bd9605882307a99ff807'

def encrypt_with_aes_cbc(key, plaintext):
   # Convert hexadecimal string to bytes for the key
    key = bytes.fromhex(key)
    
    # Generate a random IV of the correct size (16 bytes for AES-256)
    iv = secrets.token_bytes(16)
    
    # Create an AES object in CBC mode and pass the IV
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    
    # Pad the plaintext to a multiple of the block size (16 bytes)
    padded_plaintext = pad(plaintext, AES.block_size)
    
    # Encrypt the padded plaintext
    ciphertext = aes.encrypt(padded_plaintext)
    
    # Concatenate IV and ciphertext as bytes
    encrypted_data = iv + ciphertext
    
    return encrypted_data


def receive_input(): 
    while True: 
        print('')
        text = input("Type to send: ")
        text_bytes = text.encode('utf-8')
        if text == 'exit()':
            os._exit(0)    
        encrypted_text = encrypt_with_aes_cbc(preshared_secret_key, text_bytes)
        send_msg(encrypted_text)

def send_msg(text):
    dstip = '127.0.0.1'
    ip_part = IP(dst=dstip)/ICMP(type=47)/Raw(load=text)
    try:
        send(ip_part, iface='eth0')
        print("Message sent successfully.")
    except Exception as e:
        print(f"Error sending message: {e}")

def main():
    receive_input()

if __name__ == "__main__":
    main()
