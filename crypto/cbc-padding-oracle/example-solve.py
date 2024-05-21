#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
from http.cookies import SimpleCookie
from flask import Flask, request, make_response, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
base_url = "http://127.0.0.1:5000"
#base_url = "https://cbc-rsa.syssec.dk:8000/"

def oracle(block):
    try:
        res = requests.get(f'{base_url}/quote/', cookies={'authtoken': block.hex()}, timeout=5)
        if "PKCS#7 padding is incorrect" in res.text or "Padding is incorrect." in res.text:
            return False
        else:
            print(res.text)
            return True
    except (ConnectionError) as e:
        print(f"Connection error: {e}, retrying...")
        return oracle(block)
    
def get_token():
    #The requests for getting the cookie
    res = requests.get(f'{base_url}/quote/')
    #extraticn the cipertext from the requests result from the cookie
    cipertext = res.cookies.get("authtoken")
    
    #Changing the cipertext to hex from 
    cipertext = bytes.fromhex(cipertext)
	
    return cipertext

def full_attack(iv, ct):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

def craft_ciphertext(desired_plaintext):

    desired_plaintext = pad(desired_plaintext, BLOCK_SIZE)
    blocks = [desired_plaintext[i:i+BLOCK_SIZE] for i in range(0, len(desired_plaintext), BLOCK_SIZE)]
    CT_n = get_random_bytes(16)
    result = b'' + CT_n
    for block in reversed(blocks):
        PT_n = single_block_attack(CT_n) #gets the zeroing_iv
        CT_n1 = bytes(a ^ b for a,b in zip(PT_n, block)) #xor zeroing_iv with the plain_text
        result = CT_n1 + result
        CT_n = CT_n1
    
    return result



def single_block_attack(block):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv+block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv+block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

def test_systems_security(base_url):    
    token = get_token()
   
    res = full_attack(token[:BLOCK_SIZE], token[BLOCK_SIZE:])
    plaintext = unpad(res, 16)
    print("Recovered plaintext:", plaintext)

    secret = res.split(b'"')[1]
    print("Secret:", secret)
    new_plain = "I should have used authenticated encryption because ..." + ' plain CBC is not secure!'
    new_plain_bytes = bytes(new_plain, 'utf-8')


    res = craft_ciphertext(new_plain_bytes)

    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': res.hex()} )

    print(res.text)

if __name__ == '__main__':
    
    test_systems_security(base_url)
