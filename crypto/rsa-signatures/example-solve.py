import base64
import json
import math
import secrets
import string
from urllib.parse import quote as url_quote
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key
import requests

import requests
import json
import base64

base_url = "http://127.0.0.1:5000"
#base_url = "https://cbc-rsa.syssec.dk:8001"
# Replace with the actual endpoint and parameters


def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str


def cookie_to_json(base64_as_str: str) -> str:
    """Decode json data stored in a cookie-friendly way using base64."""
    # Check that the input looks like base64 data
    assert all(char in (string.ascii_letters + string.digits + '-_=') for char in base64_as_str), \
            f"input '{base64_as_str}' is no valid base64"
    # decode the base64 data
    json_as_bytes = base64.b64decode(base64_as_str, altchars=b'-_')
    # b64decode returns bytes, we want string -> decode it
    json_as_str = json_as_bytes.decode()
    return json_as_str

# This should give you the public key details.
public_key_url = base_url + '/pk/'
response = requests.get(public_key_url)
public_key = response.json()  
n = public_key['N']
e = public_key['e']


# Step 1: Choose two messages m1 and m2
m1 = "random msg ".encode()

m = "You got a 12 because you are an excellent student! :)".encode()

# Step 2: Get the server to sign m1 and m2
response1 = requests.get(f'http://localhost:5000/sign_random_document_for_students/{m1.hex()}')
s1 = json.loads(response1.text)['signature']
s1 = int(s1, 16)
# Get the server's public key
response = requests.get('http://localhost:5000/pk/')
public_key = json.loads(response.text)
N = public_key['N']
e = public_key['e']
N = int(N)

m1 = int.from_bytes(m1, 'big')
m_int = int.from_bytes(m, 'big')

#calculation of m2 
#m2 = m/m1 mod N
m2 = m_int* pow(m1, -1, N) % N
m2_lengh = (m2.bit_length() + 7) // 8
m2_bytes = m2.to_bytes(m2_lengh, 'big')
m2 = m2_bytes

response2 = requests.get(f'http://localhost:5000/sign_random_document_for_students/{m2.hex()}')
s2 = json.loads(response2.text)['signature']
s2 = int(s2, 16)

# Step 3: Compute the new signature s
#obtain valid signature from s^e mod N = s
#s^e = s1 * s2
s_new = (s1 * s2) % N

signature = s_new.to_bytes(math.ceil(N.bit_length() / 8), 'big')

# Step 2: Pair the new message with the new signature
new_grade = {"msg": m.hex(), "signature": signature.hex()}

j = json.dumps(new_grade)
c = json_to_cookie(j)

response = requests.get('http://localhost:5000/quote/', cookies= {'grade': c})
print(response.text)
