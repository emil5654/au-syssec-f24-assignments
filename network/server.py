from scapy.all import sniff, ICMP, Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

preshared_secret_key = '8efbcfc8668336a12c7fd5f81e7bc276fcf46d87a686bd9605882307a99ff807'

def decrypt_with_aes_cbc(key, encrypted_data):
    # Extract IV from the encrypted data

    key = bytes.fromhex(key)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    # Create an AES cipher object in CBC mode
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    
    # Decrypt the ciphertext
    decrypted_data = aes.decrypt(ciphertext)

    # Unpad the decrypted data
    plaintext = unpad(decrypted_data, AES.block_size)

    return plaintext

def handle_icmp_message(packet):
    if ICMP in packet and Raw in packet:
        icmp_packet = packet[ICMP]
        raw_payload = packet[Raw].load
        
        if icmp_packet.type == 47:  # Check if it's your custom ICMP type
            # Decrypt the payload
            decrypted_payload = decrypt_with_aes_cbc(preshared_secret_key, raw_payload)
            
            # Print the decrypted payload
            print("Received message:", decrypted_payload.decode('utf-8'))

def main():
    # Server information
    dstip = '127.0.0.1'

    print(f"Server listening on {dstip}:")
    try:
        sniff(iface="lo", prn=handle_icmp_message)
    except Exception as e:
        print(f'\nError: Could not start sniffing for ICMP packets: {e}')

if __name__ == "__main__":
    main()
