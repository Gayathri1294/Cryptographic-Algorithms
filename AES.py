from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_ctr(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)
    # Store nonce + ciphertext
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

def decrypt_ctr(b64data: str, key: bytes):
    raw = base64.b64decode(b64data)
    nonce, ciphertext = raw[:8], raw[8:]   # AES-CTR default nonce is 8 bytes
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Example
if _name_ == "_main_":
    key = get_random_bytes(16)  # 128-bit AES key
    text = b"Hello AES-CTR mode, no padding needed!"

    enc = encrypt_ctr(text, key)
    print("Encrypted:", enc)

    dec = decrypt_ctr(enc, key)
    print("Decrypted:", dec.decode('utf-8'))
