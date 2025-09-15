def rc4_init(key: bytes):
    """Key Scheduling Algorithm (KSA)"""
    key_length = len(key)
    S = list(range(256)) 
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i] 
    return S


def rc4_generate_keystream(S, length):
    """Pseudo-Random Generation Algorithm (PRGA)"""
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i] 
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream


def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt/Decrypt using RC4"""
    S = rc4_init(key)  
    keystream = rc4_generate_keystream(S, len(data))
    return bytes([d ^ k for d, k in zip(data, keystream)])

if __name__ == "__main__":
    key = b"secretkey"
    plaintext = b"Hello RC4 Stream Cipher!"

    # Encrypt
    ciphertext = rc4_encrypt(key, plaintext)
    print("Plaintext:", plaintext)
    print("Ciphertext (hex):", ciphertext.hex())

    # Decrypt (same function)
    decrypted = rc4_encrypt(key, ciphertext)
    print("Decrypted:", decrypted)
