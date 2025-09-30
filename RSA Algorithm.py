import random,secrets
from typing import Tuple
class RSA:
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    def is_prime(self, n: int, k: int = 128) -> bool:
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
def generate_large_prime(self) -> int:
 while True:
            num = secrets.randbits(self.key_size // 2)
            num |= (1 << (self.key_size // 2 - 1)) | 1
            if self.is_prime(num):
                return num
    def gcd(self, a: int, b: int) -> int:
        while b != 0:
            a, b = b, a % b
        return a
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    def mod_inverse(self, a: int, m: int) -> int:
        gcd, x, _ = self.extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse doesn't exist")
        return x % m
    # --- Key generation ---
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        print("Generating RSA keys...")
        p = self.generate_large_prime()
        q = self.generate_large_prime()
        while p == q:
            q = self.generate_large_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
while self.gcd(e, phi) != 1:
            e = secrets.randbelow(phi - 3) + 3
        d = self.mod_inverse(e, phi)
        self.public_key = (n, e)
        self.private_key = (n, d)
        return self.public_key, self.private_key
    def encrypt_string(self, text: str, public_key: Tuple[int, int] = None) -> list:
        if public_key is None:
            n, e = self.public_key
        else:
            n, e = public_key
        encrypted_blocks = []
        block_size = (n.bit_length() - 1) // 8  # max bytes per block
        for i in range(0, len(text), block_size):
            block = text[i:i + block_size]
            m_int = int.from_bytes(block.encode("utf-8"), "big")
            c_int = pow(m_int, e, n)
            encrypted_blocks.append(c_int)
        return encrypted_blocks
    def decrypt_string(self, encrypted_blocks: list, private_key: Tuple[int, int] = None) -> str:
        if private_key is None:
            n, d = self.private_key
        else:
            n, d = private_key
        decrypted_text = ""
        for block in encrypted_blocks:
            m_int = pow(block, d, n)
            m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
            decrypted_text += m_bytes.decode("utf-8", errors="ignore")
        return decrypted_text
def main():
    rsa = RSA(key_size=512)  
    public_key, private_key = rsa.generate_keys()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}\n")
    message = "Hello, RSA String Encryption!"
    print(f"Original message: {message}")
    encrypted_blocks = rsa.encrypt_string(message)
    print(f"Encrypted blocks: {encrypted_blocks}")
    decrypted_message = rsa.decrypt_string(encrypted_blocks)
    print(f"Decrypted message: {decrypted_message}")
if __name__ == "__main__":
    main()
