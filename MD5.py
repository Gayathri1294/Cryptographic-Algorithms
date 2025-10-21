from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
message = input("Enter your message: ").encode()
md5_hash = hashlib.md5(message).digest()
print("\n MD5 Hash of Original Message:", md5_hash.hex())
signature = private_key.sign(
    md5_hash,
    padding.PKCS1v15(),
    hashes.MD5()
)
print("\n Digital Signature Generated (Hex):", signature.hex()[:60] + "...")  # shortened for display
print("\n--- Receiver Side Verification ---")
received_message = input("Enter the received message for verification: ").encode()
received_hash = hashlib.md5(received_message).digest()
try:
    public_key.verify(
        signature,
        received_hash,
        padding.PKCS1v15(),
        hashes.MD5()
    )
    print("\n✅ Message is Authentic — No Tampering Detected.")
except Exception:
    print("\n❌ Tampering Detected! Message integrity failed.")