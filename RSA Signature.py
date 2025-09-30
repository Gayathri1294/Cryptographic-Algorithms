from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
# --- Key Generation ---
def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
# --- Signing a Message ---
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pss.new(key).sign(h)
    return signature
# --- Verifying a Signature ---
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pss.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys(bits=2048)
    message = "This is a highly secure message using RSA-PSS."
    signature = sign_message(message, private_key)
    print("\nSignature (hex):", signature.hex())
    valid = verify_signature(message, signature, public_key)
    print("\nSignature valid?", valid)
