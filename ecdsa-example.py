import ecdsa
from hashlib import sha256

def generate_signing_key():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    return sk

def get_verifying_key(public_key):
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)
    return VerifyingKey


message = b"message"

sk = generate_signing_key()
print(f"signing key is {sk.to_string().hex()}")

verifying_key = sk.get_verifying_key()
print(f"verifing key is {verifying_key.to_string().hex()}")

signed_message = sk.sign(message)
print(f"signed message is {signed_message.hex()}")

print(f"message is verified true/false {verifying_key.verify(signed_message, message)}")

