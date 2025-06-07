from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
from logger import logger

def generate_key_pair():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key from private key
    public_key = private_key.public_key()
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def save_keys(private_pem, public_pem, private_file="private_key.pem", public_file="public_key.pem"):
    # Save private key to file
    with open(private_file, "wb") as f:
        f.write(private_pem)
    
    # Save public key to file
    with open(public_file, "wb") as f:
        f.write(public_pem)

def load_private_key(private_file="private_key.pem"):
    with open(private_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(public_file="public_key.pem"):
    with open(public_file, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(message, public_key):
    if isinstance(message, str):
        message = message.encode()

    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_message(encrypted_message: bytes, private_key): 

    if len(encrypted_message) != 256:
        raise ValueError(f"Encrypted message length is invalid. Got {len(encrypted_message)} bytes, expected 256 bytes.")
    
    # Decrypt the message
    try:
        decrypted = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

