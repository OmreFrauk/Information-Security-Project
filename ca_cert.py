from rsa_keys import load_private_key, load_public_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization
import json
from logger import logger
from rsa_keys import decrypt_message
import base64
import os 

ca_private_key = load_private_key("keys/ca_private_key.pem")
ca_public_key = load_public_key("keys/ca_public_key.pem")

def send_certificate(client_socket, certificate_path, private_key):
    try:
        with open(certificate_path, "r") as f:
            certificate = json.load(f)
    
        client_socket.sendall(len(json.dumps(certificate)).to_bytes(4, byteorder="big"))
        logger.info(f"Sent certificate length: {len(json.dumps(certificate))}")
        client_socket.sendall(json.dumps(certificate).encode())
        logger.info("Sent certificate")
        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
    except Exception as e:  
        logger.exception("Failed to send certificate")
        raise e


def create_signed_certificate(common_name: str, client_public_key_pem: bytes) -> dict:
    device_public_key = client_public_key_pem.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    certificate_data = {
        "common_name": common_name,
        "public_key": device_public_key.decode()
    }
    message = (common_name + device_public_key.decode()).encode()
    signature = ca_private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return {
        "certificate": certificate_data,
        "signature": base64.b64encode(signature).decode()
    }
def validate_certificate(cert_bundle: dict, ca_public_key: rsa.RSAPublicKey) -> bool:
    cert_data = cert_bundle["certificate"]
    signature = cert_bundle["signature"]

    message = (cert_data["common_name"] + cert_data["public_key"]).encode()

    try:
        ca_public_key.verify(
            signature if isinstance(signature, bytes) else base64.b64decode(signature),
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:

        return False

def create_signed_image(image_path: str, private_key) -> dict:
    try:
        with open(image_path, "rb") as f:
            image_data = f.read()
        filename = os.path.basename(image_path)
        signature = private_key.sign(
            image_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH

            ),
            hashes.SHA256()
        )
        payload = {
            "filename": filename,
            "image_data": base64.b64encode(image_data).decode(),
            "signature": base64.b64encode(signature).decode()
        }
        return json.dumps(payload).encode()
    except Exception as e:
        logger.exception("Failed to create image certificate")
        raise e


def verify_image(payload_bytes: bytes, sender_public_key) -> bool:
    try:
        payload = json.loads(payload_bytes)
        filename = payload["filename"]
        image_data = base64.b64decode(payload["image_data"])
        signature = base64.b64decode(payload["signature"])
        sender_public_key.verify(
            signature,
            image_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True 
    except Exception as e:
        logger.exception("Failed to verify image")
        return False