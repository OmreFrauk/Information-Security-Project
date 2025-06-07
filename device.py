import socket
from rsa_keys import encrypt_message, decrypt_message, load_private_key, load_public_key
from logger import logger
import os
import tqdm
import json
from ca_cert import create_signed_certificate, validate_certificate

logger.info("Device started")
# Load keys
private_key = load_private_key("keys/device_private_key.pem")
server_public_key = load_public_key("keys/server_public_key.pem")
device_public_key = load_public_key("keys/device_public_key.pem")


try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))
    logger.info("Connected to server")
except Exception as e:
    logger.exception("Failed to connect to server")
    raise


def generate_certificate(path="certificates/device_certificate.json", device_public_key=device_public_key):
    if os.path.exists(path):
        logger.info(f"Certificate file already exists: {path}")
        return
    logger.info("Generating certificate")

    certificate = create_signed_certificate("device", device_public_key)
    with open(path, "w") as f:
        json.dump(certificate, f)
    logger.info(f"Certificate saved to {path}")

def send_certificate(client_socket, certificate_path):
    try:
        with open(certificate_path, "r") as f:
            certificate = json.load(f)
        client_socket.sendall(b"<CERT>")
        logger.info("Sent header: CERT")
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

def send_encrypted_text(client_socket,message: str, server_public_key):
    try:
        client_socket.sendall(b"<TEXT>")
        logger.info("Sent header: TEXT")

        logger.info(f"Original message: {message}")
        encrypted_message = encrypt_message(message, server_public_key)
        logger.info(f"Encrypted message length: {len(encrypted_message)}")
        
        client_socket.sendall(encrypted_message)
        logger.info("Sent encrypted message")
        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
        
        
    except Exception as e:
        logger.exception("Failed to send text message")
# Decrypt response

def send_encrypted_file(client_socket, file_path: str, server_public_key):
    try:
        client_socket.sendall(b"<FILE>")
        logger.info("Sent header: FILE")

        file_name = os.path.basename(file_path)
        encrypted_file_name = encrypt_message(file_name, server_public_key)
        client_socket.sendall(encrypted_file_name)
        logger.info(f"Sent file name: {file_name}")

        file_size = os.path.getsize(file_path)
        encrypted_file_size = encrypt_message(str(file_size), server_public_key)
        client_socket.sendall(encrypted_file_size)
        logger.info(f"File size: {file_size}")

        with open(file_path, "rb") as file:
            total_chunks = file_size // 190 + (1 if file_size % 190 != 0 else 0)
            progress_bar = tqdm.tqdm(total=total_chunks, unit="chunk", desc="Sending file")

            while True:
                chunk = file.read(190)
                if not chunk:
                    break
                encrypted_chunk = encrypt_message(chunk, server_public_key)
                client_socket.sendall(encrypted_chunk)
                progress_bar.update(1)

            progress_bar.close()
            logger.info("File sent successfully")

        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")

    except Exception as e:
        logger.exception("Failed to send file")
        raise e

def send_end_of_file(client_socket):
    try:
        client_socket.sendall(b"<ENDD>")
        logger.info("Sent header: END")
    except Exception as e:
        logger.exception("Failed to send end of file")
        raise e
    
generate_certificate()

send_certificate(client, "certificates/device_certificate.json")

send_encrypted_text(client, "Hello, server!", server_public_key)

#send_end_of_file(client)
client.close()
logger.info("Device socket closed")
