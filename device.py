import socket
from rsa_keys import encrypt_message, decrypt_message, load_private_key, load_public_key
from logger import logger
import os
import tqdm
logger.info("Device started")

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))
    logger.info("Connected to server")
except Exception as e:
    logger.exception("Failed to connect to server")
    raise

# Load keys
private_key = load_private_key("keys/device_private_key.pem")
server_public_key = load_public_key("keys/server_public_key.pem")

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





send_encrypted_file(client, "a.jpeg", server_public_key)
client.close()
logger.info("Device socket closed")
