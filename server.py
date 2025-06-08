import socket
from rsa_keys import decrypt_message, encrypt_message, load_private_key, load_public_key, derive_keys
from logger import logger
from tqdm import tqdm
from ca_cert import validate_certificate
import json
import os
from ca_cert import create_signed_certificate, send_certificate


logger.info("Server starting")

NONCE_DEVICE = None
NONCE_SERVER = None
MASTER_SECRET = None
DERIVED_KEYS = None
# Load keys
server_private_key = load_private_key("keys/server_private_key.pem")
device_public_key = load_public_key("keys/device_public_key.pem")
ca_public_key = load_public_key("keys/ca_public_key.pem")
server_public_key = load_public_key("keys/server_public_key.pem")

# Setup server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen(1)
logger.info("Server listening on port 9999")

client, addr = server.accept()
logger.info(f"Accepted connection from {addr}")


def recv_exact(sock, size):
    logger.info(f"Receiving exactly {size} bytes...")
    data = b""
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            logger.warning("Connection interrupted during receive")
            break
        data += packet
    logger.info(f"Received {len(data)} bytes successfully")
    return data

def recv_certificate(client_socket):
    try:
        logger.info("Receiving certificate header (length)...")
        length_bytes = recv_exact(client_socket, 4)
        logger.info(f"Length bytes (raw): {length_bytes.hex()}")  # Bu çok yardımcı olur
        total_length = int.from_bytes(length_bytes, byteorder="big")

        logger.info(f"Expecting certificate of {total_length} bytes")
        cert_data = recv_exact(client_socket, total_length)

        cert_bundle = json.loads(cert_data.decode())
        logger.info("Received certificate from client")
        ack = encrypt_message("CERT_RECEIVED", device_public_key)
        client_socket.sendall(ack)
        logger.info("Sent acknowledgement")

        return cert_bundle

    except Exception as e:
        logger.exception("Failed to receive or validate certificate.")
        return None
def generate_certificate(path="certificates/server_certificate.json", device_public_key=server_public_key):
    if os.path.exists(path):
        logger.info(f"Certificate file already exists: {path}")
        return
    logger.info("Generating certificate")

    certificate = create_signed_certificate("device", device_public_key)
    with open(path, "w") as f:
        json.dump(certificate, f)
    logger.info(f"Certificate saved to {path}")

def send_hello(client_socket):
    global NONCE_SERVER
    try:
        client_socket.sendall(b"<HELO>")
        logger.info("Sent header: HELLO")
        send_certificate(client_socket, "certificates/server_certificate.json", private_key=server_private_key)
        
        NONCE_SERVER = os.urandom(16)
        client_socket.sendall(NONCE_SERVER)
        logger.info(f"Sent nonce: {NONCE_SERVER}")
        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, server_private_key)
        logger.info(f"Device acknowledgement: {ack_msg}")
    
    except Exception as e:
        logger.exception("Failed to send hello")
        raise e



try:
    while True:
        header = recv_exact(client, 6)
        logger.info(f"Received header: {header}")

        if header == b"<TEXT>":
            logger.info("Expecting text message")
            encrypted_message = recv_exact(client, 256)
            decrypted_message = decrypt_message(encrypted_message, server_private_key)
            logger.info(f"Decrypted message: {decrypted_message}")

            ack = encrypt_message("TEXT_RECEIVED", device_public_key)
            client.sendall(ack)
            logger.info("Sent acknowledgement")

        elif header == b"<FILE>":
            logger.info("Expecting file")
            encrypted_file_name = recv_exact(client, 256)
            file_name = decrypt_message(encrypted_file_name, server_private_key)
            logger.info(f"Received file name: {file_name}")

            encrypted_file_size = recv_exact(client, 256)
            file_size = int(decrypt_message(encrypted_file_size, server_private_key))
            logger.info(f"Received file size: {file_size}")
            
            total_chunks = file_size // 190 + (1 if file_size % 190 != 0 else 0)
            progress = tqdm(total=total_chunks, unit="chunk", unit_scale=True, unit_divisor=1000, desc="Receiving file")
            with open(file_name, "wb") as file:
                for _ in range(total_chunks):
                    encrypted_chunk = recv_exact(client, 256)
                    decrypt_chunk = decrypt_message(encrypted_chunk, server_private_key)
                    file.write(decrypt_chunk)
                    progress.update(1)
            progress.close()
            logger.info("File received successfully")
            ack = encrypt_message("FILE_RECEIVED", device_public_key)
            client.sendall(ack)
            logger.info("Sent acknowledgement")

        elif header == b"<CERT>":
            logger.info("Expecting certificate")
            certificate = recv_certificate(client)
            if certificate:
                logger.info("Certificate received successfully")
                
                if validate_certificate(certificate, ca_public_key):
                    logger.info("Certificate validated successfully")
                else:
                    logger.warning("Certificate validation failed")
                    client.close()
                    server.close()

            else:
                logger.warning("Certificate validation failed")
                client.close()
                server.close()
                break

        elif header == b"<HELO>":
            logger.info("Expecting hello")
            certificate = recv_certificate(client)
            if validate_certificate(certificate, ca_public_key):
                logger.info("Certificate validated successfully")
            else:
                logger.warning("Certificate validation failed")
                client.close()
                server.close()
                break
            NONCE_DEVICE = recv_exact(client, 16)
            logger.info(f"Received nonce: {NONCE_DEVICE}")
            
            ack = encrypt_message("HELLO_RECEIVED", device_public_key)
            client.sendall(ack)
            logger.info("Sent acknowledgement")
            send_hello(client)


        elif header == b"<PREM>":
            try:
                logger.info("Expecting pre-master secret")
                encrypted_pre_master_secret = recv_exact(client, 256)
                pre_master_secret = decrypt_message(encrypted_pre_master_secret, server_private_key, decode=False)
                logger.info(f"Received pre-master secret: {pre_master_secret}")
                MASTER_SECRET = pre_master_secret
                ack = encrypt_message("PREM_RECEIVED", device_public_key)
                client.sendall(ack)
                logger.info("Sent acknowledgement")
                DERIVED_KEYS = derive_keys(MASTER_SECRET, NONCE_DEVICE, NONCE_SERVER)
                logger.info(f"Derived keys: {DERIVED_KEYS}")
            except Exception as e:
                logger.exception("Failed to receive pre-master secret")
                raise e

        elif header == b"<ENDD>":
            logger.info("Received end of file")
            client.close()
            server.close()
            logger.info("Server closed")
            break

        else:
            logger.error("Invalid header received")
            client.close()
            server.close()
            break
except Exception as e:
    logger.exception("An error occurred during communication.")

finally:
    client.close()
    server.close()
    logger.info("Server shut down")

