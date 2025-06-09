import socket
from rsa_keys import encrypt_message, decrypt_message, load_private_key, load_public_key
from logger import logger
import os
import tqdm
import json
from ca_cert import create_signed_certificate, validate_certificate, send_certificate, create_signed_image
from rsa_keys import derive_keys, encrypt_aes_with_hmac

NONCE_DEVICE = os.urandom(16)
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
    

def send_hello(client_socket):

    try:
        client_socket.sendall(b"<HELO>")
        logger.info("Sent header: HELLO")
        
        send_certificate(client_socket, "certificates/device_certificate.json", private_key)
        nonce_device =  NONCE_DEVICE
        client_socket.sendall(nonce_device)
        logger.info(f"Sent nonce: {nonce_device}")
        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
        return nonce_device
    except Exception as e:
        logger.exception("Failed to send hello")
        raise e

def recv_hello(client_socket):
    try:
        header = client_socket.recv(6)
        if header == b"<HELO>":
            logger.info("Received header: HELLO")
            
            logger.info("Recieving server certificate length..")
            certificate_length_bytes = client_socket.recv(4)
            certificate_length = int.from_bytes(certificate_length_bytes,byteorder="big")
            logger.info(f"Expecting server cert length {certificate_length} bytes.")

            cert_data = client_socket.recv(certificate_length)
            cert_json = json.loads(cert_data.decode())
            logger.info("Received server certificate: ")
            ack = encrypt_message("CERT_RECEIVED", server_public_key)
            client_socket.sendall(ack)
            logger.info("Sent acknowledgement")

            ca_public_key = load_public_key("keys/ca_public_key.pem")
            if validate_certificate(cert_json, ca_public_key):
                logger.info("Server certificate validated successfully")
            else:
                logger.warning("Server certificate validation failed")
                client_socket.close()
                raise Exception("Server certificate validation failed")
            
            logger.info("Recieving server nonce..")
            nonce_server = client_socket.recv(16)
            logger.info(f"Received nonce: {nonce_server}")
            ack = encrypt_message("NONCE_RECEIVED", server_public_key)
            client_socket.sendall(ack)
            logger.info("Sent acknowledgement")

            return cert_json,nonce_server
    except Exception as e:
        logger.exception("Failed to receive hello")
        raise e

def send_pre_master_secret(client_socket, server_public_key):
    try:
        pre_master_secret = os.urandom(32) #256 bits secret

        encrypted_pre_master_secret = encrypt_message(pre_master_secret, server_public_key)
        client_socket.sendall(b"<PREM>") #header
        client_socket.sendall(len(encrypted_pre_master_secret).to_bytes(4, byteorder="big"))
        client_socket.sendall(encrypted_pre_master_secret)
        logger.info("Sent pre-master secret")

        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
        return pre_master_secret
    except Exception as e:
        logger.exception("Failed to send pre-master secret")
        raise e

def send_secure_text(client_socket, message: str, keys):
    try:
        client_socket.sendall(b"<SECX>")
        logger.info("Sent header: SECX")
        
        sym_key = keys["client_enc_key"]
        mac_key = keys["client_mac_key"]
        iv = keys["iv"]

        encrypted_message = encrypt_aes_with_hmac(message.encode(), sym_key, mac_key, iv)
        client_socket.sendall(len(encrypted_message).to_bytes(4, byteorder="big"))
        client_socket.sendall(encrypted_message)
        logger.info("Sent encrypted message")

        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
    except Exception as e:
        logger.exception("Failed to send secure text")
        raise e

def send_secure_image(client_socket, image_path: str, keys):
    try:

        payload = create_signed_image(image_path, private_key)
        encrypted_payload = encrypt_aes_with_hmac(payload, keys["client_enc_key"],keys["client_mac_key"],keys["iv"])
        
        client_socket.sendall(b"<IMGX>")
        logger.info("Sent header: IMGX")
        client_socket.sendall(len(encrypted_payload).to_bytes(4, byteorder="big"))
        client_socket.sendall(encrypted_payload)
        logger.info(f"Sent image payload length: {len(encrypted_payload)}")

        ack = client_socket.recv(256)
        ack_msg = decrypt_message(ack, private_key)
        logger.info(f"Server acknowledgement: {ack_msg}")
    except Exception as e:
        logger.exception("Failed to send secure image")
        raise e
        
        
if __name__ == "__main__":

    nonce_device = send_hello(client)
    cert_json,nonce_server = recv_hello(client)
    pre_master_secret = send_pre_master_secret(client, server_public_key)

    DERIVED_KEYS = derive_keys(pre_master_secret, nonce_device, nonce_server)
    logger.info(f"Derived keys: {DERIVED_KEYS}")

    send_secure_image(client, "images/test.mp4", DERIVED_KEYS)

    send_end_of_file(client)
    client.close()
    logger.info("Device socket closed")
