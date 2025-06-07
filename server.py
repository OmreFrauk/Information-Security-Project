import socket
from rsa_keys import decrypt_message, encrypt_message, load_private_key, load_public_key
from logger import logger

logger.info("Server starting")

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

# Load keys
server_private_key = load_private_key("keys/server_private_key.pem")
device_public_key = load_public_key("keys/device_public_key.pem")

# Setup server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen(1)
logger.info("Server listening on port 9999")

client, addr = server.accept()
logger.info(f"Accepted connection from {addr}")

# Receive encrypted message
encrypted_message = recv_exact(client, 256)

# Decrypt message
try:
    decrypted_message = decrypt_message(encrypted_message, server_private_key)
    logger.info(f"Decrypted message from device: {decrypted_message}")
except Exception as e:
    logger.exception("Failed to decrypt incoming message")

# Send response
response = f"Received your message: {decrypted_message}".encode()
logger.info("Encrypting response to device")
encrypted_response = encrypt_message(response, device_public_key)
client.sendall(encrypted_response)
logger.info("Encrypted response sent to device")

client.close()
server.close()
logger.info("Server shut down")
