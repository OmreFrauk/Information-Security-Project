import socket
from rsa_keys import encrypt_message, decrypt_message, load_private_key, load_public_key
from logger import logger

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

# Encrypt and send message
message = b"Hello, server!"
logger.info(f"Encrypting message: {message}")
encrypted_message = encrypt_message(message, server_public_key)

logger.info("Sending encrypted message to server")
client.sendall(encrypted_message)

# Receive encrypted response
logger.info("Waiting for response from server")
response = client.recv(256)
logger.info("Encrypted response received")

# Decrypt response
try:
    decrypted_response = decrypt_message(response, private_key)
    logger.info(f"Decrypted server response: {decrypted_response}")
except Exception as e:
    logger.exception("Failed to decrypt server response")

client.close()
logger.info("Device socket closed")
