import socket
from rsa_keys import decrypt_message, encrypt_message, load_private_key, load_public_key
from logger import logger
from tqdm import tqdm

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

elif header == b"<END>":
    logger.info("Received end of file")
    client.close()
    server.close()
    logger.info("Server closed")

else:
    logger.error("Invalid header received")
    client.close()
    server.close()