# Information-Security-Project
# 🔐 Secure Communication Protocol

## 📌 Project Overview

This project implements a simplified **secure communication protocol** between a **device** and a **server** using **custom cryptographic primitives** over raw TCP sockets.

The system supports:
- Public Key Infrastructure (PKI)
- Secure Handshake with certificate & nonce exchange
- Shared master secret derivation and key expansion (HKDF)
- Encrypted and authenticated text and image communication
- Digital signature verification
- Logging and acknowledgement messages
- Bonus:
- End to end encrypted video transfer

> ⚠️ No SSL/TLS libraries like OpenSSL were used. All cryptographic mechanisms were implemented manually using `cryptography`.

---
## How to Run
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate
pip install -r requirements.txt
```
## Run Server
```bash
python3 server.py
```
## Run Device
```bash
python3 device.py
```

## 🧰 Technologies Used

| Component     | Purpose                                      |
|---------------|----------------------------------------------|
| Python 3.x    | Programming language                         |
| socket        | TCP-based communication                      |
| cryptography  | Key generation, RSA, AES, HMAC, HKDF         |
| tqdm          | Progress bar for file transfers              |
| logging       | Logging messages with timestamps             |
| json / base64 | Structured data and image encoding           |

---

## 📂 Project Structure
```text
project/
├── server.py
├── device.py
├── rsa_keys.py
├── ca_cert.py
├── logger.py
│
├── keys/
│ ├── ca_private_key.pem
│ ├── ca_public_key.pem
│ ├── device_private_key.pem
│ ├── device_public_key.pem
│ ├── server_private_key.pem
│ ├── server_public_key.pem
│
├── certificates/
│ ├── device_certificate.json
│ ├── server_certificate.json
│
├── images/
│ └── test.mp4
│
├── received_images/
│ └── saved files
│
├── requirements.txt
└── README.md

```
---

## 🔐 Security Features

### 1. 🔑 Public Key Generation & Certification
- RSA-2048 key pairs generated for CA, Device, and Server.
- Custom Certificate Authority (`ca_cert.py`) signs public keys.
- Certificates include `common_name`, PEM-encoded public key, and signature.

### 2. 🤝 Handshake Protocol
- `<HELO>` headers exchanged.
- Device and Server send:
  - Their certificate
  - A 16-byte random **nonce**
- Each party verifies the received certificate using CA's public key.

### 3. 🔐 Key Exchange & Derivation
- Device sends 32-byte pre-master secret encrypted with server's public key.
- Both derive a **master secret** and then apply **HKDF** to produce:
  - 2 symmetric encryption keys (client → server, server → client)
  - 2 MAC keys
  - 1 IV

### 4. ✉️ Encrypted Text Communication
- `<SECX>` header marks secure message.
- AES-CBC + HMAC-SHA256 used for confidentiality & integrity.
- Encrypted message + HMAC sent with length prefix.
- Server verifies MAC and decrypts text.

### 5. 🖼 Encrypted Image Transmission
- Image is base64-encoded and digitally signed (RSA-PSS).
- Image + signature is AES-encrypted and sent as `<IMGX>`.
- Server verifies the signature and stores the image if valid.
 
### 6. End-to-End Encrypted Video Transfer
- Video is base64-encoded and digitally signed (RSA-PSS).
- Video + signature is AES-encrypted and sent as `<IMGX>`.
- Server verifies the signature and stores the image if valid
---

## 🔁 Protocol Flow
```markdown
```text
Device              ↔            Server
  |  <HELO> + cert  →            |
  |                ←  <HELO> + cert
  |  Nonce (16B)    →            |
  |                ←  Nonce (16B)
  |  <PREM> + RSA(pre-master)   →
  |                ←  ACK
  |  derive shared keys         |
  |  <SECX> encrypted text      →
  |                ←  ACK
  |  <IMGX> encrypted image     →
  |                ←  ACK
  |  <ENDD>                     →
```
