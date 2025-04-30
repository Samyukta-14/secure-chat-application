# 🔐 Secure Chat Application

This project was developed as part of **CY6740: Network Security** at Northeastern University. It demonstrates a secure, terminal-based chat system built using modern cryptographic techniques in Python.

---

## 📌 Overview

The application enables secure communication between users by integrating:

- **SRP (Secure Remote Password protocol)** for password-based authentication
- **ECDH (Elliptic Curve Diffie-Hellman)** for key exchange
- **AES-GCM (Galois/Counter Mode)** for message confidentiality and integrity
- A socket-based client-server model with encrypted peer-to-peer messaging

---

## 🚀 Features

-  Secure login (SRP - no password transmission)
-  Encrypted messaging (ECDH key exchange + AES-GCM)
-  Real-time chat via TCP sockets
-  Online user listing
-  Message rate limiting (5 messages per 10 seconds)
-  Simple command-based interface

---

## 🧪 Test Users

You can log in using the following credentials (preloaded in `server.py`):

| Username | Password      |
|----------|---------------|
| alice    | @lice_$       |
| bob      | B0b@#redS0x   |
| charlie  | ilovechristmas|

These users have SRP verifiers already defined in the server logic.

---

## 🛠️ Setup Instructions

1. Clone the Repository
```
git clone https://github.com/Samyukta-14/secure-chat-application.git
cd secure-chat-application
```
2. Install Dependencies
```
pip install -r requirements.txt
```
## ▶️ How to Run

Start the Server
```
python src/server.py
```
Start the Client
```
python src/client.py
```
Then log in with one of the test usernames above.

⌨️ Client Commands
|      Commands      |              Description                  |
|--------------------|-------------------------------------------|
| connect <username> | Initiate secure chat with another user    |
| accept <username>  | Accept a chat request from another user   |
| send <message>     | Send an encrypted message in current chat |
| back               | Exit the current chat session             |
| list               | List all online users                     |
| logout             | Logout from the server                    |
| quit               | Exit the client application               |

⚠️ You must connect/accept before sending messages.

## 🔐 Security Details
- Authentication: Uses SRP 
- Key Exchange: ECDH 
- Encryption: AES-256 in GCM mode 
- Session Keys: Derived from ECDH using HKDF (SHA256)
- Rate Limiting: Limits users to 5 messages per 10 seconds

All cryptographic operations are performed using standard libraries.

## 📁 File Structure
```
secure-chat-application/
├── src/
│   ├── client.py
│   └── server.py
├── config/
│   └── config.txt
├── scripts/
│   └── salt-verifier-generator.py
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```
## 👥 Contributors
- Samyukta Kurikala (https://github.com/Samyukta-14)
- Tanmay Sharma (https://github.com/d3adp0et)
