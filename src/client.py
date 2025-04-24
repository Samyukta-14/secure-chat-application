import socket
import threading
import json
import base64
import os
import time

from srp import User, SHA256, NG_2048
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

session_keys = {}

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    serialized_pub = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, serialized_pub

def derive_key(private_key, peer_public_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat-session'
    ).derive(shared_secret)
    return derived

def encrypt_message(key, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    combined = iv + encryptor.tag + ciphertext
    encoded = base64.b64encode(combined).decode()
    return encoded

def decrypt_message(key, ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    plaintext = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    return plaintext

def receive_messages(sock, username, private_key):
    while True:
        try:
            msg = sock.recv(4096).decode('utf-8')
            if not msg:
                break
            data = json.loads(msg)
            sender = data.get("sender")
            msg_type = data.get("type")

            if msg_type == "chat_request":
                print(f"\n[!] Chat request from {sender}. Accept with: accept {sender}")
                session_keys[sender] = {
                    "peer_pub": data["public_key"],
                    "accepted": False
                }

            elif msg_type == "chat_accept":
                peer_pub = data["public_key"].encode()
                key = derive_key(private_key, peer_pub)
                session_keys[sender] = key
                print(f"\n[*] Chat session with {sender} established.")

            elif msg_type == "secure_message":
                if sender in session_keys:
                    key = session_keys[sender]
                    plaintext = decrypt_message(key, data["ciphertext"])
                    print(f"\n[{sender}] {plaintext}")
                else:
                    print(f"\n[!] Received secure message from {sender}, but no session key exists.")

            elif msg_type == "command_response":
                print(f"\n[SERVER] {data['message']}")

            elif msg_type == "chat_ended":
                print(f"\n[INFO] {data['message']}")

            else:
                print(f"\n[{sender}] {data.get('message', '[No message]')}")

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

def start_client():
    host = "127.0.0.1"
    port = 5555

    username = input("Username: ").strip()

    attempts = 0
    MAX_ATTEMPTS = 5

    while attempts < MAX_ATTEMPTS:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
        except:
            print("Unable to connect to server.")
            return

        password = input("Password: ").strip()
        srp_client = User(username, password, hash_alg=SHA256, ng_type=NG_2048)
        uname, A = srp_client.start_authentication()

        try:
            client.send(json.dumps({
                "type": "auth_start",
                "username": uname,
                "A": A.hex()
            }).encode())

            challenge = json.loads(client.recv(4096).decode())
            if challenge.get("type") != "auth_challenge":
                print("[!] Server refused login:", challenge.get("message"))
                client.close()
                attempts += 1
                continue

            salt = bytes.fromhex(challenge["salt"])
            B = bytes.fromhex(challenge["B"])
            M = srp_client.process_challenge(salt, B)

            client.send(json.dumps({
                "type": "auth_proof",
                "M": M.hex()
            }).encode())

            auth_resp = json.loads(client.recv(4096).decode())
            if auth_resp.get("type") != "auth_success":
                print("[!] Authentication failed:", auth_resp.get("message"))
                client.close()
                attempts += 1
                continue

            received_hamk = bytes.fromhex(auth_resp["HAMK"])
            if received_hamk == srp_client.H_AMK:
                session_key = srp_client.K
                print(f"[+] Authenticated. Welcome!")
                print("""
                Available Commands:
                ----------------------------
                connect <username>    - Initiate secure chat with a user
                accept <username>     - Accept an incoming chat request
                send <message>        - Send an encrypted message to the connected user
                back                  - Leave the current chat session
                list                  - List online users
                logout                - Logout from the server
                quit                  - Exit the application

                Note:
                - You must connect or accept before using send.
                - Messages are encrypted using ECDH + AES-GCM.
                - Rate limit: 5 messages per 10 seconds.
                ----------------------------
                """)

                break
            else:
                print("[!] HAMK mismatch. Authentication failed.")
                client.close()
                attempts += 1
        except Exception as e:
            print(f"[!] Error during login: {e}")
            client.close()
            attempts += 1
    else:
        print("[!] Too many failed login attempts. Exiting.")
        return

    private_key, public_key = generate_ecdh_keys()
    threading.Thread(target=receive_messages, args=(client, username, private_key), daemon=True).start()

    current_chat = None
    try:
        while True:
            cmd = input(f"{username}: ").strip()

            if cmd.startswith("connect "):
                target = cmd.split(" ", 1)[1].strip()
                current_chat = target
                msg = json.dumps({
                    "sender": username,
                    "to": target,
                    "type": "chat_request",
                    "public_key": public_key.decode()
                })
                client.send(msg.encode('utf-8'))

            elif cmd.startswith("accept "):
                target = cmd.split(" ", 1)[1].strip()
                current_chat = target
                if target in session_keys and not isinstance(session_keys[target], bytes):
                    peer_pub = session_keys[target]["peer_pub"].encode()
                    key = derive_key(private_key, peer_pub)
                    session_keys[target] = key
                    msg = json.dumps({
                        "sender": username,
                        "to": target,
                        "type": "chat_accept",
                        "public_key": public_key.decode()
                    })
                    client.send(msg.encode('utf-8'))

            elif cmd.startswith("send "):
                if not current_chat:
                    print("[!] No active chat. Use connect or accept first.")
                    continue
                parts = cmd.split(" ", 1)
                message = parts[1] if len(parts) > 1 else ''
                if not message:
                    print("[!] No message to send.")
                    continue
                if current_chat not in session_keys:
                    print(f"[!] No session key with {current_chat}")
                    continue
                key = session_keys[current_chat]
                ciphertext = encrypt_message(key, message)
                msg = json.dumps({
                    "sender": username,
                    "to": current_chat,
                    "type": "secure_message",
                    "ciphertext": ciphertext
                })
                client.send(msg.encode('utf-8'))

            elif cmd == "back":
                if current_chat:
                    msg = json.dumps({
                        "sender": username,
                        "to": current_chat,
                        "type": "chat_ended",
                        "message": f"{username} has left the chat."
                    })
                    client.send(msg.encode('utf-8'))
                    print(f"[*] Exiting chat with {current_chat}")
                    current_chat = None
                else:
                    print("[!] No active chat to exit.")

            elif cmd == "list":
                msg = json.dumps({
                    "sender": username,
                    "to": "server",
                    "type": "command",
                    "message": "list"
                })
                client.send(msg.encode('utf-8'))

            elif cmd == "logout":
                print("[*] Logging out...")
                logout_msg = json.dumps({
                    "sender": username,
                    "to": "server",
                    "type": "logout"
                })
                try:
                    client.send(logout_msg.encode('utf-8'))
                except:
                    print("[!] Could not notify server.")
                session_keys.clear()
                current_chat = None
                client.close()
                print("[+] Logged out successfully.")
                break

            elif cmd == "quit":
                break
            else:
                print("[!] Unknown command. Use connect, accept, send, list, quit, back, logout")

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        try:
            client.close()
        except:
            pass
        print("Disconnected.")

if __name__ == "__main__":
    try:
        start_client()
    except KeyboardInterrupt:
        print("\nExiting... (KeyboardInterrupt)")