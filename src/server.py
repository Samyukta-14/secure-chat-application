import socket
import threading
import json
import time
from collections import defaultdict, deque
from srp import Verifier, SHA256, NG_2048

clients = {}

# User database with precomputed SRP salt and verifier values
user_db = {
    'charlie': {
        'salt': bytes.fromhex('566370ba'),
        'verifier': bytes.fromhex('837667805a83332bd1fac8fff1bb5993440f480aaef792627f6411e912fc5c048feef6be987f93d0e6bc7d7effadd613cde861a7851264a5cb7efd14b9e0a59b0758db2205e63bc3daf005ba8aa4e5ae48a12794297bceb4c2856b130f9995cf53d76754cd1f2d7df7136588131ac088c850a9918c79cb301d23d1520dc951c23cfd92cae3af83c515c994042647932059c51185310eaffa60492148834bd74a07204a702f71d350239074a65cf8d561cdbba3af8602ca21f8fe331d9eac0f27a225fa6644d25b7daec868c8d3d6232d6e25aee0a2ac44262e52c39193633db8909e8714ed67dd4af3a63a30f4765e2d6ea3ddebaf3ba91f3a1a1712f13dffa6')
    },
    'alice': {
        'salt': bytes.fromhex('9f063e4e'),
        'verifier': bytes.fromhex('9a67951878244a19611c7d055c78c4536796619ba3baeb6912d1a3351126a8bc2dd7e70d4cc9ce8be48be0b84c9d2d8b4667a727ac6046d06f7ea5907d294a79543da5cbbef5df888fd281120eeb5b7797b06b97165068b138dcc38beb61a288808711d2e3d410409ca6e6415b97989dccae8d55aea7333663c920a31d84c2b8b362a4b41bf1f8040153310f788fc2572fcd11479d53d1413e384d64f7219007b7ffb96e12f924c09db33952a9884ac958126d78eda4d3fac558cd3b8cd29820fffd9bcdc2bd57bcecd85bdfce67ec23a469f1901fb99226f75fbfe5e96bda8876dd97447aa8e4cef7f7c64cd5df32276a8e66ff5876795b4a8ad73a514922b8')
    },
    'bob': {
        'salt': bytes.fromhex('9d5f58f1'),
        'verifier': bytes.fromhex('a0624561c80ffe73e4f8eee0d96aa8fe7d884b56c9c3683e5c96472db1ba97acd596d49c44bb0eac62864ae7a66aa2a41188e13d1e1c371e4f2eba6981bf5c73b83ee342ad8d936ccf59a0129bb5eab49ca17ee2974055560d21f29692e377764c9ec62838d58b6f7d9663dd8f688f537a1e1beb7019d8e77dd9eaee42984b3f7e65820714431df2b7caba92a70956622b145e9af06ee11043032c26dfd67f5202ffdd21fc6cc3adfca0c63763b791c868c31b15a7ddddd3ec96eaf2d284a38256ee3ea47fcd7f5700fea042cb739a7a60d85129bc4df8e6aee2dcd91f95e2ad9166e6a4d21745a5fe49e84d4d27c830e81fd2d0fb7887df078e4c5280399ad0')
    },
}

pending_sessions = {}
authenticated_users = set()

# Rate limiting login attempts
login_attempts = defaultdict(list)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = 300  
LOGIN_COOLDOWN_PERIOD = 600 
cooldowns = {}

# Message rate limiting
RATE_LIMIT = 5
RATE_PERIOD = 10
user_message_times = defaultdict(deque)

def handle_client(conn, addr):
    username = None
    try:
        print(f"[DEBUG] Incoming connection from {addr}")

        raw = conn.recv(4096).decode()
        data = json.loads(raw)

        if data["type"] != "auth_start":
            conn.send(json.dumps({"type": "error", "message": "Expected auth_start"}).encode())
            conn.close()
            return

        username = data["username"]
        now = time.time()

        if username in cooldowns:
            cooldown_start = cooldowns[username]
            if now - cooldown_start < LOGIN_COOLDOWN_PERIOD:
                conn.send(json.dumps({
                    "type": "error",
                    "message": f"Too many failed login attempts. Try again in {int(LOGIN_COOLDOWN_PERIOD - (now - cooldown_start))} seconds."
                }).encode())
                conn.close()
                return
            else:
                del cooldowns[username]

        A = bytes.fromhex(data["A"])

        if username not in user_db:
            conn.send(json.dumps({"type": "error", "message": "User not found"}).encode())
            return

        salt = user_db[username]['salt']
        verifier = user_db[username]['verifier']

        server = Verifier(username, salt, verifier, A, hash_alg=SHA256, ng_type=NG_2048)
        s, B = server.get_challenge()
        pending_sessions[username] = server

        conn.send(json.dumps({"type": "auth_challenge", "salt": s.hex(), "B": B.hex()}).encode())

        proof_msg = json.loads(conn.recv(4096).decode())
        M = bytes.fromhex(proof_msg["M"])
        HAMK = server.verify_session(M)

        if not HAMK:
            login_attempts[username].append(now)
            login_attempts[username] = [ts for ts in login_attempts[username] if now - ts <= LOGIN_ATTEMPT_WINDOW]

            if len(login_attempts[username]) >= LOGIN_ATTEMPT_LIMIT:
                cooldowns[username] = now
                conn.send(json.dumps({"type": "error", "message": "Too many failed attempts. Try again later."}).encode())
            else:
                conn.send(json.dumps({"type": "error", "message": "Authentication failed."}).encode())
            return

        if username in login_attempts:
            del login_attempts[username]

        session_key = server.get_session_key()
        conn.send(json.dumps({"type": "auth_success", "HAMK": HAMK.hex()}).encode())

        authenticated_users.add(username)
        clients[username] = conn

        while True:
            msg = conn.recv(4096)
            if not msg:
                break
            try:
                data = json.loads(msg.decode('utf-8'))
                sender = data.get('sender')
                target = data.get('to')
                msg_type = data.get('type')

                now = time.time()
                timestamps = user_message_times[sender]
                while timestamps and now - timestamps[0] > RATE_PERIOD:
                    timestamps.popleft()

                if msg_type == "secure_message":
                    if len(timestamps) >= RATE_LIMIT:
                        warning = json.dumps({
                            "sender": "server",
                            "to": sender,
                            "type": "command_response",
                            "message": "Rate limit exceeded. Please slow down."
                        })
                        conn.send(warning.encode('utf-8'))
                        continue
                    timestamps.append(now)

                if target == "server" and msg_type == "command" and data.get("message") == "list":
                    user_list = [u for u in clients if u != sender]
                    response = json.dumps({
                        "sender": "server",
                        "to": sender,
                        "type": "command_response",
                        "message": f"Online users: {', '.join(user_list) if user_list else 'No other users online.'}"
                    })
                    clients[sender].send(response.encode('utf-8'))
                    continue

                elif target == "server" and msg_type == "logout":
                    break

                if target and target in clients:
                    clients[target].send(msg)
                else:
                    error = json.dumps({"sender": "server", "message": f"User '{target}' not found."})
                    conn.send(error.encode('utf-8'))

            except json.JSONDecodeError:
                print("[ERROR] Failed to parse incoming JSON.")
            except Exception as e:
                print(f"[ERROR] Exception while handling message: {e}")

    finally:
        if username in clients:
            del clients[username]
        authenticated_users.discard(username)
        conn.close()
        print(f"[-] {username if username else 'Unknown user'} disconnected from {addr}")

def start_server(host='127.0.0.1', port=5555):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[+] Server listening on {host}:{port}")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nExiting server...")
    finally:
        server.close()
        print("Server socket closed.")

if __name__ == "__main__":
    start_server()
