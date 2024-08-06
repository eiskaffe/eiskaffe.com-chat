import socket
import threading
from base64 import b64encode, b64decode
from tinydb import TinyDB, where
import hashlib
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random
from dataclasses import dataclass, field
import json

rooms = {}
fileTransferCondition = threading.Condition()
HANDSHAKE_CONFIRM = [
    "Rammstein - Du Riechst So Gut",
    "Sabaton - Rise Of Evil",
    "Eisbrecher - Rot wie die Liebe",
    "The Retrosic - Total War",
    "Stahlmann - Adrenalin"
]

# Database

DEFAULT_ROOM_NAME = "general"
USERS_DATABASE_NAME = "users"
ROOMS_DATABASE_NAME = "room_meta"

api_db = TinyDB("./db/db.json")
history_db = TinyDB("./db/history.json")
history_db.default_table_name = DEFAULT_ROOM_NAME
chat_meta_db = TinyDB("./db/chat.json")
users_db = chat_meta_db.table(USERS_DATABASE_NAME)
roommeta_db = chat_meta_db.table(ROOMS_DATABASE_NAME)
rooms = {}
with open("./db/.pepper", "r", encoding="utf-8") as p:
    PEPPER = p.readline().strip()
with open("./db/.privatekey", "rb") as f:
    PRIVATE_KEY = RSA.import_key(f.read())
with open("./db/.publickey", "rb") as f:
    PUBLIC_KEY = RSA.import_key(f.read())

# Encryption

def rsa_encrypt_to_user(username: str, msg: bytes) -> bytes:
    user = api_db.search(where("username") == username)[0]
    pub = AESCipher((PEPPER+user["salt"]).encode()).decrypt(user["pub"])
    rsa_public_key = PKCS1_OAEP.new(RSA.importKey(pub))
    a = rsa_public_key.encrypt(msg)
    return b64encode(a)

class AESCipher(object):
    
    def __init__(self, key: bytes):
        self.bs = AES.block_size
        self.key = hashlib.sha3_256(key).digest()

    def encrypt(self, raw):
        if not raw: return
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        if not enc: return
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode()

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

@dataclass
class User:
    username: str
    aes: AESCipher
    client: socket
    room: str = DEFAULT_ROOM_NAME
    alive: bool = False
    
    def send(self, raw: str | bytes) -> None:
        """ Send data to the user """
        try:
            if self.alive: self.client.send(self.aes.encrypt(raw))
        except (ConnectionResetError , ConnectionAbortedError): 
            disconnect_user(self, payload={"user": "__self__"}, send_response=False)
            return
        
    def recieve(self, size: int = 1024) -> str:
        """ Receive data from the user """
        try: 
            if self.alive: return self.aes.decrypt(self.client.recv(size))
        except (ConnectionResetError , ConnectionAbortedError , ValueError): 
            disconnect_user(self, payload={"user": "__self__"}, send_response=False)
            return

@dataclass
class Room:
    name: str
    owner: str
    admins: set[str]
    all_users: set[str]
    online_users: dict[str,User] = field(init=False, default_factory=dict)
    history: TinyDB = field(init=False, repr=False)
    
    def __post_init__(self):
        self.history = history_db.table(self.name, cache_size=50)
        self.admins = set(self.admins)
        self.all_users = set(self.all_users)

    def disconnect(self,username):
        del self.online_users[username]
        users_db.update({"logged-in": False}, where("username") == username)
        self.send_message("", f"{username} logged out.")
    
    def connect(self, user: User):
        self.online_users[user.username] = user
        self.all_users.add(user.username)
        roommeta_db.upsert({"all_users": list(self.all_users)},where("name")==self.name)
        self.send_message("", f"{user.username} logged in.")

    def send_message(self, meta, msg):
        if isinstance(meta, dict):
            packet = generate_packet("CHAT_EVENT", header={"time": meta["time"], "username": meta["username"]}, payload=msg)
        else:
            packet = generate_packet("CHAT_EVENT", payload=msg)
        for member in self.online_users.values():
            print(f"Sending \"{msg}\" to {member.username}")
            member.send(packet)

def generate_packet(method: str, *, header: dict = {}, payload: str|dict = {}) -> str:
    h = ""
    header["Content-Type"] = ("string" if isinstance(payload, str) else "json")
    for key, value in header.items():
        h += f"{key}: {value}\n"
    d = (payload if isinstance(payload, str) else json.dumps(payload, indent=4))
    return f"{method.upper()}\n\n{h}\n{d}"

def process_packet(incoming: str | None) -> tuple[str, dict, str|dict]:
    if not isinstance(incoming, str): return "", {}, {}
    method, header, *body = incoming.split("\n\n")
    header = {line.split(": ")[0]:(int(k) if (k := line.split(": ")[1]).isdigit() else k) for line in header.split("\n")}
    body = "\n\n".join(body)
    if header["Content-Type"] == "json": body = json.loads(body)
    return method, header, body

def ok200():
    return generate_packet("200")

def invalid_request(user: User, header: dict = {}, payload: dict|str = {}, method: str = None):
    if method: return generate_packet("INVALID_REQUEST", payload={"header": header, "payload": payload, "method": method})
    return generate_packet("INVALID_REQUEST", payload={"header": header, "payload": payload})

def disconnect_user(user: User, header: dict = {}, payload: dict|str = {}, *, send_response: bool = True):
    if payload["user"] == "__self__":
        if send_response: user.send(generate_packet("GOODBYE"))
        user.alive = False
        rooms[user.room].disconnect(user.username)
    print(f"{user.username} disconnected.")

def get(user: User, header: dict = {}, payload: dict|str = {}):
    match payload:
        case {"user": "__self__", "class": "room", "type": "name"}:
            return generate_packet("POST_ROOM", payload=user.room)
        case _:
            return invalid_request(user, header, payload, "GET")
        
def post_msg(user: User, header: dict = {}, payload: str = None):
    if user.username != header['username'] or not isinstance(payload, str): 
        return invalid_request(user, header, payload, "POST_MSG")
    rooms[user.room].send_message(header, payload)
    return

def pyconChat(user: User):
    available_methods = {
        "GET": get,
        "DISCONNECT": disconnect_user,
        "POST_MSG": post_msg,
        "_default": invalid_request
    }
    while user.alive:
        method, header, payload = process_packet(user.recieve())
        response = available_methods.get(method, available_methods["_default"])(user, header, payload)
        if response != None: user.send(response)
    print(f"Terminating {user.username} thread")

def handshake(client: socket):
    
    #  Authenticating user
    
    USERNAME, CIPHER = client.recv(2048).decode().split() # username, rsa encrypted login credentials
    private_key = PKCS1_OAEP.new(PRIVATE_KEY)
    TOKEN = private_key.decrypt(b64decode(CIPHER)).decode()
    key, username = TOKEN.split("@")
    if username != USERNAME: client.close()
    x = api_db.search(where("username") == username)
    if len(x) > 1 or len(x) == 0: client.close()
    user = x[0]
    key = user["salt"] + key + PEPPER + "@" + username
    if not hashlib.sha3_512(key.encode()).hexdigest() == user["hash"]:
        client.close()
        
    # The user is now authenticated. Proceeding to share unique AES key. Handshake.
    
    aes_key = Random.get_random_bytes(64)
    transmission = rsa_encrypt_to_user(username, aes_key)
    client.send(transmission)
    aes = AESCipher(aes_key)
    if aes.decrypt(client.recv(2048)) not in HANDSHAKE_CONFIRM:
        client.close()
        print("Terminating, because of unsuccessful handshake event")
    client.send(aes.encrypt("200"))
    print("Successful handshake!")
    
    # AES Handshake was successful, begin normal operations.
    
    user = User(username, aes, client, alive=True)
    global rooms
    rooms[DEFAULT_ROOM_NAME].connect(user)
    users_db.upsert({"username": username, "logged-in": True}, where("username") == username)
    threading.Thread(target=pyconChat, daemon=True, args=(user,)).start()

def main():
    listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSocket.bind(("0.0.0.0", 8000))
    listenSocket.listen(10)
    global rooms
    rooms = {room_meta["name"]: Room(*room_meta.values())
            for room_meta in roommeta_db.all()}
    print("PyconChat Server running")  
    try:
        while True:
            try:
                listenSocket.settimeout(1.0)  # Set a timeout for the accept call
                client, _ = listenSocket.accept()
                print("Accepting connection")
                threading.Thread(target=handshake, args=(client,)).start()
            except socket.timeout:
                continue  # Ignore timeout and continue the loop
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        listenSocket.close()
        for v in rooms.values():
            for online_username, online_user in v.online_users.items():
                users_db.update({"logged-in": False}, where("username") == online_username)
                online_user.send("Server closed.")
                online_user.client.close()
        
        print("Server stopped.")
        

if __name__ == "__main__":
    main()