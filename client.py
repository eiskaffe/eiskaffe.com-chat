import socket
import threading
import json
import requests
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from base64 import b64encode, b64decode
from dataclasses import dataclass, field
from time import gmtime, strftime

HANDSHAKE_CONFIRM = [
    "Rammstein - Du Riechst So Gut",
    "Sabaton - Rise Of Evil",
    "Eisbrecher - Rot wie die Liebe",
    "The Retrosic - Total War",
    "Stahlmann - Adrenalin"
]

class AESCipher(object):
    
    def __init__(self, key: bytes):
        self.bs = AES.block_size
        self.key = hashlib.sha3_256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
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
class State:
    username: str
    aes: AESCipher
    client: socket
    
    alive: bool = False
    room: str = "None"
    
    def send(self, raw: str | bytes) -> None:
        """ Send data to the user """
        if self.alive: self.client.send(self.aes.encrypt(raw))
        
    def recieve(self, size: int = 1024) -> str:
        """ Recieve data from the user """
        if self.alive: return self.aes.decrypt(self.client.recv(size))
    
state: State    
def disconnect():
    state.send(generate_packet("DISCONNECT", data={"user": "__self__"}))
    # state.client.shutdown(socket.SHUT_RDWR)
    state.alive = False
    
def post_room(header = {}, payload: str = None):
    global state
    state.room = payload
    print(f"Joined to {state.room}")
    
def goodbye(header = {}, payload = {}):
    print(f"Goodbye, {state.username}!")
    
def chat_event(header = {}, payload: str = None):
    print(payload)
    
def ok200(header = {}, payload: str = None):
    pass
    
def serverListen():
    available_methods = {
        "POST_ROOM": post_room,
        "GOODBYE": goodbye,
        "CHAT_EVENT": chat_event,
        "200": ok200
    }
    global state
    while state.alive:
        method, header, payload = process_packet(state.recieve())
        available_methods[method](header, payload)
    
def post_msg(msg):
    x = generate_packet("POST_MSG", header={"username": state.username, "time": strftime("%Y-%m-%d %H:%M:%S", gmtime())}, data=msg)
    state.send(x)
    
def command(msg):
    print("Nigga :)")    

def userInput():
    available_commands = {
        "command": None,
        "_default": post_msg
    }
    global state
    while state.alive:
        try:
            msg = input(f"{state.username} > ")  # Dummy placeholder for actual user input
            if msg and msg[0] == "/": command(msg)
            else: post_msg(msg)
        except EOFError:
            break
        if msg.strip().lower() == "exit": break
    disconnect()

def generate_packet(method: str, *, header: dict = {}, data: str|dict = {}) -> str:
    h = ""
    header["Content-Type"] = ("string" if isinstance(data, str) else "json")
    for key, value in header.items():
        h += f"{key}: {value}\n"
    d = (data if isinstance(data, str) else json.dumps(data, indent=4))
    return f"{method.upper()}\n\n{h}\n{d}"

def process_packet(incoming: str) -> tuple[str, dict, str|dict]:
    method, header, *body = incoming.split("\n\n")
    header = {line.split(": ")[0]:(int(k) if (k := line.split(": ")[1]).isdigit() else k) for line in header.split("\n")}
    body = "\n\n".join(body)
    if header["Content-Type"] == "json": body = json.loads(body)
    return method, header, body

def main():
    # if len(sys.argv) < 3:
    #     print("USAGE: python client.py <IP> <Port>")
    #     print("EXAMPLE: python client.py localhost 8000")
    #     return
    
    # Authentication
    
    URL = r"http://127.0.0.1:5000/api"    
    USERNAME = input("Welcome to PyconChat! Please enter your username: ")
    cipher = b64decode(requests.request("GET", f"{URL}/pub?username="+USERNAME, headers={}, data={}).text)
    with open(f"users/{USERNAME}.privatekey", "rb") as prv:
        PRIVATE_KEY = PKCS1_OAEP.new(RSA.importKey(prv.read()))
        
    with open(f"users/{USERNAME}.authkey", "r", encoding="utf-8") as f:
        next(f)
        key = ""
        for line in f:
            if line.strip() == "-----END AUTH KEY-----": break
            key += line.strip()
            
    key, username = key.split("@")
    password = input("pwd > ") if key[0] == "1" else ""
    plain_text = key + password + "@" + username
    
    server_public_key = PKCS1_OAEP.new(RSA.importKey(PRIVATE_KEY.decrypt(cipher)))
    cipher = server_public_key.encrypt(plain_text.encode())      
        
    serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSocket.connect(("127.0.0.1", 8000))
     
    # handshake
    
    serverSocket.send(f"{USERNAME} {b64encode(cipher).decode()}".encode()) # authenticating client
    cipher = serverSocket.recv(1024) # user.privatekey rsa encrypted aes handshake
    aes_key = PRIVATE_KEY.decrypt(b64decode(cipher)) # aes-key
    aes = AESCipher(aes_key)
    serverSocket.send(aes.encrypt(Random.random.choice(HANDSHAKE_CONFIRM)))
    if aes.decrypt(serverSocket.recv(1024)) != "200":
        print("Handshake unsuccessful, terminating...")
        exit()
    print("Authentication successful.\n")
    
    # Authentication and handshake was successful, begin normal operations.
    
    global state
    state = State(USERNAME, aes, serverSocket, True)
    
    state.send(generate_packet("GET", data={"user": "__self__", "class": "room", "type": "name"}))
    
    userInputThread = threading.Thread(target=userInput)
    serverListenThread = threading.Thread(target=serverListen)
    userInputThread.start()
    serverListenThread.start()

if __name__ == "__main__":
    main()