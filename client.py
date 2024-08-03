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
        self.client.send(self.aes.encrypt(raw))
        
    def recieve(self, size: int = 1024) -> str:
        """ Receive data from the user """
        return self.aes.decrypt(self.client.recv(size))

def serverListen(serverSocket):
    while state["alive"]:
        msg = serverSocket.recv(1024).decode("utf-8")
        
def userInput(serverSocket):
    while state["alive"]:
        ...

def generate_request(method: str, *, header: dict = {}, data: str|dict = {}) -> str:
    h = ""
    header["Content-Type"] = ("string" if isinstance(data, str) else "json")
    for key, value in header.items():
        h += f"{key}: {value}\n"
    d = (data if isinstance(data, str) else json.dumps(data, indent=4))
    return f"{method.upper()}\n\n{h}\n{d}"

def process_request(incoming: str) -> tuple[str, dict, str|dict]:
    method, header, *body = incoming.split("\n\n")
    header = {line.split(": ")[0]:(int(k) if (k := line.split(": ")[1]).isdigit() else k) for line in header.split("\n")}
    body = "\n\n".join(body)
    if header["Content-Type"] == "json": body = json.loads(body)
    return method, header, body

state: State
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
    state = State(USERNAME, aes, serverSocket, False)
    
    state.send(generate_request("GET", data="self room name"))
    response = process_request(state.recieve())
    
    print(response)
    
    
    
    
    input("ENTER to exit")
    
    exit()
    
    # state["inputCondition"] = threading.Condition()
    # state["sendMessageLock"] = threading.Lock()
    
    state["groupname"] = input("Please enter the name of the group: ")
 
    userInputThread = threading.Thread(target=userInput,args=(serverSocket,))
    serverListenThread = threading.Thread(target=serverListen,args=(serverSocket,))
    userInputThread.start()
    serverListenThread.start()


if __name__ == "__main__":
    main()