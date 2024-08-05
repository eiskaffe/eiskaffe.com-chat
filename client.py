import socket
import threading
import json
import blessed.terminal
import requests
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from base64 import b64encode, b64decode
from dataclasses import dataclass, field
from time import gmtime, strftime
import blessed, curses
import signal

HANDSHAKE_CONFIRM = [
    "Rammstein - Du Riechst So Gut",
    "Sabaton - Rise Of Evil",
    "Eisbrecher - Rot wie die Liebe",
    "The Retrosic - Total War",
    "Stahlmann - Adrenalin"
]
# MESSAGE_LIMIT = 10

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
    term: blessed.Terminal
    
    terminal_lines: list[dict[str,str]] = field(default_factory=list)
    print_lock: threading.Lock = field(default_factory=threading.Lock)
    message_offset: int = 0
    pad: int = 0
    msg: str = ""
    alive: bool = False
    room: str = "None"        
    
    def send(self, raw: str | bytes) -> None:
        """ Send data to the user """
        if self.alive: self.client.send(self.aes.encrypt(raw))
        
    def recieve(self, size: int = 1024) -> str:
        """ Recieve data from the user """
        if self.alive: return self.aes.decrypt(self.client.recv(size))
        
    @property
    def max_messages_shown(self):
        return self.term.height - 4 - self.pad
    
    @staticmethod
    def _process_message(msg_head, string):
        if not len(f"{msg_head}{string}") // state.term.width > 0: return 0, f"{msg_head}{string}"
        r = ""
        k = 0
        for i in range(0, len(string)-1, state.term.width-len(msg_head)):
            if i == 0: 
                r += msg_head + string[0:state.term.width-len(msg_head)]
            else: 
                r += "\n" + " "*len(msg_head) + string[i:i+state.term.width-len(msg_head)]
                k += 1
        return k, r       
        
    def print_screen(self):
        p = 0
        self.print_lock.acquire(True)
        print(self.term.clear)
        x = len(self.terminal_lines) - self.max_messages_shown - self.message_offset
        if x < 0: x = 0
        for i, d in enumerate(self.terminal_lines[x:len(self.terminal_lines)-self.message_offset]):
            k, s = self._process_message(d["head"], d["body"])             
            print(self.term.move_xy(0, i + 1 + p) + self.term.clear_eol + s)
            p += k
        self.pad, string = State._process_message(f"{self.username} > ", self.msg)
        print(self.term.move_xy(0, self.term.height - 2 - self.pad) + self.term.clear_eos + string)
        self.print_lock.release()
        
    def add_to_screen(self, string: str, head: str = ""):
        self.terminal_lines.append({"head": head, "body": string})
        self.print_screen()

   
state: State     
       
def disconnect():
    state.send(generate_packet("DISCONNECT", data={"user": "__self__"}))
    state.alive = False
    print(state.term.exit_fullscreen)
    
def post_room(header = {}, payload: str = None):
    global state
    state.room = payload
    state.add_to_screen(f"Joined to {state.room}")
    
def goodbye(header = {}, payload = {}):
    print(f"Goodbye, {state.username}!")
    
def chat_event(header = {}, payload: str = None):
    state.add_to_screen(payload, f"[{header['time']}]-({header['username']})-> ")
    
def ok200(header = {}, payload: str = None):
    pass
    
# MAIN BOSS
def serverListen():
    available_methods = {
        "POST_ROOM": post_room,
        "GOODBYE": goodbye,
        "CHAT_EVENT": chat_event,
        "200": ok200
    }
    global state
    while state.alive:
        try: method, header, payload = process_packet(state.recieve())
        except socket.timeout: continue
        available_methods[method](header, payload)
    # print("serverListen dead.")
    return 1
    
def post_msg(msg):
    x = generate_packet("POST_MSG", header={"username": state.username, "time": strftime("%Y-%m-%d %H:%M:%S", gmtime())}, data=msg)
    state.send(x)
    
def command(msg):
    state.add_to_screen("gn :)")

# MAIN BOSS
def userInput():
    available_commands = {
        "command": None,
        "_default": post_msg
    }
    global state
    with state.term.cbreak():
        while state.alive:
            try:
                # msg = input(f"{state.username} > ")  # Dummy placeholder for actual user input
                state.msg = ""
                state.print_lock.acquire(True)
                print(state.term.move_xy(0, state.term.height - 2) + state.term.clear_eos + f"{state.username} > ")
                state.print_lock.release()
                while True:
                    inp = state.term.inkey()
                    if inp.code == curses.KEY_ENTER:
                        break
                    elif inp.code == curses.KEY_BACKSPACE:
                        state.msg = state.msg[:-1]
                    elif inp.code in [curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT]:
                        pass
                    else: 
                        state.msg += inp
                    new_pad, string = State._process_message(f"{state.username} > ", state.msg)
                    if new_pad != state.pad: 
                        state.print_screen()
                        state.pad = new_pad
                    state.print_lock.acquire(True)
                    print(state.term.move_xy(0, state.term.height - 2 - state.pad) + state.term.clear_eos + string)
                    state.print_lock.release()
                if state.msg.strip().lower() == "exit": disconnect()
                elif state.msg and state.msg[0] == "/": command(state.msg)
                else: post_msg(state.msg)

            except EOFError:
                state.alive = False
        # print("userInput dead.")
    return 1

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
    # Set up signal handler to handle Ctrl-C
    def signal_handler(sig, frame):
        print(state.term.exit_fullscreen)
        print("\nForcefully shutting down...")
        disconnect()
        userInputThread.join(1.2)
        serverListenThread.join(1.2)
        # print(userInputThread.is_alive(), serverListenThread.is_alive())
        state.client.close()
        
    signal.signal(signal.SIGINT, signal_handler)

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
    ip = requests.request("GET", f"{URL}?dynip", headers={"Authorization": f"{USERNAME} {b64encode(cipher).decode()}"}, data={}).text  
        
    serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSocket.connect((ip, 8000))
    serverSocket.settimeout(1)
     
    # handshake
    
    cipher = server_public_key.encrypt(plain_text.encode())    
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
    state = State(USERNAME, aes, serverSocket, blessed.Terminal(), alive=True)
    
    state.send(generate_packet("GET", data={"user": "__self__", "class": "room", "type": "name"}))
    
    userInputThread = threading.Thread(target=userInput)
    serverListenThread = threading.Thread(target=serverListen)
    userInputThread.start()
    serverListenThread.start()
    
    print(state.term.enter_fullscreen + state.term.home)
    
if __name__ == "__main__":
    main()