from flask import Flask, request, abort
from functools import wraps
import requests
from tinydb import TinyDB, where
from base64 import b64encode, b64decode
import hashlib
from enum import Enum
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random

app = Flask(__name__)
db = TinyDB("./db/db.json")
with open("./db/.pepper", "r", encoding="utf-8") as p:
    PEPPER = p.readline().strip()

rsa_key = RSA.generate(2048)
with open("./db/.privatekey", "wb") as o:
    o.write(PRIVATE_KEY := rsa_key.export_key('PEM'))
with open("./db/.publickey", "wb") as o:
    o.write(PUBLIC_KEY := rsa_key.publickey().exportKey('PEM'))

print("SERVER RUNNING!!")

class UserLevel(Enum):
    ROOT = 1
    ADMIN = 2
    USER = 3
    
class AESCipher(object):
    
    def __init__(self, key: str):
        self.bs = AES.block_size
        self.key = hashlib.sha3_256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def rsa_encrypt_to_user(username: str, msg: str):
    user = get_user(username)
    pub = AESCipher(PEPPER + user["salt"]).decrypt(user["pub"])
    rsa_public_key = PKCS1_OAEP.new(RSA.importKey(pub))
    a = rsa_public_key.encrypt(msg.encode())
    return b64encode(a).decode()

def get_user(username) -> dict:
    """Returns the user with the username, raises error when multiple or none are present."""
    x = db.search(where("username") == username)
    if len(x) > 1 or len(x) == 0: abort(401)
    return x[0]

def get_auth_header():
    """Obtains the Access Username and Key from the Authorization Header"""
    auth = request.headers.get("Authorization", None)
    if not auth: abort(401)
    parts = auth.split()
    if len(parts) == 1 or len(parts) > 2: abort(401)
    return parts[0], parts[1]

def requires_auth(f):
    """Determines if the Access Key is valid"""
    @wraps(f)
    def decorated(*args, **kwargs):
        USERNAME, CIPHER = get_auth_header()
        private_key = PKCS1_OAEP.new(RSA.importKey(PRIVATE_KEY))
        TOKEN = private_key.decrypt(b64decode(CIPHER)).decode()
        key, username = TOKEN.split("@")
        if username != USERNAME: abort(401)
        user = get_user(username)
        key = user["salt"] + key + PEPPER + "@" + username
        
        if hashlib.sha3_512(key.encode()).hexdigest() == user["hash"]:
            return f(username, *args, **kwargs)
        else: abort(401)
    return decorated

def requires_level(level: UserLevel):
    def middle(f):
        @wraps(f)
        def wrapper(username, *args, **kwargs):
            if level.value < get_user(username)["level"]: abort(418)
            return f(username, *args, **kwargs)
        return wrapper
    return middle

@requires_level(UserLevel.ADMIN)
def dynip(username):
    return requests.get('https://checkip.amazonaws.com').text.strip()

@app.route("/api")
@requires_auth
@requires_level(UserLevel.USER)
def main(username):
    if not request.args.get("dynip") == None: return dynip(username)
    abort(404)
    
@app.route("/api/pub")
def pub():
    username = request.args.get("username")
    if not username: abort(401)
    return rsa_encrypt_to_user(username, PUBLIC_KEY.decode())

# === DATABASE ===
# USERNAME(KEY);LEVEL;HASH;SALT;PUB(AES encrypted public key by the key)
# === DATABASE ===

if __name__ == "__main__":
    app.run(debug=True)