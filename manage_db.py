import argparse
from tinydb import TinyDB, where
from enum import Enum
from terminaltables3 import AsciiTable
from getpass import getpass
import string
import secrets
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import base64
import hashlib

db = TinyDB("./db/db.json")
TITLE = "eiskaffedotcom"
LENGTH = 128

class UserLevel(Enum):
    ROOT = 1
    ADMIN = 2
    TRUSTED_USER = 3
    USER = 4

class AESCipher(object):
    
    def __init__(self, key: str):
        self.bs = AES.block_size
        self.key = hashlib.sha3_256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def generate(username: str, password = None):
    with open("./db/.pepper", "r", encoding="utf-8") as p:
        PEPPER = p.readline().strip()
        
    alphabet = string.ascii_letters + string.digits + "-_"
    while True:
        key = "".join(secrets.choice(alphabet) for _ in range(LENGTH))
        if (sum(c.islower() for c in key) >= 32
                and sum(c.isupper() for c in key) >=32
                and sum(c.isdigit() for c in key) >=32):
            break
        
    # first character is 1 if it is a password protected key else 0
    # maybe change to the parity of the sum of all digits?
    key = ("1" if password else "0") + key[:-1]

    with open(f"users/{username}.authkey", "w", encoding="utf-8") as o:
        print("-"*5, "BEGIN AUTH KEY","-"*5, sep="", file=o)
        for i in range(0,len((k := key + "@" + username)),48):
            print(k[i:i+48], file=o)
        print("-"*5, "END AUTH KEY","-"*5, sep="", file=o)
    print(f"< {username}.authkey")
    
    SALT = secrets.token_hex(16)
    key = SALT + key + (password if password else "") + PEPPER + "@" + username
    
    aes = AESCipher(PEPPER + SALT)
    rsa_key = RSA.generate(4096)
    pub = rsa_key.publickey().exportKey("PEM").decode()
    pub = aes.encrypt(pub)
    
    with open(f"users/{username}.privatekey", "wb") as o:
        o.write(rsa_key.export_key("PEM", passphrase=(password if password else None)))
    print(f"< {username}.privatekey")
    
    hash = hashlib.sha3_512(key.encode()).hexdigest()
    
    return hash, SALT, pub

def main(argv=None):
    parser = argparse.ArgumentParser(description="eiskaffe.com api user database manager")
    
    parser.add_argument("--add", "-a", action="store_true", help="Add a user to the database")
    parser.add_argument("--remove", "-r", action="store_true", help="Remove a user from the database")
    parser.add_argument("--list", "-l", action="store_true", help="List all users")
    parser.add_argument("--pepper", "-p", action="store_true", help="Generate a new pepper. (CAUTION, generating a new pepper will delele the whole database!!!)")
    
    args = parser.parse_args() if argv is None else parser.parse_args(argv)
    
    if args.list:
        data = [(d["username"], UserLevel(d["level"])) for d in db.all()]
        data.sort(key=lambda x:x[1].value)
        data = list(map(lambda x: (x[0], x[1].name), data))
        data.insert(0, ("Username", "UserLevel")) # type: ignore
        table_instance = AsciiTable(data, TITLE)
        table_instance.justify_columns[2] = "right"
        print(table_instance.table)
        
    elif args.add:
        username = input("Enter username > ")
        if db.search(where("username") == username): 
            raise NameError("User with that name already exists")
        print("Choose UserLevel: ", end="")
        print(*[f"{v.name} ({i})" for i, v in UserLevel._value2member_map_.items()], sep="; ")
        level = int(input("> "))
        password = getpass("Enter password (optional) > ")
        
        hash, salt, pub = generate(username, password)
        
        # USERNAME(KEY);LEVEL;HASH;SALT;PUB(AES encrypted public key by the key)
        db.insert({"username":username,
                "level":UserLevel(level).value,
                "hash":hash,
                "salt":salt,
                "pub":pub.decode()})
    
    elif args.remove:
        username = input("Enter username > ")
        db.remove(where("username") == username)
        print(f"< User {username} deleted")
        
    elif args.pepper:
        with open("./db/.pepper", "w", encoding="utf-8") as o:
            print(secrets.token_hex(16), file=o,end="")
            print("< .pepper")
        db.truncate()
        
if __name__ == "__main__":
    main()