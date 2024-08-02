from Crypto.PublicKey import RSA

rsa_key = RSA.generate(2048)
with open("./db/.privatekey", "wb") as o:
    o.write(PRIVATE_KEY := rsa_key.export_key('PEM'))
with open("./db/.publickey", "wb") as o:
    o.write(PUBLIC_KEY := rsa_key.publickey().exportKey('PEM'))