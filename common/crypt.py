from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

rsa_len = 1024


def encrypt_aes(key: bytes, data: bytes) -> bytes:
    padded = pad(data, block_size=AES.block_size)
    aes = AES.new(key, mode=AES.MODE_CBC)
    return aes.iv + aes.encrypt(padded)


def decrypt_aes(key: bytes, data: bytes) -> bytes:
    iv = data[:AES.block_size]
    padded = AES.new(key, iv=iv, mode=AES.MODE_CBC).decrypt(data[AES.block_size:])
    return unpad(padded, block_size=AES.block_size)


def encrypt_rsa(rsa_pub: bytes, data: bytes) -> bytes:
    key = RSA.import_key(rsa_pub)
    return PKCS1_OAEP.new(key).encrypt(data)


def decrypt_rsa(rsa: bytes, data: bytes) -> bytes:
    key = RSA.import_key(rsa)
    return PKCS1_OAEP.new(key).decrypt(data)


def generate_rsa_keypair():
    pair = RSA.generate(rsa_len)
    pub = pair.publickey().export_key()
    private = pair.export_key()
    return pub, private
