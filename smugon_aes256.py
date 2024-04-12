import base64
from Crypto.Cipher import AES
from Crypto import Random


def add_pad(s, block_size=16):
    return s + bytes((block_size - len(s) % block_size) * chr(block_size - len(s) % block_size), 'utf-8')


def rem_pad(s):
    return s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = add_pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return rem_pad(cipher.decrypt(enc[16:]))
