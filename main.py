import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad


def get_private_key(secretKey, salt):
    return hashlib.pbkdf2_hmac('SHA256', secretKey.encode(), salt.encode(), 65536, 32)

def encrypt(message, salt, secretKey):
    private_key = get_private_key(secretKey, salt)
    message = pad(message.encode(), AES.block_size)
    iv = "\x00" * AES.block_size
    cipher = AES.new(private_key, AES.MODE_CBC, iv.encode())
    return base64.b64decode(cipher.encrypt(message))

def decrypt(enc, salt, secretKey):
    private_key = get_private_key(secretKey, salt)
    enc = base64.b64decode(enc)
    iv = "\x00" * AES.block_size
    cipher = AES.new(private_key, AES.MODE_CBC, iv.encode())
    return unpad(cipher.decrypt(enc), AES.block_size).decode('utf-8')

if __name__ == '__main__':
    secretKey = "someSecretKey"
    salt = "someSalt"
    plainText = open('sometext.txt', 'r').read()
    enc_data = encrypt(plainText, salt, secretKey)
    print(f"Encrypted: {enc_data}")