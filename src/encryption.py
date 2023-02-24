from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import bcrypt
import hashlib


def generate_key(master_password: str) -> bytes:
    """
    Generate a key from a master password using bcrypt.

    :param master_password: The master password.
    :return: The key. Length 32 bytes = 256 bits.
    """
    key = bcrypt.kdf(
        password=hashlib.sha256(master_password.encode()).digest(),
        salt=hashlib.sha256(master_password[::-1].encode()).digest(),
        desired_key_bytes=32,
        rounds=100,
    )
    return key


def encrypt(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a plaintext using AES.

    :param key: The key. Length 32 bytes = 256 bits.
    :param plaintext: The plaintext.
    :return: The ciphertext. Example: b'\x80\xe0\xee\x882r\xc9\x8a\xf4IW\x886\x89U\xfc'
    """
    plaintext = pad(plaintext.encode(), AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> str:
    """
    Decrypt a ciphertext using AES.

    :param key: The key. Length 32 bytes = 256 bits.
    :param ciphertext: The ciphertext.
    :return: The plaintext. Example: d43a8341233e54fb387683fe8076ec3701090572db8888a317dcf4f1
    """
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)    # Encoded plaintext
    return plaintext.decode()
