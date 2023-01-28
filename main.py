import bcrypt
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


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
    :return: The ciphertext.
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
    :return: The plaintext.
    """
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)    # Encoded plaintext
    return plaintext.decode()


def main():
    """
    Main function.

    :return: None
    """
    # master_password = input("Enter your master password: ")
    master_password = "parola1234"
    data = "secret message1234"

    key = generate_key(master_password)
    ciphertext = encrypt(key, data)
    plaintext = decrypt(key, ciphertext)

    print(f"Key: {key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Plaintext: {plaintext}")


if __name__ == "__main__":
    main()
