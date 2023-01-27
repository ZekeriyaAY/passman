import bcrypt
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def generate_key(password, salt):
    """
    Generates a key from the given password and salt.    


    password:
        The master password - a string.

    salt:
        A salt that is used for key generation. It
        must be 16 bytes long.

    Returns a 32-byte key that can be used for
    encryption and decryption.
    """
    key = bcrypt.kdf(password=password, salt=salt,
                     desired_key_bytes=32, rounds=100)
    return key


def encrypt(key, source, encode=True):
    """Encrypts a file using AES (CBC mode) with the
    given key.


    key:
        The encryption key - a string that must be
        either 16, 24 or 32 bytes long. Longer keys
        are more secure.

    source:
        Source string to encrypt.

    encode:
        If True, the return value is base64 encoded.
    """
    # Pad the source string
    source = pad(source, AES.block_size)

    # Generate a random initialization vector
    iv = os.urandom(16)  # 16 bytes = 128 bits

    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the source string
    ciphertext = cipher.encrypt(source)

    # Prepend the IV
    result = iv + ciphertext

    if encode:
        # Encode as base64
        result = base64.b64encode(result)

    return result


def decrypt(key, source, decode=True):
    """Decrypts a file using AES (CBC mode) with the
    given key. Parameters are similar to encrypt(),
    with one difference: source must be bytes,
    a string that contains base64 encoded data.


    key:
        The encryption key - a string that must be
        either 16, 24 or 32 bytes long. Longer keys
        are more secure.

    source:
        Source string to decrypt.

    decode:
        If True, the source string is first base64
        decoded.

    Returns the decrypted data as a string.
    """
    if decode:
        # Decode the base64 encoded bytes
        source = base64.b64decode(source)

    # Extract the initialization vector from the beginning
    iv = source[:16]
    source = source[16:]

    # Create the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    plaintext = cipher.decrypt(source)

    # Remove the padding
    plaintext = unpad(plaintext, AES.block_size)

    return plaintext


def main():
    # Get the master password from the user
    # master_password = input("Enter your master password: ").encode()
    master_password = "parola1234".encode('utf-8')
    data = "secret message".encode('utf-8')
    print("Master password: ", master_password)
    print("Data: ", data)

    # Derive the key
    salt = bcrypt.gensalt()
    print("Salt: ", salt)
    encryption_key = generate_key(master_password, salt)
    print("Key: ", encryption_key)

    # Encrypt the data
    ciphertext = encrypt(encryption_key, data)
    print("Ciphertext: ", ciphertext.decode('utf-8', 'ignore'))

    # Decrypt the data
    plaintext = decrypt(encryption_key, ciphertext)
    print("Plaintext: ", plaintext)

    # Check if decryption was successful
    if plaintext == data:
        print("Decryption was successful.")
    else:
        print("Decryption failed.")


if __name__ == "__main__":
    main()
