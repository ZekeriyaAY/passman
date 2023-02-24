import sqlite3
import base64
import hashlib
from src.encryption import generate_key, encrypt, decrypt
from config import DatabasePath


def authorize_user(master_password: str) -> bool:
    """
    Authorize a database.

    :param master_password: The master password.
    :return: True if authorized, False otherwise.
    """
    key = generate_key(master_password)
    user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()

    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        query_select_user_hash = f"""
            SELECT encrypted_user_hash FROM users WHERE user_hash = '{user_hash}'
            """
        try:
            cursor.execute(query_select_user_hash)
            encrypted_user_hash = cursor.fetchone()
        except sqlite3.Error as e:
            print("Failed to select user hash ", e)
            return False
        if encrypted_user_hash is not None:
            encrypted_user_hash = base64.b64decode(
                encrypted_user_hash[0].encode())
            plaintext_user_hash = decrypt(key, encrypted_user_hash)
            if plaintext_user_hash == user_hash:
                return True
        else:
            return False
    except sqlite3.Error as e:
        print("Failed to authorize user ", e)
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for authorize_user is closed.")


def initialize_users_table() -> None:
    """
    Create the users table.

    :return: None
    """
    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        query_create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                user_hash BLOB NOT NULL UNIQUE,
                encrypted_user_hash BLOB NOT NULL UNIQUE,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                modified_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                CHECK (modified_date > added_date  OR modified_date = added_date)
            )
            """
        try:
            cursor.execute(query_create_users_table)
            conn.commit()
            print("Users table created.")
        except sqlite3.Error as e:
            print("Failed to create users table ", e)
    except sqlite3.Error as e:
        print("Failed to create users database ", e)
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for users_table is closed.")


def initialize_unique_user_table(master_password: str) -> None:
    """
    Create the unique table.

    :param master_password: The master password.
    :return: None
    """
    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()
        query_create_table = f"""
            CREATE TABLE IF NOT EXISTS '{user_hash}' (
                id INTEGER PRIMARY KEY,
                name BLOB NOT NULL,
                username BLOB NOT NULL,
                password BLOB NOT NULL,
                urls BLOB NOT NULL,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                modified_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                CHECK (modified_date > added_date OR modified_date = added_date)
            )
            """
        try:
            cursor.execute(query_create_table)
            conn.commit()
            print("Unique table created.")
        except sqlite3.Error as e:
            print("Failed to create unique table ", e)

        key = generate_key(master_password)
        ciphertext = encrypt(key, user_hash)
        ciphertext = base64.b64encode(ciphertext).decode()
        query_add_users_table = f"""
            INSERT OR IGNORE INTO users (user_hash, encrypted_user_hash, added_date, modified_date) VALUES ('{user_hash}', '{ciphertext}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        try:
            cursor.execute(query_add_users_table)
            conn.commit()
            print("Unique table added to users table.")
        except sqlite3.Error as e:
            print("Failed to add unique table to users table ", e)
    except sqlite3.Error as e:
        print("Failed to create unique database ", e)
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for unique_table is closed.")


def encrypt_database(master_password: str) -> bool:
    """
    Encrypt the database.

    :param master_password: The master password.
    :return: True if the database is encrypted, False otherwise.
    """
    key = generate_key(master_password)
    user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()

    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        query_get_database = f"""
            SELECT * FROM '{user_hash}'
            """
        try:
            cursor.execute(query_get_database)
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            print("Failed to get database ", e)
            return False
        for row in rows:
            id, name, username, password, urls, _, _ = row
            ciphertext_name = encrypt(key, name)
            ciphertext_name = base64.b64encode(ciphertext_name).decode()
            ciphertext_username = encrypt(key, username)
            ciphertext_username = base64.b64encode(
                ciphertext_username).decode()
            ciphertext_password = encrypt(key, password)
            ciphertext_password = base64.b64encode(
                ciphertext_password).decode()
            ciphertext_urls = encrypt(key, urls)
            ciphertext_urls = base64.b64encode(ciphertext_urls).decode()
            query_update_database = f"""
                UPDATE '{user_hash}' SET name = '{ciphertext_name}', username = '{ciphertext_username}', password = '{ciphertext_password}', urls = '{ciphertext_urls}' WHERE id = {id}
                """
            try:
                cursor.execute(query_update_database)
                conn.commit()
            except sqlite3.Error as e:
                print("Failed to update database ", e)
                return False
        return True
    except sqlite3.Error as e:
        print("Failed to encrypt database ", e)
        return False
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for encrypt_database is closed.")


def decrypt_name(master_password: str) -> bool:
    key = generate_key(master_password)
    user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()

    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        query_get_name = f"""
            SELECT id, name FROM '{user_hash}'
            """
        try:
            cursor.execute(query_get_name)
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            print("Failed to get name ", e)
            return False
        for row in rows:
            id, name = row
            ciphertext_name = base64.b64decode(name.encode())
            plaintext_name = decrypt(key, ciphertext_name)
            query_update_name = f"""
                UPDATE '{user_hash}' SET name = '{plaintext_name}' WHERE id = {id}
                """
            try:
                cursor.execute(query_update_name)
                conn.commit()
                print("Decrypted name")
            except sqlite3.Error as e:
                print("Failed to update name ", e)
                return False
        return True
    except sqlite3.Error as e:
        print("Failed to decrypt name ", e)
        return False
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for decrypt_name is closed.")

# def decrypt_credential(master_password: str, name: str) -> bool:
#     key = generate_key(master_password)
#     user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()

#     conn = sqlite3.connect(DatabasePath)
#     try:
#         cursor = conn.cursor()
#         query_get_credential = f"""
#             SELECT id, username, password, urls FROM '{user_hash}' WHERE name = '{name}'
#             """
#         try:
#             cursor.execute(query_get_credential)
#             rows = cursor.fetchall()
#         except sqlite3.Error as e:
#             print("Failed to get credential ", e)
#             return False
#         for row in rows:
#             id, username, password, urls = row


def new_credential(master_password: str, credentail_name: str, credential_username: str, credential_password: str, credentail_urls: str) -> bool:
    """
    Add a new credential to the database.

    :param master_password: The master password.
    :param credentail_name: The name of the credential.
    :param credential_username: The username of the credential.
    :param credential_password: The password of the credential.
    :param credentail_urls: The urls of the credential.
    :return: True if the new credential is added, False otherwise.
    """
    key = generate_key(master_password)
    user_hash = hashlib.sha224(master_password[::-1].encode()).hexdigest()

    conn = sqlite3.connect(DatabasePath)
    try:
        cursor = conn.cursor()
        # query_get_credential = f"""
        #     SELECT id FROM '{user_hash}' WHERE name = '{credentail_name}'
        #     """
        # try:
        #     cursor.execute(query_get_credential)
        #     rows = cursor.fetchall()
        # except sqlite3.Error as e:
        #     print("Failed to get credential ", e)
        #     return False
        # if rows:
        #     print("Credential already exists.")
        #     return False
        ciphertext_name = encrypt(key, credentail_name)
        ciphertext_name = base64.b64encode(ciphertext_name).decode()
        ciphertext_username = encrypt(key, credential_username)
        ciphertext_username = base64.b64encode(
            ciphertext_username).decode()
        ciphertext_password = encrypt(key, credential_password)
        ciphertext_password = base64.b64encode(
            ciphertext_password).decode()
        ciphertext_urls = encrypt(key, credentail_urls)
        ciphertext_urls = base64.b64encode(ciphertext_urls).decode()
        query_add_credential = f"""
            INSERT INTO '{user_hash}' (name, username, password, urls, added_date, modified_date) VALUES ('{ciphertext_name}', '{ciphertext_username}', '{ciphertext_password}', '{ciphertext_urls}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        try:
            cursor.execute(query_add_credential)
            conn.commit()
            print("Credential added.")
            decrypt_name(master_password)
            return True
        except sqlite3.Error as e:
            print("Failed to add credential ", e)
            return False
    except sqlite3.Error as e:
        print("Failed to add new credential ", e)
        return False
    finally:
        if conn:
            conn.close()
            # print("The SQLite connection for new_credential is closed.")
