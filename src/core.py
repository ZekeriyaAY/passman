from src.database import authorize_user, initialize_users_table, initialize_unique_user_table, encrypt_database, decrypt_name


def register(master_password: str) -> None:
    """
    Register a database.

    :param master_password: The master password.
    :param database_path: The database path.
    :return: None
    """
    initialize_users_table()
    initialize_unique_user_table(master_password)


def login(master_password: str) -> None:
    """
    Login a database.

    :param master_password: The master password.
    :param database_path: The database path.
    :return: None
    """
    if authorize_user(master_password):
        decrypt_name(master_password)
        print("Authorized")
        """
        YETKİLİ OLDUĞUNDA KENDİ VERİTABANINDAKİ NAME KOLONLARININ ŞİFRELERİ ÇÖZÜLECEK
        ARAYÜZDE SADECE NAME VE DATE BİLGİLERİNİ GÖREBİLECEK
        """
    else:
        print("Not authorized")


def logout(master_password: str) -> None:
    """
    Logout a database.

    :return: None
    """
    # Decrypt all credentials, databases, etc.
    encrypt_database(master_password)

