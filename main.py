from src.core import register, login, logout
from src.database import new_credential


def main():
    """
    Main function.

    : return: None
    """
    # master_password = input("Enter your master password: ")
    master_password = "parola1"
    data = "secret message 1234"

    register(master_password)
    login(master_password)
    new_credential(master_password, credentail_name="Google", credential_username="googlezek",
                   credential_password="google1234", credentail_urls="['https://google.com', 'https://google.com.tr']")
    # logout(master_password)



if __name__ == "__main__":
    main()
