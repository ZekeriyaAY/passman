import os

# App Variables
AppName = "passman"
AppVersion = 0.1
AppGitHub = "https://github.com/ZekeriyaAY/passman"
AppAuthor = "Zekeriya AY <zekeriya@zekeriyaay.com>"
AppLicense = "GPLv3"
AppDescription = "A simple password manager."


# Database Variables
DatabaseName = "database.sqlite"
DatabasePath = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), DatabaseName)
