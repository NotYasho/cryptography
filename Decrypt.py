import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from colorama import Fore as fc
from colorama import init
init(autoreset=True)

def passToKey(password: str) -> bytes: 

    key_provided = password.encode()

    salt = b'S\xe3\xa6\x9cF\xd2\xa6H\x1d\xb5\xa6\x02%\x08\x9f\xe5'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                    iterations=100000, backend=default_backend())

    key_provided = base64.urlsafe_b64encode(kdf.derive(key_provided))

    return key_provided


# Taking input the message and the key

print(f"\n🔐 Enter the encoded Message: {fc.LIGHTCYAN_EX}")
encrypted_message = input(fc.LIGHTBLACK_EX+"🔑 ").encode()

print(F"{fc.RESET}🔐 Enter the Key: {fc.LIGHTCYAN_EX}")
password = input(fc.LIGHTBLACK_EX+"🔑 ")


key = passToKey(password)

# Creating an object of Fernet and passing a key to it
f = Fernet(key)
try:
    message = f.decrypt(encrypted_message).decode()

except InvalidToken:
    print(f"\n{fc.LIGHTRED_EX}⚠️  The input Message or the Key is Invalid")

else:
    print(f"\n{fc.LIGHTYELLOW_EX}The message is: {fc.LIGHTGREEN_EX}{message}\n")

input()