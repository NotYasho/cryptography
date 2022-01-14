import base64
from cryptography.fernet import Fernet
from cryptography.fernet import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

message = input("Enter a message: ")
encoded = message.encode()

key_input = input("Enter a Password: ")


def passToKey(password: str) -> bytes:

    key_provided = password.encode()

    salt = b'S\xe3\xa6\x9cF\xd2\xa6H\x1d\xb5\xa6\x02%\x08\x9f\xe5'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000, backend=default_backend())

    key_provided = base64.urlsafe_b64encode(kdf.derive(key_provided))

    return key_provided


key = passToKey(key_input)

f = Fernet(key)
encrypted = f.encrypt(encoded).decode()
print("Message = "+encrypted)
input()