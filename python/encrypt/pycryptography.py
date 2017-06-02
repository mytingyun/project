from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64,os
key="qwertyuiasdfgh12"
password = bytes(key, encoding="utf8")
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
f = base64.urlsafe_b64encode(kdf.derive(password))
key = Fernet(f)

text="this is tingyun,jfaiewjgwegweg"
text=text.encode('utf8')
token = key.encrypt(text)
print(token)

deciphertext=key.decrypt(token)
source_str=deciphertext.decode('utf8')
print(source_str)
