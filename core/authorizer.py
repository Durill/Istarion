__all__ = ("Authorizer",)

import base64
import json
import os
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from websockets.http11 import Request
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key, \
    load_der_private_key, load_pem_public_key
from dotenv import load_dotenv


class Authorizer:
    def __init__(
        self,
        user_repository,
    ) -> None:
        self.user_repository = user_repository

    def verify_user(self, request: Request):
        headers = request.headers
        # TODO: My idea for now is to hide under this header encrypted message with symmetric key(symm), login(subject) and password(pass) of user
        authorization_message = headers.get("authorization")

        server_private_key, server_public_key = self._get_keys()
        decoded_message = server_private_key.decrypt(
            ciphertext=authorization_message.encode('utf-8'),
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        mapped_message = json.loads(decoded_message.decode()) # keys: sym, log, pass

        if not self.user_repository.check_user_credentials(
            login=mapped_message.get("subject"),
            password=mapped_message.get("pass"),
        ):
            raise

        symmetric_key = mapped_message.get("symm")
        if not symmetric_key:
            raise

        # TODO: Now it's time to generate jwt token for user with his subject, some ttl of token and encrypt everything with agreed symmetric key
        payload = {
            "subject": mapped_message.get("subject"),
            "token_ttl": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }

        # TODO: encrypt this data with symmetric key
        # TODO: create jwt token from it and sign it with server private key
        # TODO: return it to be send to user

    def _get_keys(self):
        return self._get_private_key(), self._get_public_key()

    def _get_private_key(self):
        with open("/home/wb/Desktop/certs/private-key-24032025.pem", "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def _get_public_key(self):
        with open("/home/wb/Desktop/certs/public-key-24032025.pem", "rb") as key_file:
            public_key = load_pem_public_key(
                key_file.read(),
            )
        return public_key

with open("/home/wb/Desktop/certs/private-key-24032025.pem", "rb") as key_file:
    private_key = load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("/home/wb/Desktop/certs/public-key-24032025.pem", "rb") as key_file:
    public_key = load_pem_public_key(
        key_file.read(),
    )

message = {
    "sym": "aabb11cc99",
    "log": "admin",
    "pass": "aksjhd1098eru1ksajkcOAhjd-iqw"
}
message = json.dumps(message).encode('utf-8')
encrypted_message = public_key.encrypt(
    plaintext=message,
    padding=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ),
)
print(private_key)
decoded_message = private_key.decrypt(
    ciphertext=encrypted_message,
    padding=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ),
)
print(json.loads(decoded_message.decode()))
encrypted_b64 = base64.b64encode(encrypted_message)
enc = jwt.encode(payload={"ss": str(encrypted_b64)}, key=private_key, algorithm="RS256")
print(encrypted_b64.decode())
print(enc)
decoded_jwt = jwt.decode(jwt=enc, key=public_key, algorithms=["RS256"])
print(decoded_jwt)
print((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
print(datetime.now(timezone.utc).isoformat())

### FLOW

### Know How
# 1. public key for encrypting message need to be first sanitized from Header and Footer
#    and then decoded to bytes by Base64 decoder
# 2. Then that data needs to be passed to cryptography method to retrieve public key `load_der_public_key()`
# 3. To jwt.encode() pass not-sanitized private key

# I did not figured out why password is needed to load rsa private key or maybe data format is wrong

# PEM (Privacy-Enhanced Mail) - file format for storing and sending cryptographic keys, certificates, and other data.
#                               Take key with headers but typed as bytes
# DER (Distinguished Encoding Rules) - is a binary format for cryptographic keys and certificates.
#                                      Unlike PEM, it does not contain headers or Base64 encoding—it is purely a
#                                      raw binary representation of the key.

