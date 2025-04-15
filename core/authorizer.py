__all__ = ("Authorizer",)

import json
from datetime import datetime, timezone, timedelta

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from websockets.http11 import Request
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from settings import Settings


class Authorizer:
    __server_private_key: PrivateKeyTypes
    __server_public_key: PublicKeyTypes
    __algorithm: str = "RS256"
    __server_private_key_destination: str
    __server_public_key_destination: str

    def __init__(
        self,
        user_repository,
        settings: Settings,
    ) -> None:
        self.user_repository = user_repository
        self.__server_private_key_destination = settings.server_private_key_destination
        self.__server_public_key_destination = settings.server_public_key_destination
        self.__server_private_key = self._get_private_key()
        self.__server_public_key = self._get_public_key()

    def verify_user(self, request: Request) -> str:
        """
        Idea for now (12.04.2025) is to hide under Authorization header encrypted message with
        symmetric key (symm) and encrypted with that key payload (payload) that consist user
        login (login) and hashed password (pass).

        Authenticate user and return him JWT token with his encrypted subject and token_ttl.
        User then have to present this token to the server each time making request.
        :param request: WebSocket handshake request
        :return: JWT token as string
        """
        headers = request.headers
        authorization_message = headers.get("authorization")

        server_private_key = self._get_private_key()
        decoded_message = server_private_key.decrypt(
            ciphertext=authorization_message.encode('utf-8'),
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        mapped_message = json.loads(decoded_message.decode()) # keys: sym, payload
        symmetric_key = self._retrieve_symmetric_key(mapped_message=mapped_message)
        if not symmetric_key:
            raise

        payload = self._retrieve_payload(
            mapped_message=mapped_message,
            symmetric_key=symmetric_key,
        )

        if not self.user_repository.check_user_credentials(
            login=payload.get("login"),
            password=payload.get("pass"),
        ):
            raise

        jwt_payload = {
            "subject": mapped_message.get("subject"),
            "token_ttl": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }

        user_jwt = self._prepare_user_jwt(
            payload=jwt_payload,
            symmetric_key=symmetric_key,
        )

        return user_jwt

    def _get_private_key(self):
        with open(self.__server_private_key_destination, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def _get_public_key(self):
        with open(self.__server_public_key_destination, "rb") as key_file:
            public_key = load_pem_public_key(
                key_file.read(),
            )
        return public_key

    def _retrieve_symmetric_key(self, mapped_message: dict) -> bytes:
        raw_key = mapped_message.get('symm')
        b_key = raw_key.encode('utf-8')

        return b_key

    def _retrieve_payload(self, mapped_message: dict, symmetric_key: bytes) -> dict:
        encrypted_payload = mapped_message.get('payload')
        b_encrypted_payload = encrypted_payload.encode('utf-8')
        raw_payload = Fernet(key=symmetric_key).decrypt(b_encrypted_payload)
        payload = json.loads(raw_payload.decode('utf-8'))

        return payload

    def _prepare_user_jwt(self, payload: dict, symmetric_key: bytes) -> str:
        b_payload = json.dumps(payload).encode('utf-8')
        encrypted_payload = Fernet(key=symmetric_key).encrypt(b_payload)
        user_jwt = jwt.encode(
            payload={"ep": encrypted_payload},
            key=self.__server_private_key,
            algorithm=self.__algorithm,
        )

        return user_jwt
