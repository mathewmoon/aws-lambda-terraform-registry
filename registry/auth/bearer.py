#!/usr/bin/env python3
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from json import dumps, loads, JSONDecodeError
from time import time
from hashlib import sha256
from random import choice
from string import ascii_letters, digits
from typing import Self

from .exceptions import AuthError
from . import Auth, model_validator
from ..globals import logger, Clients, RegistryConfig


clients = Clients()
config = RegistryConfig()


class BearerAuth(Auth):
    """
    Handles simple Bearer Auth using static, non-expiring, tokens
    """

    min_token_length: int = 64

    @model_validator(mode="after")
    def validate(self) -> Self:
        """
        Validates the token by checking its length.

        :raises AuthError: If the token is shorter than the minimum length.
        """
        if len(self.token) < self.min_token_length:
            raise AuthError(
                f"Token must be at least {self.min_token_length} characters long"
            )
        return self

    @property
    def identifier(self):
        """
        Generates a unique identifier for the token using SHA-256 hashing.

        :return: The SHA-256 hash of the token.
        """
        return sha256(self.token.encode()).hexdigest()

    @classmethod
    def make_token(cls):
        """
        Creates a random token string of the minimum token length.

        :return: The generated token string.
        """
        letters = ascii_letters + digits
        random_str = "".join(choice(letters) for _ in range(cls.min_token_length))
        return f"{cls.__name__}-{random_str}"


class IAMBearerAuth(BearerAuth):
    """
    Generates Bearer tokens that are encrypted with clients.kms, using a method that allows them to be
    used to verify the identity of the caller when used later.

    Tokens are created in the format:
        IAMBearer~<encrypted_data>
    Encrypted data is a base64-encoded clients.kms-encrypted JSON string of the format:
        {"role_arn": "<role_arn>", "expiration": <expiration_unix_timestamp>}
    """

    @classmethod
    def make_token(
        cls, role_arn: str, expiration_seconds: int = config.max_token_expration_window
    ):
        """
        Creates a token for the given role ARN with an expiration time.

        :param role_arn: The Amazon Resource Name (ARN) of the role.
        :param expiration_seconds: The number of seconds until the token expires.
        :return: The generated token.
        :raises AuthError: If the expiration window is too large.
        """
        if expiration_seconds > config.max_token_expration_window:
            raise ValueError(
                f"Expiration window is too large. Max is {config.max_token_expration_window} seconds",
            )

        now = int(time())
        expiration = now + expiration_seconds

        payload = dumps({"role_arn": role_arn, "expiration": expiration}).encode()

        res = clients.kms.encrypt(
            KeyId=config.iam_auth_kms_key,
            Plaintext=payload,
        )["CiphertextBlob"]

        res = b64encode(res).decode()
        token = f"{cls.__name__}~{res}"

        return token

    def validate(self):
        """
        Validates the token by checking its expiration and role ARN.

        :raises AuthError: If the token has expired, the expiration is too far in the future,
                           or the token does not match the role ARN.
        """
        now = int(time()) + 20

        if now > self.expiration:
            raise AuthError("Token has expired")

        if self.expiration - now > config.max_token_expration_window:
            raise AuthError(
                f"Token expiration is too far in the future. Max window is {config.max_token_expration_window} seconds"
            )

    @property
    def role_arn(self):
        """
        Extracts the role ARN from the token.

        :return: The role ARN.
        :raises AuthError: If the token format is invalid.
        """
        return self.decrypted_token["role_arn"]

    @property
    def decrypted_token(self):
        """
        Returns the decrypted token data from the encrypted part of the token
        as a string.
        """
        token_parts = self.token.split("~")
        try:
            payload = token_parts[1]
        except IndexError:
            raise AuthError("Invalid token format")

        try:
            ciphertext = b64decode(payload)
        except Exception as e:
            raise AuthError(f"Invalid Token")

        try:
            decrypted_token = clients.kms.decrypt(
                KeyId=config.iam_auth_kms_key, CiphertextBlob=ciphertext
            )["Plaintext"].decode()
        except Exception as e:
            logger.exception(e)
            raise AuthError(f"Invalid Token")

        try:
            token = loads(decrypted_token)
        except JSONDecodeError:
            raise AuthError(f"Invalid Token")
        return token

    @property
    def expiration(self):
        """
        Returns the expiration time of the token as a Unix timestamp.
        """
        return self.decrypted_token["expiration"]

    @property
    def identifier(self):
        """
        Returns the identifier used as the right-hand side of the database
        sort key.
        """
        return self.role_arn
