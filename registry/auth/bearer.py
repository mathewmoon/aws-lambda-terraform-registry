#!/usr/bin/env python3
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from json import dumps, loads, JSONDecodeError
from time import time
from hashlib import sha256
from random import choice
from string import ascii_letters, digits
from typing import Any

from .exceptions import AuthError
from ..config import TABLE, KMS, MAX_TOKEN_EXPIRATION_WINDOW, IAM_AUTH_KMS_KEY, LOGGER


class Auth(ABC):
    def __init__(self, token: str, namespace: str):
        """
        Initialize the Auth object with a token and namespace.
        Validates the token upon initialization.

        :param token: The authentication token.
        :param namespace: The namespace identifier.
        """
        self.token = token
        self.namespace = namespace
        self.validate()

    @property
    def auth_type(self):
        """
        Returns the authentication type, which is the class name.

        :return: The name of the class.
        """
        return self.__class__.__name__

    @abstractmethod
    def validate(self):
        """
        Abstract method to validate the token.
        Must be implemented by subclasses.

        :raises NotImplementedError: If not implemented in subclass.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def make_token(cls):
        """
        Abstract class method to create a token.
        Must be implemented by subclasses.

        :raises NotImplementedError: If not implemented in subclass.
        """
        raise NotImplementedError

    @classmethod
    def get_db_key(cls, *, namespace: str, identifier: str):
        """
        Constructs the database key for the namespace and identifier.

        :return: A dictionary representing the database key.
        """
        key = {
            "pk": namespace,
            "sk": f"{cls.__name__}~{identifier}",
        }

        return key

    @classmethod
    def create_grant(
        cls,
        *,
        identifier: str,
        namespace: str,
        permissions: dict[str, dict[str, bool]] = {},
    ):
        """
        Creates an item dictionary with namespace, identifier, and permissions.

        :param permissions: A dictionary of permissions.
        :return: A dictionary representing the item.
        """
        key = cls.get_db_key(namespace=namespace, identifier=identifier)

        item = {
            **key,
            "namespace": namespace,
            "identifier": identifier,
            "permissions": permissions,
        }

        TABLE.put_item(Item=item)

        return item

    @classmethod
    def delete_grant(cls, *, namespace: str, identifier: str):
        key = cls.get_db_key(namespace=namespace, identifier=identifier)
        TABLE.delete_item(Key=key)

    @classmethod
    def update_permissions(
        cls,
        *,
        namespace: str,
        identifier: str,
        download: bool = None,
        upload: bool = None,
        create_grant: bool = None,
        delete_grant: bool = None,
    ):
        """
        Updates the item in the database with new permissions.

        :param permissions: A dictionary of permissions.
        :return: The updated item dictionary.
        """
        item = cls.get_grant(namespace=namespace, identifier=identifier)

        if item is None:
            raise ValueError(
                f"Not grant found for {identifier} in namespace {namespace}"
            )

        permissions = {
            "download": download,
            "upload": upload,
            "create_grant": create_grant,
            "delete_grant": delete_grant,
        }
        new_permissions = {k: v for k, v in permissions.items() if v is not None}
        permissions = {**item.get("permissions", {}), **new_permissions}

        return cls.create_grant(
            namespace=namespace, identifier=identifier, permissions=permissions
        )

    @property
    def permissions(self):
        """
        Retrieves the permissions from the item.

        :return: A dictionary of permissions.
        """
        return self.grant.get("permissions", {})

    def can(self, op: str):
        return self.grant and self.grant.get("permissions", {}).get(op, False)


class BearerAuth(Auth):
    """
    Handles simple Bearer Auth using static, non-expiring, tokens
    """

    min_token_length = 64

    def validate(self):
        """
        Validates the token by checking its length.

        :raises AuthError: If the token is shorter than the minimum length.
        """
        if len(self.token) < self.min_token_length:
            raise AuthError(
                f"Token must be at least {self.min_token_length} characters long"
            )

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
    Generates Bearer tokens that are encrypted with KMS, using a method that allows them to be
    used to verify the identity of the caller when used later.

    Tokens are created in the format:
        IAMBearer~<encrypted_data>
    Encrypted data is a base64-encoded KMS-encrypted JSON string of the format:
        {"role_arn": "<role_arn>", "expiration": <expiration_unix_timestamp>}
    """

    @classmethod
    def make_token(
        cls, role_arn: str, expiration_seconds: int = MAX_TOKEN_EXPIRATION_WINDOW
    ):
        """
        Creates a token for the given role ARN with an expiration time.

        :param role_arn: The Amazon Resource Name (ARN) of the role.
        :param expiration_seconds: The number of seconds until the token expires.
        :return: The generated token.
        :raises AuthError: If the expiration window is too large.
        """
        if expiration_seconds > MAX_TOKEN_EXPIRATION_WINDOW:
            raise ValueError(
                f"Expiration window is too large. Max is {MAX_TOKEN_EXPIRATION_WINDOW} seconds",
            )

        now = int(time())
        expiration = now + expiration_seconds

        payload = dumps({"role_arn": role_arn, "expiration": expiration}).encode()

        res = KMS.encrypt(
            KeyId=IAM_AUTH_KMS_KEY,
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

        if self.expiration - now > MAX_TOKEN_EXPIRATION_WINDOW:
            raise AuthError(
                f"Token expiration is too far in the future. Max window is {MAX_TOKEN_EXPIRATION_WINDOW} seconds"
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
            decrypted_token = KMS.decrypt(
                KeyId=IAM_AUTH_KMS_KEY, CiphertextBlob=ciphertext
            )["Plaintext"].decode()
        except Exception as e:
            LOGGER.exception(e)
            raise AuthError(f"Invalid Token")

        try:
            token = loads(decrypted_token)
        except JSONDecodeError:
            raise AuthError(f"Invalid Token")
        return token

    @classmethod
    def get_grant(cls, *, namespace: str, identifier: str):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        key = cls.get_db_key(namespace=namespace, identifier=identifier)
        res = TABLE.get_item(Key=key).get("Item")

        return res

    @property
    def grant(self):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        key = self.get_db_key(namespace=self.namespace, identifier=self.role_arn)
        res = TABLE.get_item(Key=key).get("Item")

        return res

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


def get_auth_type(token):
    """
    A factory for returing Auth subclasses based on the token
    characteristics.
    """
    cls_name = token.split("~")[0]
    try:
        cls = globals()[cls_name]
        assert issubclass(cls, Auth)  # Extremely important to prevent code injection
        return cls
    except (KeyError, AssertionError):
        raise AuthError(f"Invalid token type {cls_name}")
