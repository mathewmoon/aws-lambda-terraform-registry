#!/usr/bin/env python3
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from time import time
from hashlib import sha256
from random import choice
from string import ascii_letters, digits


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

    def get_db_key(self):
        """
        Constructs the database key for the namespace and identifier.

        :return: A dictionary representing the database key.
        """
        key = {
            "pk": self.namespace,
            "sk": f"{self.__class__.__name__}~{self.identifier}",
        }

        return key

    def make_item(self, permissions: dict[str, dict] = {}):
        """
        Creates an item dictionary with namespace, identifier, and permissions.

        :param permissions: A dictionary of permissions.
        :return: A dictionary representing the item.
        """
        key = self.get_db_key()
        item = {
            **key,
            "namespace": self.namespace,
            "identifier": self.identifier,
            "permissions": permissions,
        }

        return item

    @property
    def item(self):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        key = self.get_db_key()
        res = TABLE.get_item(Key=key).get("Item")

        if res is None:
            res = self.make_item()

        return res

    def put(self, permissions: dict[str, dict] = {}):
        """
        Updates the item in the database with new permissions.

        :param permissions: A dictionary of permissions.
        :return: The updated item dictionary.
        """
        item = self.item
        perms = {}

        for system, ns_perms in permissions.items():
            perm = {
                "download": ns_perms.get("download", False),
                "upload": ns_perms.get("upload", False),
            }
            perms[system] = perm

        item = self.make_item(permissions=perms)
        TABLE.put_item(Item=item)

        return self.item

    @property
    def permissions(self):
        """
        Retrieves the permissions from the item.

        :return: A dictionary of permissions.
        """
        return self.item.get("permissions", {})

    def can_download(self, system: str):
        """
        Checks if the download permission is granted for a given system.

        :param system: The system to check.
        :return: True if download is permitted, False otherwise.
        """
        return self.item.get("permissions", {}).get(system, {}).get("download", False)

    def can_upload(self, system: str):
        """
        Checks if the upload permission is granted for a given system.

        :param system: The system to check.
        :return: True if upload is permitted, False otherwise.
        """
        return self.item.get("permissions", {}).get(system, {}).get("upload", False)

    @property
    def systems(self):
        """
        Retrieves the list of systems from the permissions.

        :return: A list of system strings.
        """
        return list(self.permissions.keys())


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
        IAMBearer~<role_arn>~<encrypted_data>
    Encrypted data is a base64-encoded KMS-encrypted string of the format:
        <role_arn> <expiration>
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
            raise AuthError(
                f"Expiration window is too large. Max is {MAX_TOKEN_EXPIRATION_WINDOW} seconds",
                status=400,
            )

        now = int(time())
        expiration = now + expiration_seconds
        str_to_encrypt = f"{role_arn} {expiration}"
        res = KMS.encrypt(
            KeyId=IAM_AUTH_KMS_KEY,
            Plaintext=str_to_encrypt.encode(),
        )["CiphertextBlob"]

        res = b64encode(res).decode()
        token = f"{cls.__name__}~{role_arn}~{res}"

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

        if self.decrypted_token.split(" ")[0] != self.role_arn:
            raise AuthError("Token does not match the role arn")

    @property
    def role_arn(self):
        """
        Extracts the role ARN from the token.

        :return: The role ARN.
        :raises AuthError: If the token format is invalid.
        """
        try:
            arn = self.token.split("~")[1]
        except IndexError:
            raise AuthError("Invalid token format")
        return arn

    @property
    def decrypted_token(self):
        """
        Returns the decrypted token data from the encrypted part of the token
        as a string.
        """
        token_parts = self.token.split("~")
        try:
            encrypted_data = token_parts[2]
        except IndexError:
            raise AuthError("Invalid token format")

        ciphertext = b64decode(encrypted_data)

        try:
            decrypted_token = KMS.decrypt(
                KeyId=IAM_AUTH_KMS_KEY, CiphertextBlob=ciphertext
            )["Plaintext"].decode()
        except Exception as e:
            LOGGER.exception(e)
            raise AuthError(f"Token decryption failed")

        return decrypted_token

    @property
    def expiration(self):
        """
        Returns the expiration time of the token as a Unix timestamp.
        """
        parts = self.decrypted_token.split(" ")
        if len(parts) != 2:
            raise AuthError(
                "Invalid encrypted token format. Expected '<role arn> <expiration>'"
            )

        return int(parts[1])

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
