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
    """
    A base class for authentication authenticating users. Subclasses
    are expected to be able to validate, authorize, authenticate, and generate tokens.
    """
    def __init__(self, token: str, tenant: str):
        self.token = token
        self.tenant = tenant
        self.validate()


    @property
    def auth_type(self):
        return self.__class__.__name__

    @abstractmethod
    def validate(self):
        """
        Validate the token and raise an exception if it is invalid.
        If no exception is raised, the token is valid.
        """
        raise NotImplementedError


    @classmethod
    @abstractmethod
    def make_token(cls):
        """
        Generate a token and return it to the caller.
        """
        raise NotImplementedError


    def get_db_key(self):
        """
        Generate the hash key for the database item.
        """
        key = {
            "pk": self.tenant,
            "sk": f"{self.__class__.__name__}~{self.identifier}"
        }

        return key


    def make_item(self, permissions: dict[str, dict] = {}):
        """
        Prepare a DB item for insertion.
        """
        key = self.get_db_key()
        item = {
            **key,
            "tenant": self.tenant,
            "identifier": self.identifier,
            "permissions": permissions
        }

        return item

    @property
    def item(self):
        """
        Retrieve the item from the database or create a new one if it doesn't exist.
        """
        key = self.get_db_key()
        try:
            res = TABLE.get_item(Key=key).get("Item")
        except TABLE.meta.client.exceptions.ResourceNotFoundException:
            res = None

        if res is None:
            res = self.make_item()

        return res


    def put(self, permissions: dict[str, dict] = {}):
        """
        Save the item to the database, overwriting any existing item.
        """
        item = self.item
        perms = {}

        for namespace, ns_perms in permissions.items():
            perm = {
                "download": ns_perms.get("download", False),
                "upload": ns_perms.get("upload", False)
            }
            perms[namespace] = perm           

        item = self.make_item(permissions=perms)
        TABLE.put_item(Item=item)
        
        return self.item

    @property
    def permissions(self):
        return self.item.get("permissions", {})

    def can_download(self, namespace: str):
        return self.item.get("permissions", {}).get(namespace, {}).get("download", False)

    def can_upload(self, namespace: str):
        return self.item.get("permissions", {}).get(namespace, {}).get("upload", False)

    @property
    def namespaces(self):
        return list(self.permissions.keys())


class BearerAuth(Auth):
    min_token_length = 64


    def validate(self):
        if self.token < self.min_token_length:
            raise AuthError(f"Token must be at least {self.min_token_length} characters long")

    @property
    def identifier(self):
        return sha256(self.token.encode()).hexdigest()

    @classmethod
    def make_token(cls):
        letters = ascii_letters + digits
        random_str = "".join(choice(letters) for _ in range(cls.min_token_length))
        return f"{cls.__name__}-{random_str}"


class IAMBearerAuth(BearerAuth):
    """
    token: str - The token to use for authentication. Formatted as "IAMBearerAuth~<encrypted data>"
    Encrypted data is formatted as "<role_arn> <expiration>"
    """

    @classmethod
    def make_token(cls, role_arn: str, expiration_seconds: int = MAX_TOKEN_EXPIRATION_WINDOW):
        if expiration_seconds > MAX_TOKEN_EXPIRATION_WINDOW:
            raise AuthError(
                f"Expiration window is too large. Max is {MAX_TOKEN_EXPIRATION_WINDOW} seconds",
                status=400
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
        now = int(time()) + 20

        if now > self.expiration:
            raise AuthError("Token has expired")

        if self.expiration - now > MAX_TOKEN_EXPIRATION_WINDOW:
            raise AuthError(f"Token expiration is too far in the future. Max window is {MAX_TOKEN_EXPIRATION_WINDOW} seconds")

        if self.decrypted_token.split(" ")[0] != self.role_arn:
            raise AuthError("Token does not match the role arn")

    @property
    def role_arn(self):
        try:
            arn = self.token.split("~")[1]
        except IndexError:
            raise AuthError("Invalid token format")

        return arn

    @property
    def decrypted_token(self):
        token_parts = self.token.split("~")
        try:
            encrypted_data = token_parts[2]
        except IndexError:
            raise AuthError("Invalid token format")

        ciphertext = b64decode(encrypted_data)

        try:
            decrypted_token = KMS.decrypt(
                KeyId=IAM_AUTH_KMS_KEY,
                CiphertextBlob=ciphertext
            )["Plaintext"].decode()
        except Exception as e:
            LOGGER.exception(e)
            raise AuthError(f"Token decryption failed")

        return decrypted_token


    @property
    def expiration(self):
        parts = self.decrypted_token.split(" ")
        if len(parts) != 2:
            raise AuthError("Invalid encrypted token format. Expected '<role arn> <expiration>'")

        return int(parts[1])


    @property
    def identifier(self):
        return self.role_arn


def get_auth_type(token):
    cls_name = token.split("~")[0]
    try:
        cls = globals()[cls_name]
        assert issubclass(cls, Auth)  # Extremely important to prevent code injection
        return cls
    except (KeyError, AssertionError):
        raise AuthError(f"Invalid token type {cls_name}")
