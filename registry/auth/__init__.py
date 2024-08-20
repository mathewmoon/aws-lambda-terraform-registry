#!/usr/bin/env python3
from abc import ABC, abstractmethod
from base64 import urlsafe_b64encode
from enum import auto, StrEnum
from json import dumps
from time import time
from typing import Self
from pydantic import BaseModel, model_validator

from boto3.dynamodb.types import Binary

from ..globals import Clients, RegistryConfig


class Permissions(BaseModel):
    download: bool = False
    upload: bool = False
    create_grant: bool = False
    delete_grant: bool = False


class Operation(StrEnum):
    download = auto()
    upload = auto()
    create_grant = auto()
    delete_grant = auto()


class _AuthBase:
    pass


class Auth(BaseModel, ABC, _AuthBase):
    token: str
    namespace: str

    @model_validator(mode="after")
    def model_validator(self) -> Self:
        """
        Abstract method to validate the token.
        Must be implemented by subclasses.

        :raises NotImplementedError: If not implemented in subclass.
        """
        self.validate()
        return self

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

    @property
    def grant(self):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        key = self.get_db_key(namespace=self.namespace, identifier=self.identifier)
        res = Clients().table.get_item(Key=key).get("Item")

        return res

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
    def get_identifier(cls, *, issuer: str, subject: str):
        """
        Constructs the identifier for the grant.

        :return: The identifier string.
        """
        return f"{issuer}~{subject}"

    @classmethod
    def get_grant(cls, *, namespace: str, identifier: str):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        key = cls.get_db_key(namespace=namespace, identifier=identifier)
        res = Clients().table.get_item(Key=key).get("Item")
        return res

    @classmethod
    def unmarshall(cls, item: any):
        if isinstance(item, dict):
            for k, v in item.items():
                item[k] = cls.unmarshall(v)

        if isinstance(item, list):
            for i, v in enumerate(item):
                item[i] = cls.unmarshall(v)

        if isinstance(item, BaseModel):
            item = cls.unmarshall(item.model_dump())

        if isinstance(item, StrEnum):
            item = item.value

        if isinstance(item, Binary):
            item = bytes(item)

        return item

    @classmethod
    def create_grant(
        cls,
        *,
        identifier: str,
        namespace: str,
        permissions: Permissions = Permissions(),
        **kwargs: dict[str, any],
    ):
        """
        Creates an item dictionary with namespace, identifier, and permissions.

        :param permissions: A dictionary of permissions.
        :return: A dictionary representing the item.
        """
        key = cls.get_db_key(namespace=namespace, identifier=identifier)

        kwargs = cls.unmarshall(kwargs)
        permissions = cls.unmarshall(permissions)

        item = {
            **key,
            "namespace": namespace,
            "identifier": identifier,
            "permissions": permissions,
            **kwargs,
        }

        Clients().table.put_item(Item=item)

        return item

    @classmethod
    def delete_grant(cls, *, namespace: str, identifier: str):
        key = cls.get_db_key(namespace=namespace, identifier=identifier)
        Clients().table.delete_item(Key=key)

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

    def can(self, op: Operation):
        return self.grant and self.grant.get("permissions", {}).get(op, False)


def parse_assumed_role(role_arn):
    """
    Handles parsing of assumed role ARNs to IAM role ARNs.
    """
    role_arn_with_session = role_arn.replace(":sts:", ":iam:").replace(
        ":assumed-role/", ":role/"
    )
    role_parts = role_arn_with_session.split("/")
    role_parts.pop(-1)

    if role_parts[-1].startswith("AWSReservedSSO_"):
        role_parts[-1] = f"aws-reserved/sso.amazonaws.com/{role_parts[-1]}"

    role_arn = "/".join(role_parts)

    return role_arn


def make_token_for_iam(
    role_arn: str, expiration_seconds: int = RegistryConfig().max_token_expration_window
):
    """
    Creates a token for the given role ARN with an expiration time.

    :param role_arn: The Amazon Resource Name (ARN) of the role.
    :param expiration_seconds: The number of seconds until the token expires.
    :return: The generated token.
    :raises AuthError: If the expiration window is too large.
    """
    if expiration_seconds > RegistryConfig().max_token_expration_window:
        raise ValueError(
            f"Expiration window is too large. Max is {RegistryConfig().max_token_expration_window} seconds",
        )

    now = int(time())
    expiration = now + expiration_seconds

    opts = {
        "aud": RegistryConfig().hostname,
        "expiration_hours": expiration,
        "iss": RegistryConfig().jwt_issuer,
        "sub": role_arn,
    }

    header = (
        urlsafe_b64encode(
            dumps(
                {"kid": f"kms:{RegistryConfig().iam_auth_kms_key}", "alg": "RS256"}
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    payload = urlsafe_b64encode(dumps(opts).encode()).decode().rstrip("=")
    message = f"{header}.{payload}"

    res = Clients().kms.sign(
        KeyId=RegistryConfig().iam_auth_kms_key,
        Message=message.encode(),
        MessageType="RAW",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )["Signature"]

    signature = urlsafe_b64encode(res).decode().rstrip("=")
    token = f"{message}.{signature}"

    return token
