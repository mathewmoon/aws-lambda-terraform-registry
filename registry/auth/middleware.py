#!/usr/bin/env python3
from functools import wraps
from typing import Any, Callable

from fastapi import Request

from . import Auth, _AuthBase
from .exceptions import AuthError
from .jwt import JWTAuth
from .bearer import BearerAuth, IAMBearerAuth
from ..globals import RegistryConfig

config = RegistryConfig()


def parse_path(event: dict) -> dict:
    """
    Returns the namespace and system from the path.
    """
    try:
        path = event["rawPath"]
    except KeyError:
        path = event["path"]
    parts = path.lstrip("/").split("/")[2:4]

    return tuple(parts)


def get_header(req: Request, name: str) -> Any:
    """
    Returns the value of a specific header by name.
    """
    try:
        return req.headers[name]
    except KeyError:
        return req.headers[name.lower()]


def authenticate(req: Request) -> Auth:
    """
    Initializes an Auth object based on the token in the Authorization header
    and returns it.
    """
    namespace = req.path_params["namespace"]
    try:
        auth_header = get_header(req, "Authorization")
    except KeyError:
        raise AuthError("Missing Auth header", status=401)
    if not auth_header:
        raise AuthError("Missing or invalid credentials", status=401)

    if auth_header:
        try:
            token = auth_header.split(" ")[1]
        except (KeyError, IndexError):
            raise AuthError("Missing or invalid credentials", status=401)

    auth_cls = get_auth_type(token)
    return auth_cls(namespace=namespace, token=token)


def auth_wrapper(*perms: str) -> Callable:
    """
    Decorator function for checking user permissions.

    Args:
        permission (Operation): The required permission for the decorated function.

    Returns:
        Callable: The decorated function.
    """

    def wrapper(func):
        @wraps(func)
        async def inner(*args, request: Request, **kwargs):
            if config.disable_auth:
                return await func(*args, request=request, **kwargs)

            auth = authenticate(request)
            for perm in perms:
                if not auth.can(perm):
                    raise AuthError(
                        f"Not authorized to {perm} in namespace {auth.namespace}",
                        status=403,
                    )

            return await func(*args, request=request, **kwargs)

        return inner

    return wrapper


#!/usr/bin/env python3
from abc import ABC, abstractmethod
from enum import auto, StrEnum
from typing import Self
from pydantic import BaseModel, model_validator


from .exceptions import AuthError
from ..globals import Clients


clients = Clients()


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


class Auth(BaseModel, ABC):
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

    @classmethod
    @abstractmethod
    def make_token(cls):
        """
        Abstract class method to create a token.
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
        res = clients.table.get_item(Key=key).get("Item")

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
        res = clients.table.get_item(Key=key).get("Item")
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

        clients.table.put_item(Item=item)

        return item

    @classmethod
    def delete_grant(cls, *, namespace: str, identifier: str):
        key = cls.get_db_key(namespace=namespace, identifier=identifier)
        clients.table.delete_item(Key=key)

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


def get_auth_type(token):
    """
    A factory for returing Auth subclasses based on the token
    characteristics.
    """
    cls_name = token.split("~")[0]
    try:
        cls = globals()[cls_name]
        assert issubclass(
            cls, _AuthBase
        )  # Extremely important to prevent code injection
        return cls
    except (KeyError, AssertionError):
        raise AuthError(f"Invalid token type {cls_name}")
