#!/usr/bin/env python3
from functools import wraps, lru_cache
from typing import Any, Callable

from fastapi import Request
from jwt import decode as jwt_decode
from . import Auth
from .jwt import JWTAuth
from .exceptions import AuthError
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


def is_jwt_auth(token: str) -> bool:
    """
    Returns True if the token appears to be a JWT token.
    """
    try:
        jwt_decode(token, options={"verify_signature": False})
        return True
    except Exception:
        return False


@lru_cache(maxsize=64)
def get_auth_type(token):
    """
    A factory for returing Auth subclasses based on the token
    characteristics.
    """
    if is_jwt_auth(token):
        return JWTAuth
