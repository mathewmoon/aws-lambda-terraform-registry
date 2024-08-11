#!/usr/bin/env python3
from functools import wraps
from typing import Any, Callable

from fastapi import Request

from .bearer import Auth, get_auth_type
from .exceptions import AuthError


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
        auth_header = None
        try:
            token = req.query_params["x_registry_auth"]
        except KeyError:
            raise AuthError("Missing or invalid credentials", status=401)

    if auth_header:
        try:
            token = auth_header.split(" ")[1]
        except (KeyError, IndexError):
            raise AuthError("Missing or invalid credentials", status=401)

    auth_cls = get_auth_type(token)
    return auth_cls(namespace=namespace, token=token)


def is_authenticated(req: Request) -> bool:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    
    authenticate(req)

    return True


def download_auth(req: Request) -> True:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    namespace = req.path_params["namespace"]
    auth = authenticate(req)

    if not (auth and auth.can_download(namespace)):
        raise AuthError(
            f"Not authorized to download from namespace {namespace}",
            status=403,
        )

    return True


def upload_auth(req: Request) -> None:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    path_params = req.path_params

    namespace = path_params["namespace"]

    auth = authenticate(req)

    if not (auth and auth.can_upload(namespace)):
        raise AuthError(status=403)

    return True


def auth_wrapper(authorizor: Callable):
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
            authorizor(request)

            return await func(*args, request=request, **kwargs)

        return inner

    return wrapper
