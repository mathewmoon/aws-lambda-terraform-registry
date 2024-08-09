#!/usr/bin/env python3

from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

from .types import get_auth_type
from .exceptions import AuthError


def parse_path(path: str) -> dict:
    parts = path.lstrip("/").split("/")[2:4]

    return tuple(parts)


def authenticate(event):
    tenant, _ = parse_path(event["rawPath"])

    try:
        token = event["headers"]["authorization"].split(" ")[1]
    except (KeyError, IndexError):
        raise AuthError("Missing or invalid credentials", status=401)

    auth_cls = get_auth_type(token)
    return auth_cls(tenant=tenant, token=token)


def is_authenticated(app: object, next_middleware: NextMiddleware) -> Response:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    event = app.current_event
    authenticate(event)

    return next_middleware(app)


def download_auth(app: object, next_middleware: NextMiddleware) -> Response:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    event = app.current_event
    tenant, namespace = parse_path(event["rawPath"])
    auth = authenticate(event)

    if not (auth and auth.can_download(namespace)):
        raise AuthError(f"Not authorized to download from namespace {namespace} in tenant {tenant}", status=403)

    return next_middleware(app)


def upload_auth(app: object, next_middleware: NextMiddleware) -> Response:
    """
    Middleware for authenticating requests.

    Args:
        app (Resolver): The Resolver object.
        next_middleware (NextMiddleware): The NextMiddleware object.

    Returns:
        Response: The response object.
    """
    event = app.current_event
    _, namespace = parse_path(event["rawPath"])
    auth = authenticate(event)

    if not (auth and auth.can_upload(namespace)):
        raise AuthError(status=403)

    return next_middleware(app)
