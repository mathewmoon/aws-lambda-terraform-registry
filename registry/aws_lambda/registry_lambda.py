#!/usr/bin/env python3
from json import dumps
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from pydantic import ValidationError
from ..auth import parse_assumed_role
from ..models import Module
from ..config import (
    APP,
    MANGUM,
    BASE_URI,
    LOGGER,
    MAX_TOKEN_EXPIRATION_WINDOW,
)
from ..auth.bearer import IAMBearerAuth
from ..auth.middleware import auth_wrapper
from ..auth.exceptions import AuthError
from .. import routes


@APP.exception_handler(Exception)
def custom_exceptions(_: Any, e: Exception):
    if isinstance(e, ValidationError):
        try:
            msg = str(e).split("\n")[1]
        except IndexError:
            msg = str(e)
        return Response(status_code=400, content=msg, media_type="text/plain")

    if isinstance(e, ValueError):
        return Response(status_code=400, content=str(e), media_type="text/plain")

    if isinstance(e, AuthError):
        return Response(status_code=e.status, content=str(e), media_type="text/plain")

    LOGGER.exception(e)

    return JSONResponse(
        status_code=500, content={"message": "Internal Server Error", "code": 500}
    )


@APP.get(routes.well_known)
async def discovery() -> dict:
    """
    Endpoint for serving the Terraform discovery JSON.

    Returns:
        dict: The Terraform discovery JSON.
    """
    data = {"modules.v1": BASE_URI}
    return data


@APP.get(routes.versions)
@auth_wrapper("download")
async def get_versions(namespace: str, system: str, name: str, _: Request) -> Response:
    """
    Endpoint for retrieving the versions of a Terraform module.

    Args:
        namespace (str): The namespace of the module.
        system (str): The system of the module.
        name (str): The name of the module.

    Returns:
        dict: The response containing the versions of the module.
    """
    versions = Module.versions(namespace=namespace, system=system, name=name)

    return JSONResponse(
        status_code=200, content=versions, media_type="application/json"
    )


@APP.get(routes.get_download_url)
@auth_wrapper("download")
async def get_download_url(
    namespace: str, system: str, name: str, version: str, _: Request
) -> Response:
    """
    Returns back the download URL for the module inside of the response headers.
    """
    module = Module.get(namespace=namespace, system=system, name=name, version=version)

    if not module:
        return Response(status_code=404, body="Module not found")

    url = module.presigned_url()

    return Response(status_code=204, headers={"X-Terraform-Get": url})


@APP.post(routes.create)
@auth_wrapper("upload")
async def upload_module(
    namespace: str,
    system: str,
    name: str,
    version: str,
    request: Request,
) -> Response:
    post_data = await request.json()

    module = Module.get(namespace=namespace, system=system, name=name, version=version)

    if module:
        return Response(
            status_code=409, content="Module already exists", media_type="text/plain"
        )

    module = Module(
        namespace=namespace, system=system, name=name, version=version, **post_data
    )
    module.create()

    return JSONResponse(status_code=201, content=module.model_dump())


@APP.get(routes.iam_token_endpoint)
def get_token(request: Request) -> str:
    """
    Endpoint for generating temporary credentials based on IAM auth

    Returns:
        str: The response containing the temporary credentials.
    """
    event = request.scope["aws.event"]
    req_ctx = event["requestContext"]
    authorizor = req_ctx.get("authorizer", req_ctx.get("identity"))
    user_arn = authorizor.get("iam", {}).get("userArn") or authorizor["userArn"]

    role_arn = parse_assumed_role(user_arn)
    params = event.get("queryStringParameters", {}) or {}

    expiration_seconds = int(
        params.get("expiration_seconds", MAX_TOKEN_EXPIRATION_WINDOW)
    )

    token = IAMBearerAuth.make_token(
        role_arn=role_arn,
        expiration_seconds=expiration_seconds,
    )
    return Response(status_code=200, content=token, media_type="text/plain")


def handler(event, ctx):
    """
    Lambda handler function.

    Args:
        event: The Lambda event object.
        ctx: The Lambda context object.

    Returns:
        Any: The response from the Mangum handler.
    """
    LOGGER.debug(dumps(event, indent=2, default=lambda x: str(x)))

    res = MANGUM(event, ctx)

    LOGGER.debug(dumps(res, indent=2, default=lambda x: str(x)))

    return res
