#!/usr/bin/env python3
from json import dumps
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from pydantic import ValidationError

from .. import routes
from ..auth import parse_assumed_role
from ..models import (
    Module,
    ModuleStorage,
    DiscoveryResponse,
    VersionsResponse,
    url_response,
)
from ..config import (
    APP,
    MANGUM,
    LOGGER,
    MAX_TOKEN_EXPIRATION_WINDOW,
)
from ..auth.bearer import IAMBearerAuth
from ..auth.middleware import auth_wrapper
from ..auth.exceptions import AuthError


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


@APP.get(routes.well_known, response_model=DiscoveryResponse)
async def discovery(request: Request) -> Response:
    """
    Endpoint for serving the Terraform discovery JSON.

    Returns:
        dict: The Terraform discovery JSON.
    """
    data = JSONResponse(status_code=200, content=DiscoveryResponse().model_dump())
    return data


@APP.get(routes.versions, response_model=VersionsResponse)
@auth_wrapper("download")
async def get_versions(
    namespace: str, system: str, name: str, request: Request
) -> Response:
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


@APP.get(routes.get_download_url, response_model=str, openapi_extra=url_response)
@auth_wrapper("download")
async def get_download_url(
    namespace: str, system: str, name: str, version: str, request: Request
) -> Response:
    """
    Returns back the download URL for the module inside of the response headers.
    """
    module = Module.get(namespace=namespace, system=system, name=name, version=version)

    if not module:
        return Response(status_code=404, body="Module not found")

    url = module.presigned_url()

    return Response(status_code=204, headers={"X-Terraform-Get": url})


@APP.post(routes.create, response_model=Module)
@auth_wrapper("upload")
async def create_module(
    namespace: str,
    system: str,
    name: str,
    version: str,
    request: Request,
    post_data: ModuleStorage,
) -> Response:
    """
    Creates a new module in the registry with the given namespace, system, name, and version.
    The checksum of the module is verified against the expected checksum. If the checksums match
    then the module is created in the registry with the checsum stored as part of the object. Subsequent
    downloads will validate that the checksum matches the expected checksum.
    """
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


@APP.get(routes.iam_token_endpoint, response_model=str, openapi_extra=url_response)
def get_token(request: Request) -> str:
    """
    Endpoint for generating temporary credentials based on IAM auth. Requests to this endpoint
    must be signed with SigV4 using AWS credentials.

    Returns:
        str: The response containing the temporary token to be used in API calls.
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
