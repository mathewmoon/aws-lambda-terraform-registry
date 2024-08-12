#!/usr/bin/env python3
from base64 import b64decode
from io import BytesIO
from json import dumps
from typing import Any
from urllib.parse import urlencode
from tempfile import NamedTemporaryFile

from fastapi import Request
from fastapi.responses import JSONResponse, Response, StreamingResponse, FileResponse

from . import make_lambda_response
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
from ..auth.middleware import download_auth, upload_auth, auth_wrapper, get_header
from ..auth.exceptions import AuthError
from .. import routes


@APP.exception_handler(Exception)
def custom_exceptions(_: Any, e: Exception):
    if isinstance(e, ValueError):
        return Response(
            status_code=400, content=str(e)
        )

    if isinstance(e, AuthError):
        return Response(
            status_code=e.status, content=str(e)
        )

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
@auth_wrapper(download_auth)
async def get_versions(namespace: str, system: str, name: str, request: Request) -> Response:
    """
    Endpoint for retrieving the versions of a Terraform module.

    Args:
        namespace (str): The namespace of the module.
        system (str): The system of the module.
        name (str): The name of the module.

    Returns:
        dict: The response containing the versions of the module.
    """
    versions = Module.versions(
        namespace=namespace,
        system=system,
        name=name
    )
    versions = [{"version": v.version} for v in versions]
    res = {"modules": [{"versions": versions}]}

    return JSONResponse(status_code=200, content=res)


@APP.get(routes.get_download_url)
@auth_wrapper(download_auth)
async def get_download_url(namespace: str, system: str, name: str, version: str, request: Request) -> Response:
    """
    Returns back the download URL for the module inside of the response headers.
    """
    module = Module.get(
        namespace=namespace,
        system=system,
        name=name,
        version=version
    )


    if not module:
        return Response(status_code=404, body="Module not found")

    if module.zipfile:
        event = request.scope["aws.event"]
        cur_path = event["path"].lstrip("/")
        host = event["headers"]["Host"]

        role = get_header(request, "authorization").split("~")[1]

        token = IAMBearerAuth.make_token(
            role_arn=role,
            expiration_seconds=3000
        )

        params = urlencode({"x_registry_auth": token})
        url = f"https://{host}/{cur_path}/zip?{params}"

    else:
        url = module.presigned_url()

    return Response(status_code=204, headers={"X-Terraform-Get": url})


@APP.get(routes.download)
@auth_wrapper(download_auth)
async def download(namespace, system, name, version, request: Request) -> Response:
    """
    Downloads the module.
    """

    module = Module.get(
        namespace=namespace,
        system=system,
        name=name,
        version=version
    )

    if not module:
        return Response(status_code=404, body="Module not found")

    if zipfile := module.zipfile:
        LOGGER.info(f"Found zipfile for {module.module_path}")
        obj = BytesIO(zipfile.data)
        obj.seek(0)

        fname = f"{module.module_path}/{module.version}.zip".replace("/", "-")
        from os import path
        newpath = path.join(path.dirname(__file__), "test.zip")
        return FileResponse(newpath, headers={"Content-Disposition": f"attachment; filename={fname}"}, media_type="application/zip")
        with NamedTemporaryFile(mode="w+b", delete=False) as f:
            f.write(zipfile.data)
            f.seek(0)
            return Response(zipfile.data, headers={"Content-Type": "gzip"}, media_type="application/gzip")


@APP.post(routes.upload_module)
@auth_wrapper(upload_auth)
async def upload_module(
    namespace: str, system: str, name: str, version: str, zipfile: str, request: Request
) -> Response:
    module = Module(
        namespace=namespace,
        system=system,
        name=name,
    )

    if module.get_version(version):
        return Response(status_code=409, body="Module already exists")

    zipfile = b64decode(zipfile.encode())

    res = module.create_version(version=version, zipfile=zipfile)
    return Response(status_code=201, content=res)


@APP.get(routes.create_module)
@auth_wrapper(upload_auth)
async def create_module(request: Request) -> Response:
    raise NotImplementedError("Create module endpoint not implemented")


@APP.get(routes.iam_token_endpoint)
def get_token(request: Request) -> str:
    """
    Endpoint for generating temporary credentials based on IAM auth

    Returns:
        str: The response containing the temporary credentials.
    """
    event = request.scope["aws.event"]

    try:
        authorizor = event["requestContext"]["authorizer"]
    except KeyError:
        authorizor = event["requestContext"]["identity"]

    try:
        user_arn = authorizor["iam"]["userArn"]
    except KeyError:
        user_arn = authorizor["userArn"]

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
    LOGGER.info(dumps(event, indent=2, default=lambda x: str(x)))

    res = MANGUM(event, ctx)
    LOGGER.info(dumps(res, indent=2, default=lambda x: str(x)))
    return res