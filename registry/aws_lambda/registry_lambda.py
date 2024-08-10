#!/usr/bin/env python3
from base64 import b64decode
from json import dumps

from aws_lambda_powertools.event_handler.api_gateway import Response

from . import make_lambda_response
from ..models import Module
from ..config import (
    APP,
    BASE_URI,
    LOGGER,
)
from ..auth.middleware import download_auth, upload_auth
from ..auth.exceptions import AuthError
from .. import routes


@APP.get(routes.well_known)
def discovery() -> dict:
    """
    Endpoint for serving the Terraform discovery JSON.

    Returns:
        dict: The Terraform discovery JSON.
    """
    data = {"modules.v1": BASE_URI}
    return data


@APP.get(routes.versions, middlewares=[download_auth])
def get_versions(namespace, system, name) -> Response:
    """
    Endpoint for retrieving the versions of a Terraform module.

    Args:
        namespace (str): The namespace of the module.
        system (str): The system of the module.
        name (str): The name of the module.

    Returns:
        dict: The response containing the versions of the module.
    """
    module = Module(namespace=namespace, system=system, name=name)
    versions = module.versions

    return Response(status_code=200, body=versions, content_type="application/json")


@APP.get(routes.get_download_url, middlewares=[download_auth])
def get_download_url(namespace: str, system: str, name: str, version: str) -> Response:
    """
    Returns back the download URL for the module inside of the response headers.
    """
    module = Module(
        namespace=namespace,
        system=system,
        name=name,
    )

    version = module.get_version(version)

    if not version:
        return Response(status_code=404, body="Module not found")

    return Response(status_code=204, headers={"X-Terraform-Get": module.download_url})


@APP.get(routes.download, middlewares=[download_auth])
def download(namespace, system, name, version) -> Response:
    """
    Downloads the module.
    """
    module = Module(
        namespace=namespace,
        system=system,
        name=name,
    )
    version = module.get_version(version)

    if not version:
        return Response(status_code=404, body="Module not found")

    if not version.get("zipfile"):
        url = module.presigned_url(version)

        return Response(
            status_code=302,
            headers={"Location": url},
        )

    return Response(
        status_code=200,
        body=version["zipfile"],
        headers={"Content-Type": "application/zip"},
    )


@APP.post(routes.upload_module, middlewares=[upload_auth])
def upload_module(
    namespace: str, system: str, name: str, version: str, zipfile: str
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
    return Response(status_code=201, body=res)


@APP.get(routes.create_module, middlewares=[upload_auth])
def create_module():
    raise NotImplementedError("Create module endpoint not implemented")


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
    LOGGER.info(APP)
    LOGGER.info(type(APP))

    try:
        res = APP.resolve(event, ctx)
        LOGGER.info(dumps(res, indent=2, default=lambda x: str(x)))
        return res
    except AuthError as e:
        LOGGER.info(dumps(e.response, indent=2, default=lambda x: str(x)))
        return make_lambda_response(status=e.status, body=str(e))
    except Exception as e:
        LOGGER.exception(e)
        return make_lambda_response(status=500, body="Internal Server Error...")
