#!/usr/bin/env python3
from json import dumps

from aws_lambda_powertools.event_handler.api_gateway import Response

from ..models import Module
from ..config import (
    APP,
    BASE_URI,
    HOSTNAME,
    PROTO,
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
    data = {"modules.v1": f"{PROTO}{HOSTNAME}{BASE_URI}"}
    return data



@APP.get(routes.versions, middlewares=[download_auth])
def get_versions(tenant, namespace, name) -> Response:
    """
    Endpoint for retrieving the versions of a Terraform module.

    Args:
        tenant (str): The tenant of the module.
        namespace (str): The namespace of the module.
        name (str): The name of the module.

    Returns:
        dict: The response containing the versions of the module.
    """
    module = Module(
        tenant=tenant,
        namespace=namespace,
        name=name
    )
    versions = module.versions

    if not versions:
        return Response(status_code=404, body=f"Module {module.module_path} not found")

    res = {"modules": [{"versions": versions}]}

    return Response(status_code=200, body=res, content_type="application/json")


@APP.get(routes.download_module, middlewares=[download_auth])
def download_module(
    tenant, namespace, name, version
) -> Response:
    """
    Endpoint for downloading a specific version of a Terraform module.

    Args:
        tenant (str): The tenant of the module.
        namespace (str): The namespace of the module.
        name (str): The name of the module.
        version (str): The version of the module.

    Returns:
        Response: The response with the download link.
    """
    module = Module(
        tenant=tenant,
        namespace=namespace,
        name=name,
    )
    link = module.presigned_download(version=version)

    if link is None:
        return Response(status_code=404, body=f"Module {module.module_path} version {version} not found")

    return Response(status_code=204, headers={"X-Terraform-Get": link})


@APP.get(routes.upload_module, middlewares=[upload_auth])
def upload_module():
    raise NotImplementedError("Upload module endpoint not implemented")


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

    try:
        res = APP.resolve(event, ctx)
        LOGGER.info(dumps(res, indent=2, default=lambda x: str(x)))
        return res
    except AuthError as e:
        LOGGER.info(dumps(e.response, indent=2, default=lambda x: str(x)))
        return e.response
    except Exception as e:
        LOGGER.exception(e)
        return {"status_code":500, "body": "Internal Server Error"}

