#!/usr/bin/env python3
from json import dumps

from fastapi import Response, Request

from . import make_lambda_response
from .. import routes
from ..auth import parse_assumed_role
from ..auth.bearer import IAMBearerAuth
from ..auth.exceptions import AuthError
from ..config import (
    APP,
    MANGUM,
    LOGGER,
    MAX_TOKEN_EXPIRATION_WINDOW,
)


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
    params = event.get("queryStringParameters", {})
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

    try:
        res = MANGUM(event, ctx)
        LOGGER.info(dumps(res, indent=2, default=lambda x: str(x)))
        return res
    except AuthError as e:
        LOGGER.info(dumps(e.response, indent=2, default=lambda x: str(x)))
        return make_lambda_response(status=e.status, body=str(e))
    except Exception as e:
        LOGGER.exception(e)
        return make_lambda_response(status=500, body="Internal Server Error...")
