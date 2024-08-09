#!/usr/bin/env python3
from json import dumps

from aws_lambda_powertools.event_handler.api_gateway import Response

from . import make_lambda_response
from .. import routes 
from ..auth.bearer import IAMBearerAuth
from ..auth.exceptions import AuthError
from ..config import (
    APP,
    LOGGER,
    MAX_TOKEN_EXPIRATION_WINDOW,
)

def parse_assumed_role(role_arn):
    role_arn_with_session = role_arn.replace(":sts:", ":iam:").replace(":assumed-role/", ":role/")
    role_parts = role_arn_with_session.split("/")
    role_parts.pop(-1)

    if role_parts[-1].startswith("AWSReservedSSO_"):
        print("SSO")
        role_parts[-1] = f"aws-reserved/sso.amazonaws.com/{role_parts[-1]}"

    role_arn = "/".join(role_parts)

    return role_arn


@APP.get(routes.iam_token_endpoint)
def get_token() -> str:
    """
    Endpoint for generating temporary credentials based on IAM auth

    Returns:
        str: The response containing the temporary credentials.
    """
    authorizor = APP.current_event["requestContext"]["authorizer"]
    user_arn = authorizor["iam"]["userArn"]
    role_arn = parse_assumed_role(user_arn)
    params = APP.current_event.get("queryStringParameters", {})
    expiration_seconds = int(params.get("expiration_seconds", MAX_TOKEN_EXPIRATION_WINDOW))

    token = IAMBearerAuth.make_token(
        role_arn=role_arn,
        expiration_seconds=expiration_seconds,
    )
    return Response(status_code=200, body=token, content_type="text/plain")


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
        return make_lambda_response(status=e.status, body=str(e) )
    except Exception as e:
        LOGGER.exception(e)
        return make_lambda_response(status=500, body="Internal Server Error...")

