#!/usr/bin/env python3
from logging import getLogger, StreamHandler
from os import environ
from sys import stdout

from boto3 import client, resource


TABLE_NAME = environ.get("TABLE", "terraform-modules")
TABLE = resource("dynamodb").Table(TABLE_NAME)
REGISTRY_BUCKET = environ.get("REGISTRY_BUCKET", "hingehealth-sec-junkdrawer")
S3 = client("s3")
KMS = client("kms")
RESOLVER_TYPE = environ.get("RESOLVER_TYPE", "FUNCTION_URL")
MAX_TOKEN_EXPIRATION_WINDOW = 60000

if RESOLVER_TYPE == "FUNCTION_URL":
    from aws_lambda_powertools.event_handler import LambdaFunctionUrlResolver as Resolver
elif RESOLVER_TYPE == "API_GATEWAY_HTTP":
    from aws_lambda_powertools.event_handler import APIGatewayHttpResolver as Resolver
elif RESOLVER_TYPE == "API_GATEWAY_REST":
    from aws_lambda_powertools.event_handler import APIGatewayRestResolver as Resolver
elif RESOLVER_TYPE == "ALB":
    from aws_lambda_powertools.event_handler import ALBResolver as Resolver


APP = Resolver()
PROTO = environ.get("PROTO", "https://")
BASE_URI = "/v1/modules"
HOSTNAME = environ.get("HOSTNAME", "localhost:8000")
LOGGER = getLogger(__name__)
IAM_AUTH_KMS_KEY = environ.get("IAM_AUTH_KMS_KEY", "alias/terraform-registry")


if not environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    LOGGER.addHandler(StreamHandler(stdout))

LOGGER.setLevel(environ.get("LOG_LEVEL", "INFO")) 

