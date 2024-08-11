#!/usr/bin/env python3
from logging import getLogger, StreamHandler
from os import environ
from sys import stdout

from boto3 import client, resource
from botocore.config import Config
from fastapi import FastAPI
from mangum import Mangum

TABLE_NAME = environ.get("TABLE", "terraform-registry")
TABLE = resource("dynamodb").Table(TABLE_NAME)
S3 = client("s3", config=Config(signature_version="s3v4"))
KMS = client("kms")
RESOLVER_TYPE = environ.get("RESOLVER_TYPE", "FUNCTION_URL")
MAX_TOKEN_EXPIRATION_WINDOW = 60000
APP = FastAPI()
MANGUM = Mangum(APP, lifespan="off")
BASE_URI = "/v1/modules"
LOGGER = getLogger(__name__)
IAM_AUTH_KMS_KEY = environ.get("IAM_AUTH_KMS_KEY", "alias/terraform-registry")


if not environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    LOGGER.addHandler(StreamHandler(stdout))

LOGGER.setLevel(environ.get("LOG_LEVEL", "INFO"))
