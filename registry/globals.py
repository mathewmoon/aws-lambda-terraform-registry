#!/usr/bin/env python3
from functools import lru_cache
from json import load
from logging import getLogger, StreamHandler
from os import environ, path
from sys import stdout
from typing import Self

from boto3 import client, resource
from botocore.config import Config
from pydantic import BaseModel, field_validator, PrivateAttr


class _RegistryConfig(BaseModel):
    table_name: str = "terraform-registry"
    max_token_expration_window: int = 60000
    base_url: str = "/v1/modules"
    iam_auth_kms_key: str = "alias/terraform-registry"
    disable_auth: bool = False
    no_verify_jwt_exp: bool = False
    jwt_issuer: str = "http://localhost:8000"
    hostname: str = "localhost:8000"
    log_level: str = "INFO"

    def __init__(self, *args, **kwargs) -> None:
        cur_dir = path.dirname(path.realpath(__file__))
        config_name = path.join(cur_dir, "config.json")
        if path.isfile(config_name):
            with open(config_name, "r") as f:
                additional_config = load(f)
                kwargs.update(additional_config)

        environ_args = {
            k.lower().replace("registry_config_", "", 1): v
            for k, v in environ.items()
            if k.startswith("REGISTRY_CONFIG_")
        }
        kwargs.update(environ_args)

        for k, v in kwargs.items():
            if isinstance(v, str) and v.lower() in ["true", "false"]:
                kwargs[k] = True if v.lower() == "true" else False

        super().__init__(*args, **kwargs)

    @field_validator("max_token_expration_window")
    def check_max_token_expration_window(cls, value: str | int) -> int:
        return int(value)


# Stupid way to make a singleton for a class that inherits from BaseModel
class RegistryConfig:
    _instance: _RegistryConfig = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = _RegistryConfig(*args, **kwargs)

        return cls._instance


class Clients:
    instance: Self = None

    def __init__(self) -> None:
        self.config = RegistryConfig()

        self.__table = resource("dynamodb").Table(self.config.table_name)
        self.__s3 = client("s3", config=Config(signature_version="s3v4"))
        self.__kms = client("kms")

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super().__new__(cls, *args, **kwargs)

        return cls.instance

    @property
    def table(self):
        return self.__table

    @property
    def s3(self):
        return self.__s3

    @property
    def kms(self):
        return self.__kms


logger = getLogger(__name__)

if not environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    logger.addHandler(StreamHandler(stdout))

logger.setLevel(RegistryConfig().log_level)
