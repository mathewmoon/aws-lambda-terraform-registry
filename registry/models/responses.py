#!/usr/bin/env python3
from typing import TypedDict

from pydantic import BaseModel

from ..globals import RegistryConfig


class DiscoveryResponse(TypedDict):
    modules_v1: str = RegistryConfig().base_url


class _VersionObj(TypedDict):
    version: str


class _VersionsObject(TypedDict):
    versions: list[_VersionObj]


class VersionsResponse(BaseModel):
    modules: list[_VersionsObject]


class UrlResponse(BaseModel):
    X_Terraform_Get: str


url_response = {
    "responses": {
        200: {
            "headers": {
                "X-Terraform-Get": {
                    "schema": {"type": "string"},
                    "description": "The download URL for the module",
                }
            }
        }
    }
}
