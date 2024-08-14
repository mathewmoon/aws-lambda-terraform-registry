#!/usr/bin/env python3
from __future__ import annotations

from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import serialization
from enum import auto, StrEnum
from fnmatch import fnmatch
from json import dumps, loads
from re import compile
import jwt.algorithms
from requests import get
from time import time
from typing import Any, Dict, List, NamedTuple, Optional

from jwt.exceptions import (
    DecodeError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    ExpiredSignatureError,
    MissingRequiredClaimError,
)
import jwt

from pydantic import BaseModel

from . import Auth, Permissions, Operation
from .exceptions import AuthError

from ..config import LOGGER, NO_VERIFY_JWT_EXP


URL_REGEX = compile(r"^http(s?)://.*\.[a-zA-Z]$")
KMS_REGEX = compile(f"arn:aws:kms:(.*):[0-9]{16}:key/(.*)")
AUTH_CACHE: dict[str, dict[str, any]] = {}


class ClaimMatchType(StrEnum):
    string = auto()
    glob = auto()


class BoundClaim(BaseModel):
    name: str
    match_type: ClaimMatchType
    value: str

    def validate_claim(self, data: Dict[str, Any]):
        assert self.name in data
        if self.match_type == ClaimMatchType.glob:
            assert fnmatch(data[self.name], self.value)
        else:
            assert data[self.name] == self.value

        return True


class JWTAuth(Auth):
    """
    Represents a permission grant for a repository.
    """

    @property
    def issuer(self):
        return self.unverified_payload[1]["iss"]

    @property
    def subject(self):
        return self.unverified_payload[1]["sub"]

    @property
    def identifier(self):
        return f"{self.issuer}~{self.subject}"

    @classmethod
    def create_grant(
        cls,
        namespace: str,
        issuer: str,
        subject: str,
        permissions: Permissions = Permissions(),
        bound_claims: list[BoundClaim] = [],
        jwks: Optional[dict] = None,
    ):
        identifier = cls.get_identifier(issuer=issuer, subject=subject)
        opts = {
            "namespace": namespace,
            "identifier": identifier,
            "issuer": issuer,
            "subject": subject,
            "bound_claims": bound_claims,
            "permissions": permissions,
        }
        if jwks:
            opts["jwks"] = jwks

        return super().create_grant(**opts)

    @property
    def jwt(self):
        return self.token

    @property
    def signing_key(self):
        # TODO: Update jwks from http if key not present
        res = self.grant.get("jwks")
        key = None
        kid = self.unverified_payload[0]["kid"]

        try:
            if res:
                res["keys"] = [x for x in res["keys"] if x["kid"] == kid]

                if res["keys"]:
                    jwks = dumps(res["keys"][0])
                    pub_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks)
                    key = pub_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )

            if not res:
                client = jwt.PyJWKClient(self.issuer)
                key = client.get_signing_key_from_jwt(self.jwt).key
        except (IndexError, KeyError):
            pass
        except Exception as e:
            LOGGER.error(f"Error getting key: {e}")

        if key is None:
            raise AuthError("Invalid issuer", status=401)

        return key

    @property
    def unverified_payload(self):
        return self.get_unverified_payload(self.token)

    @property
    def bound_claims(self):
        return [BoundClaim(**claim) for claim in self.grant["bound_claims"]]

    def validate_bound_claims(
        self,
    ) -> None:
        for claim in self.bound_claims:
            claim.validate_claim(self.unverified_payload[1])

    @classmethod
    def get_unverified_payload(self, token):
        def get_padding(val):
            return "=" * (-len(val) % 4)

        try:
            header, payload, _ = token.split(".")
            header = loads(urlsafe_b64decode(f"{header}{get_padding(header)}").decode())
            payload = loads(
                urlsafe_b64decode(f"{payload}{get_padding(payload)}").decode()
            )
            payload["kid"] = header["kid"]
        except Exception as e:
            LOGGER.error(f"Error decoding token: {e}")
            raise InvalidTokenError()

        return header, payload

    @property
    def aud(self):
        return self.unverified_payload[1]["aud"]

    @classmethod
    def make_token(cls):
        pass

    def validate(self):
        opts = {
            "issuer": self.issuer,
            "jwt": self.jwt,
            "key": self.signing_key,
            "algorithms": ["RS256"],
            "audience": self.aud,
            "options": {},
        }
        opts["options"]["verify_exp"] = not NO_VERIFY_JWT_EXP

        try:
            data = jwt.decode(**opts)
        except (
            MissingRequiredClaimError,
            InvalidAudienceError,
            InvalidIssuerError,
            InvalidSignatureError,
            ExpiredSignatureError,
            InvalidTokenError,
            DecodeError,
        ) as e:
            LOGGER.debug(f"JWT Error: {e}")
            raise AuthError(status=401, detail="Invalid token")

        self.validate_bound_claims()

        return data

    @classmethod
    def get_grant(cls, *, namespace: str, issuer: str, subject: str):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        identifier = cls.get_identifier(issuer=issuer, subject=subject)
        res = super().get_grant(namespace=namespace, identifier=identifier)

        return res
