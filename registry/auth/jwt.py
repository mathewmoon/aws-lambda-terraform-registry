#!/usr/bin/env python3
from __future__ import annotations

from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import serialization
from enum import auto, StrEnum
from fnmatch import fnmatch
from json import dumps, loads
from re import compile
import jwt.algorithms
from typing import Any, Optional, Self

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
from pydantic import BaseModel, PrivateAttr

from . import Auth, Permissions
from .exceptions import AuthError

from ..globals import logger, RegistryConfig


AUTH_CACHE = {}
PUB_KEY_CACHE = {}
URL_REGEX = compile(r"^http(s?)://.*\.[a-zA-Z]$")
config = RegistryConfig()


class ClaimMatchType(StrEnum):
    string = auto()
    glob = auto()


class BoundClaim(BaseModel):
    name: str
    match_type: ClaimMatchType
    value: str

    def validate_claim(self, data: dict[str, Any]):
        assert self.name in data
        if self.match_type == ClaimMatchType.glob:
            assert fnmatch(data[self.name], self.value)
        else:
            assert data[self.name] == self.value

        return True


class JWTAuth(Auth):
    _grant: dict[str, Any] = PrivateAttr()

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

        if key := PUB_KEY_CACHE.get(self.issuer, {}).get(kid):
            return key

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
            logger.debug(f"Key not found in JWKS")
        except Exception as e:
            logger.error(f"Error getting key: {e}")

        if key is None:
            raise AuthError("Invalid issuer", status=401)

        if self.issuer not in PUB_KEY_CACHE:
            PUB_KEY_CACHE[self.issuer] = {kid: key}
        else:
            PUB_KEY_CACHE[self.issuer].update({kid: key})

        return key

    @property
    def unverified_payload(self):
        return self.get_unverified_payload(self.token)

    @property
    def bound_claims(self):
        return [BoundClaim(**claim) for claim in self.grant.get("bound_claims", [])]

    def validate_bound_claims(
        self,
    ) -> None:
        for claim in self.bound_claims:
            claim.validate_claim(self.verified_payload)

    @property
    def verified_payload(self):
        return self.validate()

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
            logger.error(f"Error decoding token: {e}")
            raise InvalidTokenError()

        return header, payload

    @property
    def aud(self):
        return self.unverified_payload[1]["aud"]

    @classmethod
    def make_token(cls):
        pass

    def decode_jwt(self):
        opts = {
            "issuer": self.issuer,
            "jwt": self.jwt,
            "key": self.signing_key,
            "algorithms": ["RS256"],
            "audience": self.aud,
            "options": {},
        }
        opts["options"]["verify_exp"] = not config.no_verify_jwt_exp

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
            logger.debug(f"JWT Error: {e}")
            raise AuthError(status=401, detail="Invalid token")

        return data

    def validate(self) -> Self:
        self._grant = self.get_grant(
            namespace=self.namespace, issuer=self.issuer, subject=self.subject
        )

        if self.jwt not in AUTH_CACHE:
            AUTH_CACHE[self.jwt] = self.decode_jwt()

            return AUTH_CACHE[self.jwt]

        self.validate_bound_claims()
        AUTH_CACHE[self.jwt] = self.decode_jwt()

        return self

    @classmethod
    def get_grant(cls, *, namespace: str, issuer: str, subject: str):
        """
        Retrieves the item from the database or creates a new one if not found.

        :return: The item dictionary.
        """
        identifier = cls.get_identifier(issuer=issuer, subject=subject)
        res = super().get_grant(namespace=namespace, identifier=identifier)
        return res
