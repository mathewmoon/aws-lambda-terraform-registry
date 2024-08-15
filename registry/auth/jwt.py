#!/usr/bin/env python3
from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import serialization
from enum import auto, StrEnum
from fnmatch import fnmatch
from json import loads
from re import compile
from typing import Any, Optional, Self

import jwt.algorithms
import requests

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

    def get_remote_jwks(self):
        # Use an explicit URL first
        url = self.grant.get("jwks_endpoint")

        if not url:
            try:
                # Turns out not everyone plays by the rules and .well-known/jwks.json
                # could be anything so we need to fetch from openid-configuration instead
                # I'm talking to you GitHub.
                res = requests.get(f"{self.issuer}/.well-known/openid-configuration")
                res.raise_for_status()
                url = res.json().get("jwks_uri")
            except requests.exceptions.HTTPError:
                raise AuthError(
                    f"Error fetching openid-configuration from {self.issuer}",
                    status=401,
                )

        if not url:
            raise AuthError(
                f"No OpenID Connect configuration endpoint found for issuer {self.issuer}",
                status=401,
            )

        try:
            res = requests.get(url)
            jwks = res.json()
            res.raise_for_status()
        except (KeyError, requests.exceptions.HTTPError) as e:
            raise AuthError(
                f"Error fetching openid-configuration from {self.issuer}", status=401
            )
        except Exception as e:
            logger.error(f"Error fetching JWKS from {url}: {e}")
            raise e

        return jwks

    def get_jwk_from_jwks(self, jwks: dict, kid: str):
        for k in jwks["keys"]:
            if k["kid"] == kid:
                return k

    def update_jwks(self, keys: dict) -> dict:
        res = self.get_remote_jwks()

        if old_jwks := res.get("jwks"):
            old_jwks["keys"] += keys

        res = self.create_grant(
            namespace=self.namespace,
            issuer=self.issuer,
            subject=self.subject,
            permissions=self.permissions,
            bound_claims=self.bound_claims,
            jwks=res,
        )

        return res["jwks"]

    @property
    def signing_key(self):
        if key := PUB_KEY_CACHE.get(self.issuer, {}).get(kid):
            return key

        jwks = self.grant.get("jwks", {"keys": []})
        kid = self.unverified_payload[0]["kid"]

        jwk = self.get_jwk_from_jwks(jwks, kid)

        # If the key isn't there, then fetch the remote jwks
        # and try again
        if not jwk:
            res = self.get_remote_jwks()
            jwks["keys"] += res["keys"]

            if jwks != self.grant.get("jwks"):
                self.update_jwks(jwks["keys"])

            jwk = self.get_jwk_from_jwks(jwks, kid)

        if not jwk:
            raise AuthError(
                f"Key {kid} not found in JWKS for issuer {self.issuer}", status=401
            )

        try:
            pub_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            key = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        except jwt.exceptions.PyJWTError as e:
            logger.debug(f"Error decoding private key for issuer {self.issuer}")
            raise AuthError(
                f"Error decoding private key for issuer {self.issuer}", status=401
            )

        except Exception as e:
            logger.error(f"Error getting key: {e}")
            raise e

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
        return self.verified_payload[1]["aud"]

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

        for claim in self.bound_claims:
            claim.validate_claim(data)

        return data

    def validate(self) -> Self:
        self._grant = self.get_grant(
            namespace=self.namespace, issuer=self.issuer, subject=self.subject
        )

        if self.jwt not in AUTH_CACHE:
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
