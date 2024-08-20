#!/usr/bin/env python3
from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import serialization
from enum import auto, StrEnum
from fnmatch import fnmatch
from functools import cached_property
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
from pydantic import BaseModel, computed_field

from . import Auth, Permissions
from .exceptions import AuthError

from ..globals import logger, Clients, RegistryConfig


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
    @computed_field
    @cached_property
    def grant(self) -> dict[str, Any]:
        res = self.get_grant(
            namespace=self.namespace,
            issuer=self.unverified_payload["iss"],
            subject=self.unverified_payload["sub"],
        )
        return res

    @property
    def issuer(self):
        return self.grant["issuer"]

    @property
    def subject(self):
        return self.grant["subject"]

    @property
    def identifier(self):
        return f"{self.issuer}~{self.subject}"

    @classmethod
    def create_grant(
        cls,
        *,
        audience: str,
        namespace: str,
        issuer: str,
        subject: str,
        permissions: Permissions = Permissions(),
        bound_claims: list[BoundClaim] = [],
        jwks: Optional[dict] = None,
    ):
        identifier = cls.get_identifier(issuer=issuer, subject=subject)
        opts = {
            "audience": audience,
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
            audience=self.audience,
        )

        return res["jwks"]

    def get_kms_pub_key(self, kid: str):
        if key := KMSPubKey.get(kid=kid):
            return key.public_key
        raise AuthError("No valid JWKS found", status=401)

    @property
    def signing_key(self):
        kid = self.header["kid"]
        if kid.startswith("kms:"):
            try:
                key = self.get_kms_pub_key(kid.replace("kms:", ""))
                return key
            except Exception as e:
                logger.error(f"Error getting key: {e}")

        issuer = self.unverified_payload["iss"]
        if key := PUB_KEY_CACHE.get(issuer, {}).get(kid):
            return key

        jwks = self.grant.get("jwks", {"keys": []})

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

    @cached_property
    def unverified_payload(self):
        return jwt.decode(self.token, options={"verify_signature": False})

    @cached_property
    def bound_claims(self):
        return [BoundClaim(**claim) for claim in self.grant.get("bound_claims", [])]

    @cached_property
    def verified_payload(self):
        return self.decode_jwt()

    @property
    def header(self):
        header_str = self.token.split(".")[0]
        padding = "=" * (-len(header_str) % 4)
        header = loads(urlsafe_b64decode(f"{header_str}{padding}").decode())
        return header

    @property
    def audience(self):
        return self.grant["audience"]

    def decode_jwt(self):
        opts = {
            "issuer": self.issuer,
            "jwt": self.jwt,
            "key": self.signing_key,
            "algorithms": ["RS256"],
            "audience": self.audience,
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
            msg = str(e).replace("jwt.exceptions.", "")
            raise AuthError(msg, status=401)

        for claim in self.bound_claims:
            claim.validate_claim(data)

        return data

    def validate(self) -> Self:
        if self.grant is None:
            raise AuthError("Not authorized", status=401)

        data = self.decode_jwt()

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


class KMSPubKey(BaseModel):
    kid: str
    key: bytes

    @classmethod
    def create(cls, *, kid: str):
        res = Clients().kms.get_public_key(KeyId=kid)
        key_bytes = res["PublicKey"]

        key = {
            "pk": "__SYSTEM__",
            "sk": f"{cls.__name__}~{kid}",
        }
        item = {
            **key,
            "kid": kid,
            "key": key_bytes,
        }
        res = Clients().table.put_item(Item=item)
        return cls.get(kid=kid)

    @classmethod
    def get(cls, *, kid: str):
        key = {
            "pk": "__SYSTEM__",
            "sk": f"{cls.__name__}~{kid}",
        }
        if res := Clients().table.get_item(Key=key).get("Item"):
            res = Auth.unmarshall(res)
            return cls(**res)

    @property
    def pem(self):
        return self.key.decode()

    @cached_property
    def public_key(self):
        return serialization.load_der_public_key(self.key)
