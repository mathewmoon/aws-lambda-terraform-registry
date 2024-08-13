#!/usr/bin/env python3
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, model_validator
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from .config import S3, LOGGER, TABLE


class Module(BaseModel, extra="ignore"):
    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    namespace: str  # The name of the namespace
    system: str  # The name of the system
    name: str  # The name of the module
    version: str  # The version of the module
    bucket: str  # The bucket that the object is stored in, if not passed as a binary parameter
    key: str  # The key of the object in the bucket
    expected_checksum: str  # The expected checksum of the object

    @model_validator(mode="after")
    def validate_model(self):
        real_checksum = self.get_checksum(bucket=self.bucket, key=self.key)

        if real_checksum != self.expected_checksum:
            raise ValueError(
                f"Checksum mismatch. Expected {self.expected_checksum}, got {real_checksum}"
            )

    @classmethod
    def get_sk(
        cls, *, namespace: str, system: str, name: str, version: str | None = None
    ):
        sk = f"{cls.__name__}~{namespace}~{name}~{system}~"
        if version:
            sk += version

        return sk

    @classmethod
    def __get_db_key(
        cls, *, namespace: str, system: str, name: str, version: str | None = None
    ):
        return {
            "pk": namespace,
            "sk": cls.get_sk(
                namespace=namespace, system=system, name=name, version=version
            ),
        }

    @classmethod
    def get_checksum(cls, *, bucket: str, key: str):
        try:
            res = S3.get_object_attributes(
                Bucket=bucket, Key=key, ObjectAttributes=["Checksum"]
            )
            return res["Checksum"]["ChecksumSHA256"]
        except KeyError:
            LOGGER.error(f"No checksum found for {bucket}/{key}")
            raise ValueError(
                "Checksum not found. Make sure your object contains a SHA256 checksum."
            )
        except ClientError as e:
            LOGGER.error(f"Client error when getting checksum for {bucket}/{key}: {e}")

            if "Access Denied" in str(e):
                raise ValueError(
                    f"Access denied to bucket or object when accessing bucket {bucket} with key {key}."
                )

            else:
                raise Exception(e)
        except (
            S3.exceptions.NoSuchKey,
            S3.exceptions.NoSuchBucket,
        ):
            raise ValueError(f"Backend object {key} does not exist in bucket {bucket}")

    @classmethod
    def versions(
        cls,
        *,
        namespace: str,
        system: str,
        name: str,
    ) -> list[Self]:
        """
        Get the versions of the module.

        Returns:
            list: A list of dictionaries containing the versions of the module.
        """
        sk = cls.get_sk(namespace=namespace, system=system, name=name)

        res = TABLE.query(
            KeyConditionExpression=Key("pk").eq(namespace) & Key("sk").begins_with(sk),
        )["Items"]

        versions = {"modules": [{"versions": [{"version": v["version"]} for v in res]}]}

        return versions

    @property
    def __db_key(self):
        return self.__get_db_key(
            namespace=self.namespace,
            system=self.system,
            name=self.name,
            version=self.version,
        )

    @classmethod
    def get(
        cls,
        *,
        namespace: str,
        system: str,
        name: str,
        version: str,
    ):
        key = cls.__get_db_key(
            namespace=namespace, system=system, name=name, version=version
        )

        res = TABLE.get_item(Key=key).get("Item")

        if res:
            return cls(**res)

    def presigned_url(self, *, expires_in=30):
        url = S3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": self.key,
            },
            ExpiresIn=expires_in,
        )
        return url

    def create(self, *, allow_overwrite=False):
        item = {
            **self.__db_key,
            **self.model_dump(),
        }

        opts = {
            "Item": item,
        }

        if not allow_overwrite:
            opts["ConditionExpression"] = (
                Attr("pk").not_exists() & Attr("sk").not_exists()
            )

        TABLE.put_item(**opts)
