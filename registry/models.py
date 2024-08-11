#!/usr/bin/env python3
from base64 import b64decode
from hashlib import sha256
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, field_validator
from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import Binary

from .config import S3, TABLE


class Zipfile(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        arbitrary_types_allowed=True
    )
    namespace: str
    system: str
    name: str
    version: str
    data: bytes | Binary = b""


    @field_validator("data")
    def to_bytes(cls, data) -> bytes:
        if isinstance(data, Binary):
            data = data.value
        return data


    @property
    def checksum(self):
        return sha256(self.data).hexdigest()


    @classmethod
    def get_db_key(cls, namespace, system, name, version):
        return {
            "pk": namespace,
            "sk": f"{cls.__name__}~{namespace}/{system}/{name}~{version}",
        }

    @classmethod
    def create(
        cls,
        namespace,
        system,
        name,
        version,
        data,
        allow_overwrite=False
    ):
        key = cls.get_db_key(namespace, system, name, version)

        item = {
            **key,
            "namespace": namespace,
            "system": system,
            "name": name,
            "version": version,
            "data": data,
        }

        opts = {
            "Item": item,
        }

        if not allow_overwrite:
            opts["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()

        TABLE.put_item(**opts)

        return cls(**item)


    @classmethod
    def get(cls, namespace, system, name, version):
        res = TABLE.get_item(
            Key=cls.get_db_key(namespace, system, name, version)
        )
        if item := res.get("Item"):
            return cls(**item)


    def module(self):
        return Module.get(self.namespace, self.system, self.name, self.version)


class Module(BaseModel, extra="ignore"):
    model_config = ConfigDict(
        extra="ignore",
        arbitrary_types_allowed=True
    )

    namespace: str  # The name of the namespace
    system: str  # The name of the system
    name: str  # The name of the module
    version: str  # The version of the module
    bucket: str | None = None  # The bucket that the object is stored in, if not passed as a binary parameter
    expected_checksum: str | None = None  # The expected checksum of the object


    @property
    def module_path(self):
        """
        Get the path of the module.

        Returns:
            str: The path of the module.
        """
        return f"{self.namespace}/{self.system}/{self.name}"

    @classmethod
    def get_sk(
        cls,
        namespace,
        system,
        name,
        version=None
    ):
        sk = f"{cls.__name__}~{namespace}/{system}/{name}~"
        if version:
            sk += f"{version}"

        return sk

    @classmethod
    def get_db_key(
        cls,
        namespace,
        system,
        name,
        version=None
    ):
        return {
            "pk": namespace,
            "sk": cls.get_sk(namespace, system, name, version),
        }


    @property
    def zipfile(self):
        res = Zipfile.get(
            self.namespace,
            self.system,
            self.name,
            self.version
        )
        return res


    @classmethod
    def get_s3_checksum(
        self,
        namespace,
        system,
        name,
        version,
        bucket
    ):
        key = f"{namespace}/{system}/{name}/{version}.zip"
        try:
            res = S3.get_object_attributes(
                Bucket=bucket,
                Key=key,
                ObjectAttributes=["Checksum"],
            )
            return res["Checksum"]["ChecksumSHA256"]
        except KeyError:
            raise ValueError("Checksum not found. Make sure your object contains a SHA256 checksum.")
        except (
            S3.exceptions.NoSuchKey,
            S3.exceptions.NoSuchBucket,
        ):
            raise ValueError(f"Object {self.module_path}/{self.version}.zip does not exist in bucket {self.bucket}")


    @classmethod
    def versions(
        cls,
        namespace: str,
        system: str,
        name: str,
    ) -> list[Self]:
        """
        Get the versions of the module.

        Returns:
            list: A list of dictionaries containing the versions of the module.
        """
        sk = cls.get_sk(namespace, system, name)

        res = TABLE.query(
            KeyConditionExpression=Key("pk").eq(namespace)
            & Key("sk").begins_with(sk),
        )["Items"]

        versions = [
            cls(**item) for item in res
        ]

        return versions


    @property
    def db_key(self):
        return self.get_db_key(self.namespace, self.system, self.name, self.version)


    @classmethod
    def get(
        cls,
        namespace: str,
        system: str,
        name: str,
        version: str,
    ):
        key = cls.get_db_key(namespace, system, name, version)

        res = TABLE.get_item(Key=key).get("Item")

        if res:
            return cls(**res)


    def presigned_url(self, expires_in=30):
        url = S3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": f"{self.module_path}/{self.version}.zip",
            },
            ExpiresIn=expires_in,
        )
        return url

    @property
    def download_url(self):
        """
        Return the relative download URL of the module.
        """
        return "./zip"


    @classmethod
    def create(
        cls,
        namespace: str,
        system: str,
        name: str,
        version: str,
        zipfile: bytes | None = None,
        bucket: str | None = None,
        allow_overwrite=False
    ):
        if (
            (zipfile is None and bucket is None)
            or (zipfile is not None and bucket is not None)
        ):
            raise ValueError("Exactly one of zipfile or bucket must be passed")

        key = cls.get_db_key(namespace, system, name, version)

        item = {
            **key,
            "namespace": namespace,
            "system": system,
            "name": name,
            "version": version,
        }            

        if bucket:
            item["expected_checksum"] = cls.get_s3_checksum(namespace, system, name, version, bucket)
        else:
            item["expected_checksum"] = sha256(zipfile).hexdigest()

        opts = {
            "Item": item,
        }

        if not allow_overwrite:
            opts["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()


        TABLE.put_item(**opts)
        
        if zipfile:
            Zipfile.create(
                namespace=namespace,
                system=system,
                name=name,
                version=version,
                data=zipfile,
                allow_overwrite=allow_overwrite
            )

        return cls(**item)

