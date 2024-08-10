#!/usr/bin/env python3
from base64 import b64decode

from pydantic import BaseModel, PrivateAttr
from boto3.dynamodb.conditions import Key

from .config import REGISTRY_BUCKET, S3, TABLE


class Module(BaseModel):
    namespace: str  # The name of the namespace
    system: str  # The name of the system
    name: str  # The name of the module
    _versions: list | None = PrivateAttr(
        None
    )  # A private attribute to store the versions of the module

    def namespace_exists(self):
        """
        Check if the namespace exists in the registry bucket.

        Returns:
            bool: True if the namespace exists, False otherwise.
        """
        res = TABLE.get(
            Key={
                "pk": self.namespace,
                "sk": "NAMESPACE~",
            }
        )

        return bool(res.get("Item"))

    @property
    def sk_identifier(self):
        return self.__class__.__name__

    @property
    def full_name(self):
        return f"{self.name}/{self.system}"

    @classmethod
    def get_version_from_path(cls, path):
        """
        Get the version from the given path.

        Args:
            path (str): The path to extract the version from.

        Returns:
            str: The extracted version.
        """
        return path.split("/")[-1].replace("v", "").replace(".zip", "")

    @property
    def system_path(self):
        """
        Get the path of the system.

        Returns:
            str: The path of the system.
        """
        return f"{self.namespace}/{self.system}"

    @property
    def namespace_path(self):
        """
        Get the path of the namespace.

        Returns:
            str: The path of the namespace.
        """
        return self.namespace

    @property
    def module_path(self):
        """
        Get the path of the module.

        Returns:
            str: The path of the module.
        """
        return f"{self.namespace}/{self.system}/{self.name}"

    @property
    def versions(self):
        """
        Get the versions of the module.

        Returns:
            list: A list of dictionaries containing the versions of the module.
        """
        res = TABLE.query(
            KeyConditionExpression=Key("pk").eq(self.namespace)
            & Key("sk").begins_with(f"{self.sk_identifier}~{self.system}/{self.name}"),
        )["Items"]

        versions = {
            "versions": [{"version": x["version"]} for x in res],
        }

        return versions

    def get_key(self, version):
        return {
            "pk": self.namespace,
            "sk": f"{self.sk_identifier}~{self.system}/{self.name}~{version}",
        }

    def get_version(self, version):
        return self.item(version, no_create=True)

    def presigned_url(self, version, expires_in=30):
        url = S3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": REGISTRY_BUCKET,
                "Key": f"{self.module_path}/{version}.zip",
            },
            ExpiresIn=expires_in,
        )
        return url

    @property
    def download_url(self):
        """
        Return the relative download URL of the module.
        """
        return "./package"

    def download_from_item(self, version):
        """
        Download the module from the item.

        Args:
            version (str): The version of the module to download.

        Returns:
            dict: A dictionary containing the download link of the module.
        """
        item = self.get_version_item(version)

        if item is None or "zipfile" not in item:
            return None

        zipfile = item["zipfile"].decode()

        return zipfile

    def has_version(self, version: str):
        return self.item(version, no_create=True) is not None

    def item(self, version, no_create=False):
        item = TABLE.get_item(Key=self.get_key(version)).get("Item")

        if item is None and not no_create:
            item = self.get_key(version)
            item["version"] = version

        return item

    def delete_version(self, version):
        TABLE.delete_item(Key=self.get_key(version))
        S3.delete_object(
            Bucket=REGISTRY_BUCKET,
            Key=f"{self.module_path}/{version}.zip",
        )

    def create_version(self, version: str, zipfile: bytes, allow_overwrite=False):
        item = self.item(version)
        item["zipfile"] = zipfile
        opts = {"Item": item}

        if not allow_overwrite:
            opts[
                "ConditionExpression"
            ] = "attribute_not_exists(pk) AND attribute_not_exists(sk)"

        return TABLE.put_item(**opts)

    @property
    def readme(self):
        """
        Get the content of the README file.

        Returns:
            dict: A dictionary containing the content of the README file.
        """
        try:
            res = S3.get_object(
                Bucket=REGISTRY_BUCKET,
                Key=f"{self.module_path}/README.md",
            )
            body = res["Body"].read().decode()
        except S3.exceptions.NoSuchKey:
            body = ""

        res = {
            "readme": body,
        }

        return res
