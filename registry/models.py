#!/usr/bin/env python3
from pydantic import BaseModel, PrivateAttr
from .config import REGISTRY_BUCKET, S3


class Module(BaseModel):
    tenant: str  # The name of the tenant
    namespace: str  # The name of the namespace
    name: str  # The name of the module
    _versions: list | None = PrivateAttr(
        None
    )  # A private attribute to store the versions of the module

    def tenant_exists(self):
        """
        Check if the tenant exists in the registry bucket.

        Returns:
            bool: True if the tenant exists, False otherwise.
        """
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.tenant_path,
            MaxKeys=1,
        )

        return bool(res.get("Contents"))

    def namespace_exists(self):
        """
        Check if the namespace exists in the registry bucket.

        Returns:
            bool: True if the namespace exists, False otherwise.
        """
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.namespace_path,
            MaxKeys=1,
        )

        return bool(res.get("Contents"))

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
    def namespace_path(self):
        """
        Get the path of the namespace.

        Returns:
            str: The path of the namespace.
        """
        return f"{self.tenant}/{self.namespace}"

    @property
    def tenant_path(self):
        """
        Get the path of the tenant.

        Returns:
            str: The path of the tenant.
        """
        return self.tenant

    @property
    def module_path(self):
        """
        Get the path of the module.

        Returns:
            str: The path of the module.
        """
        return f"{self.tenant}/{self.namespace}/{self.name}"

    @property
    def versions(self):
        """
        Get the versions of the module.

        Returns:
            list: A list of dictionaries containing the versions of the module.
        """
        if self._versions is None:
            self._versions = self.list_versions()

        return self._versions

    def presigned_download(self, version, expires_in=30):
        """
        Generate a presigned URL for downloading the module.

        Args:
            version (str): The version of the module to download.
            expires_in (int, optional): The expiration time of the presigned URL in seconds. Defaults to 30.

        Returns:
            str: The presigned URL for downloading the module.
        """
        key = f"{self.module_path}/{version}.zip"
        try:
            res = S3.head_object(Bucket=REGISTRY_BUCKET, Key=key)
        except S3.exceptions.NoSuchKey:
            return None

        res = S3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": REGISTRY_BUCKET,
                "Key": key,
            },
            ExpiresIn=expires_in,
        )
        return res

    def list_versions(self, version=None):
        """
        List the versions of the module.

        Args:
            version (str, optional): The specific version to filter. Defaults to None.

        Returns:
            list: A list of dictionaries containing the versions of the module.
        """
        self.readme
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.module_path,
        ).get("Contents", [])

        versions = [
            {"version": self.get_version_from_path(item["Key"])}
            for item in res
            if item["Key"].endswith(".zip")
        ]

        if version is not None:
            versions = [x for x in versions if x["version"] == version]

        return versions

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
