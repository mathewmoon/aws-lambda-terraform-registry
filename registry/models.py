#!/usr/bin/env python3
from pydantic import BaseModel, PrivateAttr
from .config import REGISTRY_BUCKET, S3


class Module(BaseModel):
    tenant: str
    namespace: str
    name: str
    _versions: list | None = PrivateAttr(None)


    def tenant_exists(self):
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.tenant_path,
            MaxKeys=1,
        )

        return bool(res.get("Contents"))

    def namespace_exists(self):
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.namespace_path,
            MaxKeys=1,
        )

        return bool(res.get("Contents"))


    @classmethod
    def get_version_from_path(cls, path):
        return path.split("/")[-1].replace("v", "").replace(".zip", "")

    @property
    def namespace_path(self):
        return f"{self.tenant}/{self.namespace}"

    @property
    def tenant_path(self):
        return self.tenant

    @property
    def module_path(self):
        return f"{self.tenant}/{self.namespace}/{self.name}"

    @property
    def versions(self):
        if self._versions is None:
            self._versions = self.list_versions()

        return self._versions

    def presigned_download(self, version, expires_in=30):
        key = f"{self.module_path}/{version}.zip"
        try:
            res = S3.head_object(
                Bucket=REGISTRY_BUCKET,
                Key=key
            )
        except S3.exceptions.NoSuchKey:
            return None

        res = S3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": REGISTRY_BUCKET,
                "Key": key,
            },
            ExpiresIn=expires_in
        )
        return res

    def list_versions(self, version=None):
        self.readme
        res = S3.list_objects_v2(
            Bucket=REGISTRY_BUCKET,
            Prefix=self.module_path,
        ).get("Contents", [])

        versions = [
            {"version": self.get_version_from_path(item["Key"])}
            for item in res if item["Key"].endswith(".zip")
        ]

        if version is not None:
            versions = [x for x in versions if x["version"] == version]

        return versions


    @property
    def readme(self):
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
