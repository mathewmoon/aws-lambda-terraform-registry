#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps

from ..auth.bearer import IAMBearerAuth


parser = ArgumentParser(description="Manage permissions for an IAM user")
subparsers = parser.add_subparsers(dest="cmd", required=True)
remove_parser = subparsers.add_parser(
    "delete",
    description="Delete a grant, with all corresponding permissions, for an IAM user on a specific namespace and system",
    help="Delete a grant, with all corresponding permissions, for an IAM user on a specific namespace and system",
)
update_parser = subparsers.add_parser(
    "update",
    description="Update the permissions for an IAM user on a specific namespace and system",
    help="Update the permissions for an IAM user on a specific namespace and system",
)
create_parser = subparsers.add_parser(
    "create",
    description="Create a new permission grant for an IAM user on a specific namespace.",
    help="Create a new permission grant for an IAM user on a specific namespace.",
)

parser.add_argument(
    "--role-arn",
    "-r",
    type=str,
    required=True,
    help="The role ARN to modify permissions for",
)
parser.add_argument(
    "--namespace",
    "-n",
    type=str,
    required=True,
    help="The namespace to add permissions for",
)
update_parser.add_argument(
    "--download", "-d", action="store_true", help="Whether or not to allow downloads"
)
update_parser.add_argument(
    "--upload", "-u", action="store_true", help="Whether or not to allow uploads"
)
update_parser.add_argument(
    "--create-grant",
    "-c",
    action="store_true",
    help="Whether or not to allow creating grants",
)
update_parser.add_argument(
    "--delete-grant",
    "-D",
    action="store_true",
    help="Whether or not to allow deleting grants",
)

create_parser.add_argument(
    "--download", "-d", action="store_true", help="Whether or not to allow downloads"
)
create_parser.add_argument(
    "--upload", "-u", action="store_true", help="Whether or not to allow uploads"
)
create_parser.add_argument(
    "--create-grant",
    "-c",
    action="store_true",
    help="Whether or not to allow creating grants",
)
create_parser.add_argument(
    "--delete-grant",
    "-D",
    action="store_true",
    help="Whether or not to allow deleting grants",
)

args = parser.parse_args()


def main():
    if args.cmd in ("update", "create"):
        permissions = {
            "download": args.download,
            "upload": args.upload,
            "create_grant": args.create_grant,
            "delete_grant": args.delete_grant,
        }
        permissions = {k: v for k, v in permissions.items() if v is not None}
        opts = {
            "namespace": args.namespace,
            "identifier": args.role_arn,
        }
        if args.cmd == "create":
            grant = IAMBearerAuth.create_grant(
                namespace=args.namespace,
                identifier=args.role_arn,
                permissions=permissions,
            )

        else:
            grant = IAMBearerAuth.get_grant(
                namespace=args.namespace, identifier=args.role_arn
            )
            if grant is None:
                print(
                    f"Grant for {args.role_arn} does not exist in namespace {args.namespace}. You can create one with the `create` command."
                )
                exit(1)

            permissions = {**grant.get("permissions", {}), **permissions}
            opts = {**opts, **permissions}

            IAMBearerAuth.update_permissions(**opts)

        res = IAMBearerAuth.get_grant(
            namespace=args.namespace, identifier=args.role_arn
        ).get("permissions", {})
        res = {
            "namespace": args.namespace,
            "role": args.role_arn,
            "permissions": permissions,
        }
        print(dumps(res, indent=2))

    elif args.cmd == "delete":
        permissions = IAMBearerAuth.delete_grant(
            namespace=args.namespace, identifier=args.role_arn
        )
    else:
        raise ValueError(f"Invalid command: {args.cmd}")
