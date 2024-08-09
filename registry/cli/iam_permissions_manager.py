#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps

from ..auth.bearer import IAMBearerAuth


parser = ArgumentParser(description="Manage permissions for an IAM user")
subparsers = parser.add_subparsers(dest="cmd")
remove_parser = subparsers.add_parser("remove", help="Remove the permissions for an IAM user on a specific tenant and namespace")
update_parser = subparsers.add_parser("update", help="Update the permissions for an IAM user on a specific tenant and namespace")

remove_parser.add_argument("--role-arn", "-r", type=str, required=True, help="The role ARN to add permissions for")
remove_parser.add_argument("--tenant", "-t", type=str, required=True, help="The tenant to add permissions for")
remove_parser.add_argument("--namespace", "-n", type=str, required=True, help="The namespace to add permissions for")

update_parser.add_argument("--role-arn", "-r", type=str, required=True, help="The role ARN to add permissions for")
update_parser.add_argument("--tenant", "-t", type=str, required=True, help="The tenant to add permissions for")
update_parser.add_argument("--namespace", "-n", type=str, required=True, help="The namespace to add permissions for")
update_parser.add_argument("--download", "-d", action="store_true", help="Whether or not to allow downloads")
update_parser.add_argument("--upload", "-u", action="store_true", help="Whether or not to allow uploads")

args = parser.parse_args()


def update(cur_user):
    permissions = cur_user.permissions

    permissions[args.namespace] = {
        "download": args.download,
        "upload": args.upload
    }

    cur_user.put(permissions=permissions)
    return cur_user.permissions


def remove(cur_user):
    permissions = cur_user.permissions

    if args.namespace in permissions:
        del permissions[args.namespace]

    cur_user.put(permissions=permissions)
    return cur_user.permissions


def main():
    token = IAMBearerAuth.make_token(role_arn=args.role_arn, expiration_seconds=60)

    cur_user = IAMBearerAuth(
        tenant=args.tenant,
        token=token
    )

    if args.cmd == "update":
        permissions = update(cur_user)
    elif args.cmd == "remove":
        permissions = remove(cur_user)
    else:
        raise ValueError(f"Invalid command: {args.cmd}")
    
    print(dumps(permissions, indent=2))