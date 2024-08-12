#!/usr/bin/env python3
from argparse import ArgumentParser, RawTextHelpFormatter
from requests_auth_aws_sigv4 import AWSSigV4

import requests


parser = ArgumentParser(
    description="Get a Bearer token to use for registry authentication by Authing with AWS IAM.",
    formatter_class=RawTextHelpFormatter,
)
parser.add_argument(
    "cmd",
    type=str,
    help="""
    token: Get a raw token
    config: Get a Terraform config snippet suitable for use in a Terraform RC file
    env: Get an environment variable suitable for use in a shell script. EG: Prints `TF_TOKEN_myregistry_com=xxxxxxxxxx` to stdout
    """,
    choices=["token", "config", "env"],
)
parser.add_argument(
    "--time",
    "-T",
    type=int,
    default=300,
    help="The number of seconds until the token expires. Default is 300 seconds.",
)
parser.add_argument(
    "--registry-host",
    "-r",
    type=str,
    help="The hostname of the registry. Do not include the protocol.",
)
parser.add_argument(
    "--service",
    type=str,
    help="Choose 'execute-api' for AWS API Gateway and Lambda for direct Lambda URL invocation.",
    default="execute-api",
)
args = parser.parse_args()


def make_token():
    url = f"https://{args.registry_host}/token"
    res = requests.get(
        url,
        auth=AWSSigV4(service=args.service),
        params={"expiration_seconds": args.time},
    )
    return res.text


def make_env_var():
    if not args.registry_host:
        print("No host provided. Specify with the --host/-h flag.")
        exit(1)
    token = make_token()
    hostname = args.registry_host.replace(".", "_").replace("-", "__").lower()
    var = f'TF_TOKEN_{hostname}="{token}"'

    return var


def make_config():
    if not args.host:
        print("No host provided. Specify with the --host/-h flag.")
        exit(1)

    token = make_token()
    config = f"""
credentials "{args.host}" {{
    token = "{token}"
}}
"""
    return config


def main():
    if args.cmd == "token":
        print(make_token())
    elif args.cmd == "config":
        print(make_config())
    elif args.cmd == "env":
        print(make_env_var())
