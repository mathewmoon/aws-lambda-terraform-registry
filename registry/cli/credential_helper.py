#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps

from requests_auth_aws_sigv4 import AWSSigV4
import requests

parser = ArgumentParser(description="A credential helper for Terraform Registry")
parser.add_argument(
    "--expiration-window",
    type=str,
    help="The number of seconds the token is good for",
    default="300",
)
parser.add_argument(
    "--service", type=str, help="The AWS service to auth for", default="execute-api"
)
parser.add_argument(
    "cmd", type=str, help="The command to run", choices=["get", "store", "forget"]
)
parser.add_argument(
    "host", type=str, help="The hostname of the Terraform Registry to auth for."
)
args = parser.parse_args()


def get_credentials():
    res = requests.get(
        f"https://{args.host}/token",
        auth=AWSSigV4(service=args.service),
        params={"expiration_seconds": args.expiration_window},
    )
    try:
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(e)
        exit(1)
    return res.text


def store_credentials():
    raise NotImplementedError("This function is not implemented yet.")


def remove_credentials():
    raise NotImplementedError("This function is not implemented yet.")


cmds = {
    "get": get_credentials,
    "store": store_credentials,
    "forget": remove_credentials,
}

if __name__ == "__main__":
    res = cmds[args.cmd]()
    if res:
        res = {"token": res}
    else:
        token = {}

    print(dumps(res))
