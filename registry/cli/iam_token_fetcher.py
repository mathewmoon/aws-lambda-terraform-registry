#!/usr/bin/env python3
from argparse import ArgumentParser
from requests_auth_aws_sigv4 import AWSSigV4

import requests


parser = ArgumentParser(description="Get a KMS token to use for registry authentication.")
parser.add_argument("cmd", type=str, help="The command to run.", choices=["token", "config", "env"])
parser.add_argument("--time", "-T", type=int, default=300, help="The time in seconds until the token expires.")
parser.add_argument("--registry-host", "-r", type=str, help="The hostname of the registry.")
parser.add_argument("--token-host", "-t", type=str, help="The token endpoint to use.")
args = parser.parse_args()


def make_token():
    url = f"https://{args.token_host}/token"
    res = requests.get(url, auth=AWSSigV4(service="lambda"), params={"expiration_seconds": args.time} )
    return res.text


def make_env_var():
    if not args.registry_host:
        print("No host provided. Specify with the --host/-h flag.")
        exit(1)
    token = make_token()
    hostname = args.registry_host.replace(".", "_").replace("-", "__").lower()
    var = f"TF_TOKEN_{hostname}=\"{token}\""

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
