#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps
from os import chmod, makedirs, path


parser = ArgumentParser(description="Install the Terraform credential helper")
parser.add_argument(
    "--service",
    type=str,
    help="""
    The AWS service to auth for. Use `execuite-api (default) if your registry is behind API Gateway, or `lambda`
    if using a direct Lambda Function URL.
    """,
    default="execute-api",
)
parser.add_argument(
    "--expiration-window",
    type=str,
    help="The number of seconds the token is good for.",
    default="300",
)
parser.add_argument(
    "--plugin-directory",
    type=str,
    help="The directory to install the plugin to. Defaults to $HOME/.terraform.d/plugins",
    default=path.join(path.expanduser("~"), ".terraform.d", "plugins"),
)
parser.add_argument(
    "--rc-file",
    type=str,
    help="The path to the Terraform RC file to write to. Optional.",
)
parser.add_argument(
    "--registry-host",
    type=str,
    help="The host to get tokens from. Do not unclude URL or protocol",
    required=True,
)

args = parser.parse_args()

tf_args = dumps(
    ["--service", args.service, "--expiration-window", args.expiration_window], indent=2
)


rc_code = f"""
credentials_helper "aws-credstore" {{
      args = {tf_args}
}}
"""


def main():
    try:
        makedirs(args.plugin_directory, exist_ok=True)
        fpath = path.join(args.plugin_directory, "terraform-credentials-aws-credstore")

        helper_code_path = path.join(path.dirname(__file__), "credential_helper.py")
        with open(helper_code_path, "r") as f:
            cred_helper_code = f.read()

        with open(fpath, "w") as f:
            f.write(cred_helper_code)

        chmod(fpath, 0o755)
    except Exception as e:
        print(e)
        exit(1)

    print(f"Installed Terraform credential helper to {fpath}")
    if args.rc_file:
        with open(args.rc_file, "a") as f:
            f.write(rc_code)

        print(f"Added the following to your {args.rc_file} file:")
        print(rc_code)
    else:
        print(f"Add the following to your ~/.terraformrc file:")
        print(rc_code)
