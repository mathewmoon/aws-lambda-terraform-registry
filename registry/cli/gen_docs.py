#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dump
from shutil import which
from subprocess import Popen

from fastapi.openapi.utils import get_openapi

from ..aws_lambda.registry_lambda import APP

parser = ArgumentParser()
parser.add_argument(
    "--swagger-output",
    help="The path to write the OpenAPI documentation to.",
    default="swagger.json"
)
parser.add_argument(
    "--redoc-output",
    help="The path to write the ReDoc documentation to.",
    default="redoc.html"
)
args = parser.parse_args()

def main():
    try:
        docs = get_openapi(
            title=APP.title,
            version=APP.version,
            openapi_version=APP.openapi_version,
            description=APP.description,
            routes=APP.routes,
        )

        with open(args.swagger_output, "w") as f:
            dump(docs, f, indent=2)

        if not (
            which("node")
            and which ("npx")
        ):
            print("Node.js and npx are required to build the documentation.")
            exit(1)

        try:
            proc = Popen(
                [
                    "npx",
                    "@redocly/cli",
                    "build-docs",
                    "swagger.json",
                    "-o",
                    args.redoc_output,
                ],
            )
            proc.communicate()
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)
        exit(1)

main()