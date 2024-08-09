from .config import BASE_URI


upload_module = f"{BASE_URI}/modules/upload_version"
create_module = f"{BASE_URI}/modules/create"
versions = f"{BASE_URI}/<tenant>/<namespace>/<name>/versions"
download_module = f"{BASE_URI}/<tenant>/<namespace>/<name>/<version>/download"
well_known = "/.well-known/terraform.json"
iam_token_endpoint = "/token"