from .config import BASE_URI


upload_module = f"{BASE_URI}/modules/upload_version"
create_module = f"{BASE_URI}/modules/create"
versions = f"{BASE_URI}/<namespace>/<system>/<name>/versions"
get_download_url = f"{BASE_URI}/<namespace>/<system>/<name>/<version>/download"
download = f"{BASE_URI}/<namespace>/<system>/<name>/<version>/<version>.zip"
well_known = "/.well-known/terraform.json"
iam_token_endpoint = "/token"
