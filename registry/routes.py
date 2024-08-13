from .config import BASE_URI


create = f"{BASE_URI}/{{namespace}}/{{name}}/{{system}}/{{version}}/create"
versions = f"{BASE_URI}/{{namespace}}/{{name}}/{{system}}/versions"
get_download_url = f"{BASE_URI}/{{namespace}}/{{name}}/{{system}}/{{version}}/download"
well_known = "/.well-known/terraform.json"
iam_token_endpoint = "/token"
