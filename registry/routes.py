from .globals import RegistryConfig


create = (
    f"{RegistryConfig().base_url}/{{namespace}}/{{name}}/{{system}}/{{version}}/create"
)
versions = f"{RegistryConfig().base_url}/{{namespace}}/{{name}}/{{system}}/versions"
get_download_url = f"{RegistryConfig().base_url}/{{namespace}}/{{name}}/{{system}}/{{version}}/download"
well_known = "/.well-known/terraform.json"
iam_token_endpoint = "/token"
