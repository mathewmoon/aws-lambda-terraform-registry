# Self-hosted Terraform Module Registry with IAM Auth
This repository contains all of the pieces needed to both host, and use, a Terraform Module registry hosted on AWS Lambda.

## Installation
* PyPi: `pip3 install lambda-terraform-module-registry`
* Source: `pip3 install lambda-terraform-module-registry`
* Source and able to make live-edits: `cd <repo root>; pip3 install --editable .`

## Deploying
The `terraform-module` directory contains a module, along with all of the submodules, necessary to deploy into AWS. See
[README.md](terraform-module/README.md) in the `terraform-module` directory for a list of resources that are created.

Deploy full application to AWS:
* `cd terraform module`
* Create a `tfvars` file to configure the variables to your suiting
* Make any backend configuration updates you need
* `terraform apply`

To build a Lambda manually:
* `pip3 install --no-cache -t build lambda-terraform-module-registry`
* `cd build`
* `zip -r ../myfunction.zip .`

## CLI Tools
The package includes a few CLI tools for working with the registry:

#### get-registry-token
This tool is used to manually return a token, optionally also as an env var or hcl formatted for a `.terraformrc` file.
```
usage: get-registry-token [-h] [--time TIME] [--registry-host REGISTRY_HOST] [--token-host TOKEN_HOST] [--service SERVICE] {token,config,env}

Get a Bearer token to use for registry authentication by Authing with AWS IAM.

positional arguments:
  {token,config,env}
                            token: Get a raw token
                            config: Get a Terraform config snippet suitable for use in a Terraform RC file
                            env: Get an environment variable suitable for use in a shell script. EG: Prints `TF_TOKEN_myregistry_com=xxxxxxxxxx` to stdout


options:
  -h, --help            show this help message and exit
  --time TIME, -T TIME  The number of seconds until the token expires. Default is 300 seconds.
  --registry-host REGISTRY_HOST, -r REGISTRY_HOST
                        The hostname of the registry. Do not include the protocol.
  --token-host TOKEN_HOST, -t TOKEN_HOST
                        The hostname of the token endoint. Do not include the protocol. This is normally the same as the registry host.
  --service SERVICE     Choose 'execute-api' for AWS API Gateway and Lambda for direct Lambda URL invocation.
```

#### manage-registry-permissions
Add and remove permissions for an IAM user from a namespace

Main usage
```
usage: manage-registry-permissions [-h] --role-arn ROLE_ARN --tenant TENANT --namespace NAMESPACE {remove,update} ...

Manage permissions for an IAM user

positional arguments:
  {remove,update}
    remove              Remove the permissions for an IAM user on a specific tenant and namespace
    update              Update the permissions for an IAM user on a specific tenant and namespace

options:
  -h, --help            show this help message and exit
  --role-arn ROLE_ARN, -r ROLE_ARN
                        The role ARN to modify permissions for
  --tenant TENANT, -t TENANT
                        The tenant to add permissions for
  --namespace NAMESPACE, -n NAMESPACE
                        The namespace to add permissions for
```

Additional options for adding/updating permission on a namespace:
```
usage: manage-registry-permissions update [-h] [--download] [--upload]

options:
  -h, --help      show this help message and exit
  --download, -d  Whether or not to allow downloads
  --upload, -u    Whether or not to allow uploads
```

#### install-registry-credentials-helper
This installs a credential helper that Terraform can call to generate credentials dynamically. See
Hashicorp's documentation for credential helpers [HERE](https://developer.hashicorp.com/terraform/internals/credentials-helpers)

When using the credentials helper, the environment that Terraform is running in must have access to AWS credentials through either:
1. A default profile
2. AWS_PROFILE environment variable, along with a corresponding profile configured
3. AWS IAM credentials stored as environment variables

```
usage: install-registry-credentials-helper [-h] --token-host TOKEN_HOST [--service SERVICE] [--expiration-window EXPIRATION_WINDOW] [--plugin-directory PLUGIN_DIRECTORY] [--rc-file RC_FILE]

Install the Terraform credential helper

options:
  -h, --help            show this help message and exit
  --token-host TOKEN_HOST
                        The host to get tokens from. Do not unclude URL or protocol
  --service SERVICE     The AWS service to auth for. Use `execuite-api (default) if your registry is behind API Gateway, or `lambda` if using a direct Lambda Function URL."
  --expiration-window EXPIRATION_WINDOW
                        The number of seconds the token is good for.
  --plugin-directory PLUGIN_DIRECTORY
                        The directory to install the plugin to. Defaults to $HOME/.terraform.d/plugins
  --rc-file RC_FILE     The path to the Terraform RC file to write to. Optional.
```

## Registry configuration
The registry stores modules in S3 under the structure `<tenant>/<namespace>/<module name>/<semantic version>.zip`. Currently uploading modules via the API
is not implemented, so you must upload them directly to S3, ensuring that the path is configured correctly.

#### Tenants, Namespaces and Administration
Tenants and Namespaces exist as soon as there is an object in a path that represents them. In other words, you don't
need an operation dedicated to creating tenants. AWS IAM permission with RW access to the underlying Dynamodb table
and S3 bucket are all that is required to admin the system.

#### Example of creating a new module
If not using the default Dynamodb table name, make sure to `export TABLE_NAME=my-table`

```
> aws s3 cp mymodule.0.1.0.zip s3://my-bucket/default_tenant/my_team/mymodule/0.1.0.zip
Done: mymodule.0.1.0.zip uploaded to s3://my-bucket/default_tenant/my_team/mymodule/0.1.0.zip

> manage-registry-permissions \
    -r arn:aws:iam::xxxxxxxxxxxx:role/myrole
    -t default_tenant \
    -n my_team \
    update \
    -d \
    -u

{
    "my_team": {
        "download": true,
        "upload": true
    }
}
```
Note that, while the API does not support uploads yet, the auth schema still allows specifying upload permissions.


## Authentication
While the registry technically supports simple Bearer auth using non-expiring tokens, it is highly discouraged. One of the main
benifits of this application is the IAM authentication.

How it works:<br>

* An admin adds a permission to the DB table using the `manage-registry-permissions` CLI tool. This entry says that the specified AWS Role has the given
permissions on the specified Tenant and Namespace
* When a client wants to use the registry they will call the token endpoint with a signed request using their role's credentials.
    * The `get-registry-token` cli tool can return a token to be used in the `TF_TOKEN_***` env var, `.terraformrc` configuration, etc and
    can be manually run by the user.
    * You can also install the credentials helper tool to allow Terraform to handle the authentication dynamically
* The request to get a token requires sending the `expiration_window`, which is the number of seconds from now before the token expires. This is capped by the application
by setting the `MAX_IAM_TOKEN_EXPIRATION_WINDOW` env var.
* The token that is returned from the token API endpoint is used as a Bearer token in all API requests.

Server Side Auth validation:<br>

When the server receives a request it parses the Bearer token. The token is constructed from the following sections, contatenated by `~`:

* IAMBearerAuth
* The ARN of the IAM role that is being authenticated
* An encrypted string

The encrypted string is a combination of the role ARN and the datetime at which the token expires. It is encrypted at the time the token is generated
using a KMS key by the registry application. Validation is done by:

* Verifying the prefix is IAMBearerAuth
* Decrypting the encrypted section
* Ensuring the decrypted role ARN matches the plain text ARN
* Ensuring the token has not expired
* Looking up the reference to the role in the DB table
* Verifying that the entry in the table exists for the requested role, Tenant, Namespace, and operation (download or upload)

## Registry Configuration

* `TABLE_NAME`: The name of the Dynamodb table used.
* `REGISTRY_BUCKET`: The ARN of the S3 bucket used for storing modules.
* `RESOLVER_TYPE`: Can be one of `FUNCTION_URL`, `API_GATEWAY_REST`, `API_GATEWAY_HTTP`, or `ALB`. Defaults to `FUNCTION_URL`. This is used to resolve the `Resolver` class
to use by the AWS Lambda Powertools layer. Although the included Terraform uses an API Gateway V2 HTTP API, the `API_GATEWAY_REST` resolver actually works best.
* `HOSTNAME`: This should be set to the hostname where your repository API is hosted. If you're using API Gateway then this is the hostname to your deployment. If using a Lambda
Function URL then this would be the hostname for that URL. Note that if using the Function URL you would use the Function that actually hosts the registry, and not the auth endpoint.
* `IAM_AUTH_KMS_KEY`: Arn of a KMS key to use for encrypting and decrypting tokens.
