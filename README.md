# Self-hosted Terraform Module Registry with IAM Auth
This repository contains all of the pieces needed to both host, and use, a Terraform Module registry hosted on AWS Lambda.

## Installation
* PyPi: `pip3 install lambda-terraform-module-registry`
* Source: `pip3 install lambda-terraform-module-registry`
* Source and able to make live-edits: `cd <repo root>; pip3 install --editable .`

Dependencies for local development:
* FastAPI
* Mangum
* pydantic
* boto3
* requests-auth-aws-sig4

They can be install using `poetry` or manually


## Deploying
The `terraform-module` directory contains a module, along with all of the submodules, necessary to deploy into AWS. See
[README.md](terraform-module/README.md) in the `terraform-module` directory for a list of resources that are created.

Deploy full application to AWS:
* `cd terraform module`
* Create a `tfvars` file to configure the variables to your suiting
* Make any backend configuration updates you need
* `terraform apply`

The Terraform builds the Lambda package without any dependencies. This helps with debugging and developement
keeping the package size small enough to allow for editing in the AWS Console.<br>

To create a full deployment you should build a layer and pass it as an entry in the `var.lambda_layers` variable. To create a layer
edit `build_layer.sh` to tweak the build directory and/or zip file name and run it. A layer version will be built and uploaded.

## CLI Tools
The package includes a few CLI tools for working with the registry:

#### get-registry-token
This tool is used to manually return a token, optionally also as an env var or hcl formatted for a `.terraformrc` file.
```
usage: get-registry-token [-h] [--time TIME] [--registry-host REGISTRY_HOST] [--service SERVICE] {token,config,env}

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
  --service SERVICE     Choose 'execute-api' for AWS API Gateway and Lambda for direct Lambda URL invocation.
```

#### manage-registry-permissions
Add and remove permissions for an IAM user from a namespace
:exclamation: To manage grants using the CLI tool you must be authenticated to AWS with permissions
to read/write to the backend Dynamodb Table.

Main usage
```
usage: manage-registry-permissions [-h] --role-arn ROLE_ARN --namespace NAMESPACE {delete,update,create} ...

Manage permissions for an IAM user

positional arguments:
  {delete,update,create}
    delete              Delete a grant, with all corresponding permissions, for an IAM user on a specific namespace and system
    update              Update the permissions for an IAM user on a specific namespace and system
    create              Create a new permission grant for an IAM user on a specific namespace.

options:
  -h, --help            show this help message and exit
  --role-arn ROLE_ARN, -r ROLE_ARN
                        The role ARN to modify permissions for
  --namespace NAMESPACE, -n NAMESPACE
                        The namespace to add permissions for
```
Create a new grant:
```
usage: manage-registry-permissions create [-h] [--download] [--upload] [--create-grant] [--delete-grant]

Create a new permission grant for an IAM user on a specific namespace.

options:
  -h, --help          show this help message and exit
  --download, -d      Whether or not to allow downloads
  --upload, -u        Whether or not to allow uploads
  --create-grant, -c  Whether or not to allow creating grants
  --delete-grant, -D  Whether or not to allow deleting grants
```

Update an existing grant
```
usage: manage-registry-permissions update [-h] [--download] [--upload] [--create-grant] [--delete-grant]

Update the permissions for an IAM user on a specific namespace and system

options:
  -h, --help          show this help message and exit
  --download, -d      Whether or not to allow downloads
  --upload, -u        Whether or not to allow uploads
  --create-grant, -c  Whether or not to allow creating grants
  --delete-grant, -D  Whether or not to allow deleting grants
```

Delete a grant, with  all of its permissions
```
usage: manage-registry-permissions delete [-h]

Delete a grant, with all corresponding permissions, for an IAM user on a specific namespace and system

options:
  -h, --help  show this help message and exit
```


#### install-registry-credentials-helper
This installs a credential helper that Terraform can call to generate credentials dynamically. See
Hashicorp's documentation for credential helpers [HERE](https://developer.hashicorp.com/terraform/internals/credentials-helpers)

When using the credentials helper, the environment that Terraform is running in must have access to AWS credentials through either:
1. A default profile
2. AWS_PROFILE environment variable, along with a corresponding profile configured
3. AWS IAM credentials stored as environment variables

```
usage: install-registry-credentials-helper [-h] [--service SERVICE] [--expiration-window EXPIRATION_WINDOW] [--plugin-directory PLUGIN_DIRECTORY] [--rc-file RC_FILE] --registry-host REGISTRY_HOST

Install the Terraform credential helper

options:
  -h, --help            show this help message and exit
  --service SERVICE     The AWS service to auth for. Use `execuite-api (default) if your registry is behind API Gateway, or `lambda` if using a direct Lambda Function URL.
  --expiration-window EXPIRATION_WINDOW
                        The number of seconds the token is good for.
  --plugin-directory PLUGIN_DIRECTORY
                        The directory to install the plugin to. Defaults to $HOME/.terraform.d/plugins
  --rc-file RC_FILE     The path to the Terraform RC file to write to. Optional.
  --registry-host REGISTRY_HOST
                        The host to get tokens from. Do not unclude URL or protocol
```

## Storage backend
The registry is BYOB (Bring your own Bucket). When uploading a new module you specify the S3 bucket, and Key. The registry doesn't care where or what these are so long
as these conditions are met:
1. The Lambda function must have the following S3 permissions for the bucket on any paths where modules are stored:
  * `s3:GetObject`
  * `s3:ListObjects`
  * `s3:GetObjectAttributes`
2. Lambda needs the following permissions for KMS if the bucket uses a CMK
  * `kms:Decrypt`
3. The module's object must include a SHA256 Checksum. This can be created by setting a flag when the object is created.


#### Tenants, Namespaces and Administration
Namespaces exist as soon as there is module that references it. In other words, you don't
need an operation dedicated to creating namespaces.

#### Example of creating a new module
TODO: Explain and implement this.......


## Authentication
While the registry technically supports simple Bearer auth using non-expiring tokens, it is highly discouraged. One of the main
benifits of this application is the IAM authentication.

How it works:<br>

* An admin adds a permission to the DB table using the `manage-registry-permissions` CLI tool. This entry says that the specified AWS Role has the given
permissions on the specified Namespace
* When a client wants to use the registry they will call the token endpoint with a signed request using their role's credentials.
    * The `get-registry-token` cli tool can return a token to be used in the `TF_TOKEN_***` env var, `.terraformrc` configuration, etc and
    can be manually run by the user.
    * You can also install the credentials helper tool to allow Terraform to handle the authentication dynamically (Preferred)
* The request to get a token requires sending the `expiration_window`, which is the number of seconds from now before the token expires. This is capped by the application
by setting the `MAX_IAM_TOKEN_EXPIRATION_WINDOW` env var.
* The token that is returned from the token API endpoint is used as a Bearer token in all API requests.


## Registry Configuration

* `TABLE_NAME`: The name of the Dynamodb table used.
* `RESOLVER_TYPE`: Can be one of `FUNCTION_URL`, `API_GATEWAY_REST`, `API_GATEWAY_HTTP`, or `ALB`. Defaults to `FUNCTION_URL`. This is used to resolve the `Resolver` class
to use by the AWS Lambda Powertools layer. Although the included Terraform uses an API Gateway V2 HTTP API, the `API_GATEWAY_REST` resolver actually works best.
Function URL then this would be the hostname for that URL. Note that if using the Function URL you would use the Function that actually hosts the registry, and not the auth endpoint.
* `IAM_AUTH_KMS_KEY`: Arn of a KMS key to use for encrypting and decrypting tokens.
