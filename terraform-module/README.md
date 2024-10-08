# Deploy all the goodies

API GW:
  IAM Authorizor ->Auth Token Endpoing Lambda
  Registry Lambda
Dynamodb
KMS Key

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.62.0 |
| <a name="requirement_external"></a> [external](#requirement\_external) | >= 2.3.3 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.62.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_registry_lambda"></a> [registry\_lambda](#module\_registry\_lambda) | ./submodules/lambda_function | n/a |
| <a name="module_s3_bucket"></a> [s3\_bucket](#module\_s3\_bucket) | ./submodules/s3 | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_api_gateway_account.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_account) | resource |
| [aws_api_gateway_base_path_mapping.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_base_path_mapping) | resource |
| [aws_api_gateway_deployment.registry](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment) | resource |
| [aws_api_gateway_domain_name.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name) | resource |
| [aws_api_gateway_integration.tf_api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_integration) | resource |
| [aws_api_gateway_method.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method) | resource |
| [aws_api_gateway_resource.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_resource) | resource |
| [aws_api_gateway_rest_api.registry](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api) | resource |
| [aws_api_gateway_rest_api_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api_policy) | resource |
| [aws_api_gateway_stage.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage) | resource |
| [aws_dynamodb_table.registry](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |
| [aws_iam_role.api_gw](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.registry_lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_kms_alias.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_kms_key_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key_policy) | resource |
| [aws_lambda_permission.registry](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.api_gw](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.api_gw_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.lambda_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.terraform_registry](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_organizations_organization.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/organizations_organization) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_allow_organization_access"></a> [allow\_organization\_access](#input\_allow\_organization\_access) | Whether to allow access to the registry from the entire organization | `bool` | `false` | no |
| <a name="input_allowed_registry_identities"></a> [allowed\_registry\_identities](#input\_allowed\_registry\_identities) | The identities allowed to access the registry via resource policies | `list(string)` | `[]` | no |
| <a name="input_bucket_arn"></a> [bucket\_arn](#input\_bucket\_arn) | The ARN of an existing S3 bucket to use for the registry | `string` | `null` | no |
| <a name="input_bucket_name"></a> [bucket\_name](#input\_bucket\_name) | The name of the S3 bucket | `string` | n/a | yes |
| <a name="input_bucket_versioning"></a> [bucket\_versioning](#input\_bucket\_versioning) | Whether to enable versioning for the S3 bucket | `bool` | `true` | no |
| <a name="input_certificate_arn"></a> [certificate\_arn](#input\_certificate\_arn) | The ARN of the ACM certificate to use for the API Gateway | `string` | `null` | no |
| <a name="input_create_bucket"></a> [create\_bucket](#input\_create\_bucket) | Whether to create an S3 bucket for the registry | `bool` | `true` | no |
| <a name="input_domain_name"></a> [domain\_name](#input\_domain\_name) | The domain name for the API Gateway | `string` | `null` | no |
| <a name="input_dynamodb_billing_mode"></a> [dynamodb\_billing\_mode](#input\_dynamodb\_billing\_mode) | The billing mode of the DynamoDB table | `string` | `"PAY_PER_REQUEST"` | no |
| <a name="input_dynamodb_cmk"></a> [dynamodb\_cmk](#input\_dynamodb\_cmk) | The ARN of the KMS key used to encrypt the DynamoDB table. If omitted, the table will use AWS managed keys. | `string` | `null` | no |
| <a name="input_dynamodb_pitr"></a> [dynamodb\_pitr](#input\_dynamodb\_pitr) | Whether to enable point-in-time recovery for the DynamoDB table | `bool` | `true` | no |
| <a name="input_dynamodb_read_capacity"></a> [dynamodb\_read\_capacity](#input\_dynamodb\_read\_capacity) | The read capacity unitis of the DynamoDB table | `number` | `5` | no |
| <a name="input_dynamodb_table_name"></a> [dynamodb\_table\_name](#input\_dynamodb\_table\_name) | The name of the DynamoDB table | `string` | `"terraform-registry"` | no |
| <a name="input_dynamodb_ttl"></a> [dynamodb\_ttl](#input\_dynamodb\_ttl) | The TTL attribute of the DynamoDB table | `string` | `"TTL"` | no |
| <a name="input_dynamodb_write_capacity"></a> [dynamodb\_write\_capacity](#input\_dynamodb\_write\_capacity) | The write capacity unitis of the DynamoDB table | `number` | `5` | no |
| <a name="input_kms_alias"></a> [kms\_alias](#input\_kms\_alias) | The alias of the KMS key to use for the application | `string` | `"alias/terraform-registry"` | no |
| <a name="input_lambda_layers"></a> [lambda\_layers](#input\_lambda\_layers) | The ARNs of the Lambda layers to attach to the registry Lambda function | `list(string)` | <pre>[<br>  "arn:aws:lambda:us-east-1:637423294718:layer:terraform-registry-deps:2"<br>]</pre> | no |
| <a name="input_registry_api_name"></a> [registry\_api\_name](#input\_registry\_api\_name) | The name of the API Gateway | `string` | `"terraform-registry"` | no |
| <a name="input_registry_function_name"></a> [registry\_function\_name](#input\_registry\_function\_name) | The name of the registry Lambda function | `string` | `"terraform-registry"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->