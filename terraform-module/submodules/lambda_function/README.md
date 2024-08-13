<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_external"></a> [external](#provider\_external) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_lambda_function.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [external_external.build](https://registry.terraform.io/providers/hashicorp/external/latest/docs/data-sources/external) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | The environment variables of the Lambda function | `map(string)` | `{}` | no |
| <a name="input_handler"></a> [handler](#input\_handler) | The entry point of the Lambda function | `string` | `"lambda_function.lambda_handler"` | no |
| <a name="input_layers"></a> [layers](#input\_layers) | The ARNs of the Lambda layers to attach to the function | `list(string)` | `[]` | no |
| <a name="input_memory_size"></a> [memory\_size](#input\_memory\_size) | The memory size of the Lambda function | `number` | `1024` | no |
| <a name="input_name"></a> [name](#input\_name) | The name of the Lambda function | `string` | n/a | yes |
| <a name="input_registry_package"></a> [registry\_package](#input\_registry\_package) | The name of the pip package to install in the Lambda function. | `string` | `"lambda-terraform-module-registry"` | no |
| <a name="input_registry_version"></a> [registry\_version](#input\_registry\_version) | The version of the registry python package to use. | `string` | n/a | yes |
| <a name="input_role_arn"></a> [role\_arn](#input\_role\_arn) | The ARN of the IAM role that the Lambda function assumes | `string` | n/a | yes |
| <a name="input_runtime"></a> [runtime](#input\_runtime) | The runtime of the Lambda function | `string` | `"python3.12"` | no |
| <a name="input_timeout"></a> [timeout](#input\_timeout) | The timeout of the Lambda function | `number` | `8` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arn"></a> [arn](#output\_arn) | The ARN of the Lambda function |
| <a name="output_function_name"></a> [function\_name](#output\_function\_name) | The name of the Lambda function |
<!-- END_TF_DOCS -->