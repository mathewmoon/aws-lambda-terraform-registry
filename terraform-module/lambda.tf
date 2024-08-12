module "registry_lambda" {
  source           = "./submodules/lambda_function"
  name             = var.registry_function_name
  handler          = "registry.aws_lambda.registry_lambda.handler"
  runtime          = "python3.12"
  timeout          = 10
  memory_size      = 1024
  role_arn         = aws_iam_role.registry_lambda_role.arn
  registry_version = "0.2.2"
  environment      = local.lambda_env_vars
  auth_type        = "AWS_IAM"
}
