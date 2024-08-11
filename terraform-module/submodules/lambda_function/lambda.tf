data "external" "build" {
  program = ["bash", "${path.module}/scripts/build-lambda.sh", var.registry_package, var.registry_version, "${path.module}/lambda_build"]
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  handler       = var.handler
  runtime       = var.runtime
  filename      = data.external.build.result["zip_file"]
  role          = var.role_arn
  timeout       = var.timeout
  memory_size   = var.memory_size
  layers        = ["arn:aws:lambda:us-east-1:637423294718:layer:fastapi:1"]

  environment {
    variables = var.environment
  }
}

resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.this.function_name
  authorization_type = var.auth_type
}
