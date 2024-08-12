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
  layers        = var.layers

  environment {
    variables = var.environment
  }
}
