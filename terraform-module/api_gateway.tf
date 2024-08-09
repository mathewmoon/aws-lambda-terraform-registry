resource "aws_apigatewayv2_api" "registry" {
  name          = var.registry_api_name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "registry" {
  api_id             = aws_apigatewayv2_api.registry.id
  integration_type   = "AWS_PROXY"
  integration_method = "ANY"
  integration_uri    = module.registry_lambda.arn
}

resource "aws_apigatewayv2_integration" "authorizor" {
  api_id             = aws_apigatewayv2_api.registry.id
  integration_type   = "AWS_PROXY"
  integration_method = "ANY"
  integration_uri    = module.iam_endpoint_lambda.arn
}

resource "aws_apigatewayv2_route" "registry" {
  api_id             = aws_apigatewayv2_api.registry.id
  route_key          = "$default"
  target             = "integrations/${aws_apigatewayv2_integration.registry.id}"
  authorization_type = "NONE"

}

resource "aws_apigatewayv2_route" "authorizor" {
  api_id             = aws_apigatewayv2_api.registry.id
  route_key          = "GET /token"
  target             = "integrations/${aws_apigatewayv2_integration.authorizor.id}"
  authorization_type = "AWS_IAM"

}

resource "aws_apigatewayv2_stage" "registry" {
  api_id      = aws_apigatewayv2_api.registry.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.registry.arn
    format = jsonencode({
      requestId         = "$context.requestId",
      ip                = "$context.identity.sourceIp",
      request           = "$context.httpMethod $context.routeKey",
      status            = "$context.status",
      response          = "$context.responseLength"
      error             = "$context.error.message"
      integration_error = "$context.integration.error"
    })
  }

  default_route_settings {
    detailed_metrics_enabled = true
    logging_level            = "INFO"
    throttling_rate_limit    = 10000
    throttling_burst_limit   = 10000
  }

  route_settings {
    route_key                = "GET /token"
    detailed_metrics_enabled = true
    logging_level            = "INFO"
    throttling_rate_limit    = 10000
    throttling_burst_limit   = 10000
  }

  route_settings {
    route_key                = "$default"
    detailed_metrics_enabled = true
    logging_level            = "INFO"
    throttling_rate_limit    = 10000
    throttling_burst_limit   = 10000
  }

}

resource "aws_apigatewayv2_deployment" "registry" {
  api_id      = aws_apigatewayv2_api.registry.id
  description = "Terraform Registry"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_permission" "registry" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = module.registry_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.registry.execution_arn}/*/$default"
}

resource "aws_lambda_permission" "authorizor" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = module.iam_endpoint_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.registry.execution_arn}/*/*/token"
}

resource "aws_cloudwatch_log_group" "registry" {
  name = "terraform-registry-api"
}
