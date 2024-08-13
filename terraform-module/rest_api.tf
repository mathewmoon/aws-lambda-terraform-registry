resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.api_gw.arn
}

resource "aws_api_gateway_rest_api" "registry" {
  name        = "terraform-registry"
  description = "Terraform Registry API"
}

locals {
  gw_resources = {
    token_endpoint = {
      path   = "token",
      method = "GET",
      auth   = "AWS_IAM"
    }
    registry = {
      path   = "{proxy+}",
      method = "ANY",
      auth   = "NONE"
    }
  }
}


data "aws_iam_policy_document" "api" {
  statement {
    effect    = "Allow"
    actions   = ["execute-api:*"]
    resources = ["${aws_api_gateway_rest_api.registry.execution_arn}/registry/*/token"]

    principals {
      type = "AWS"
      identifiers = flatten([
        var.allowed_registry_identities,
        data.aws_caller_identity.current.account_id,
      ])
    }
  }

  dynamic "statement" {
    for_each = var.allow_organization_access ? [1] : []
    content {
      effect    = "Allow"
      actions   = ["execute-api:*"]
      resources = ["${aws_api_gateway_rest_api.registry.execution_arn}/registry/*/token"]
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [data.aws_organizations_organization.this.id]
      }
    }
  }

  statement {
    effect        = "Allow"
    actions       = ["execute-api:*"]
    not_resources = ["${aws_api_gateway_rest_api.registry.execution_arn}/registry/*/token"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "this" {
  rest_api_id = aws_api_gateway_rest_api.registry.id
  policy      = data.aws_iam_policy_document.api.json
}


resource "aws_api_gateway_resource" "this" {
  for_each    = local.gw_resources
  rest_api_id = aws_api_gateway_rest_api.registry.id
  parent_id   = aws_api_gateway_rest_api.registry.root_resource_id
  path_part   = each.value.path
}

resource "aws_api_gateway_method" "this" {
  for_each    = aws_api_gateway_resource.this
  rest_api_id = each.value.rest_api_id
  resource_id = each.value.id

  http_method   = local.gw_resources[each.key].method
  authorization = local.gw_resources[each.key].auth
}

resource "aws_api_gateway_integration" "tf_api" {
  for_each = aws_api_gateway_resource.this

  rest_api_id             = each.value.rest_api_id
  resource_id             = each.value.id
  http_method             = aws_api_gateway_method.this[each.key].http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${module.registry_lambda.arn}/invocations"
}


resource "aws_api_gateway_deployment" "registry" {
  rest_api_id = aws_api_gateway_rest_api.registry.id

  triggers = {
    redeployment = sha1(join("", [
      jsonencode(local.gw_resources),
      jsonencode(aws_api_gateway_integration.tf_api),
      jsonencode(aws_api_gateway_method.this),
      jsonencode(aws_api_gateway_resource.this),
      data.aws_iam_policy_document.api.json,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "api" {
  deployment_id = aws_api_gateway_deployment.registry.id
  rest_api_id   = aws_api_gateway_rest_api.registry.id
  stage_name    = "api"
}

resource "aws_lambda_permission" "registry" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = module.registry_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.registry.execution_arn}/*/*"
}

resource "aws_api_gateway_domain_name" "this" {
  count = var.domain_name != null ? 1 : 0

  domain_name     = var.domain_name
  certificate_arn = var.certificate_arn
  security_policy = "TLS_1_2"

  lifecycle {
    precondition {
      condition     = var.domain_name != null && var.certificate_arn != null
      error_message = "An var.acm_certificate_arn must be provided when var.domain_name is set"
    }
  }
}

resource "aws_api_gateway_base_path_mapping" "this" {
  count = length(aws_api_gateway_domain_name.this)

  domain_name = aws_api_gateway_domain_name.this[0].domain_name
  api_id      = aws_api_gateway_rest_api.registry.id
  stage_name  = aws_api_gateway_stage.api.stage_name
  base_path   = ""
}

