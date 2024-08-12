locals {
  registry_bucket_arn = var.create_bucket ? module.s3_bucket[0].arn : var.bucket_arn
  lambda_env_vars = {
    TABLE                       = aws_dynamodb_table.registry.name
    REGISTRY_BUCKET             = replace(local.registry_bucket_arn, "/.*:/", "")
    RESOLVER_TYPE               = "API_GATEWAY_REST"
    MAX_TOKEN_EXPIRATION_WINDOW = 300
    IAM_AUTH_KMS_KEY            = aws_kms_alias.this.name
  }
}
