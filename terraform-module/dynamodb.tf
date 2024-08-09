resource "aws_dynamodb_table" "registry" {
  name           = var.dynamodb_table_name
  hash_key       = "pk"
  range_key      = "sk"
  billing_mode   = var.dynamodb_billing_mode
  write_capacity = var.dynamodb_billing_mode != "PROVISIONED" ? null : var.dynamodb_write_capacity
  read_capacity  = var.dynamodb_billing_mode != "PROVISIONED" ? null : var.dynamodb_read_capacity

  ttl {
    attribute_name = var.dynamodb_ttl
    enabled        = true
  }


  point_in_time_recovery {
    enabled = var.dynamodb_pitr
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.dynamodb_cmk
  }

  # LSI attributes
  dynamic "attribute" {
    for_each = range(5)

    content {
      name = "lsi${attribute.value}_sk"
      type = "S"
    }
  }

  # GSI pk attributes
  dynamic "attribute" {
    for_each = range(20)

    content {
      name = "gsi${attribute.value}_pk"
      type = "S"
    }
  }

  # GSI sk attributes
  dynamic "attribute" {
    for_each = range(20)

    content {
      name = "gsi${attribute.value}_sk"
      type = "S"
    }
  }

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # GSI's
  dynamic "global_secondary_index" {
    for_each = range(20)

    content {
      name            = "gsi${global_secondary_index.value}"
      hash_key        = "gsi${global_secondary_index.value}_pk"
      range_key       = "gsi${global_secondary_index.value}_sk"
      projection_type = "ALL"
    }
  }

  # LSI's
  dynamic "local_secondary_index" {
    for_each = range(5)

    content {
      name            = "lsi${local_secondary_index.value}"
      range_key       = "lsi${local_secondary_index.value}_sk"
      projection_type = "ALL"
    }
  }
}
