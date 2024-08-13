data "aws_iam_policy_document" "kms" {
  statement {
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
    ]

    resources = [
      aws_kms_key.this.arn,
    ]

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.registry_lambda_role.arn,
      ]
    }
  }

  statement {
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
    ]

    resources = [
      aws_kms_key.this.arn,
    ]

    principals {
      type = "Service"
      identifiers = [
        "dynamodb.amazonaws.com",
        "s3.amazonaws.com",
      ]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "KMS key for Terraform Registry"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_alias" "this" {
  name          = var.kms_alias
  target_key_id = aws_kms_key.this.key_id
}

resource "aws_kms_key_policy" "this" {
  key_id = aws_kms_key.this.id
  policy = data.aws_iam_policy_document.kms.json
}
